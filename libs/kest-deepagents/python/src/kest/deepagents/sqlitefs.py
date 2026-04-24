"""
SqliteFileSystem — a personal filesystem backed by a single SQLite database.
=============================================================================

Treats one SQLite ``.db`` file as a self-contained filesystem.  Files are
stored as BLOBs; directories are either explicit rows (``is_dir=1``) or
implicitly inferred from path prefixes.

Usage::

    from kest.deepagents.sqlitefs import SqliteFileSystem

    fs = SqliteFileSystem(db_path="/path/to/personal.db")
    fs.pipe_file("/notes/hello.txt", b"Hello, world!")
    print(fs.cat_file("/notes/hello.txt"))   # b"Hello, world!"
    print(fs.ls("/notes"))                   # [{"name": "/notes/hello.txt", ...}]

    # Progressive disclosure — like head / tail
    print(fs.head("/notes/hello.txt", n=5))  # first 5 lines as list
    print(fs.tail("/notes/hello.txt", n=5))  # last 5 lines as list

Integration with FsspecAgent::

    from kest.deepagents.fsspec_agent import FsspecAgent
    from kest.deepagents.sqlitefs import SqliteFileSystem

    fs = SqliteFileSystem(db_path="~/personal.db")
    agent = FsspecAgent(fs=fs, root="/workspace")

Or mount interactively via the TUI with ``mount sqlite``.

Schema
------
::

    CREATE TABLE files (
        path        TEXT PRIMARY KEY,
        content     BLOB,                -- NULL for directories
        size        INTEGER NOT NULL DEFAULT 0,
        is_dir      INTEGER NOT NULL DEFAULT 0,  -- 0=file, 1=directory
        mime_type   TEXT,                -- detected on write; NULL for dirs
        created_at  REAL NOT NULL,
        modified_at REAL NOT NULL
    )

Path conventions
----------------
- All paths are POSIX-style starting with ``/``.
- The root ``/`` is virtual and never stored as a row.
- Trailing slashes are stripped; ``//`` is collapsed.

MIME detection
--------------
``mime_type`` is detected on every ``pipe_file`` call using a two-stage
strategy:

1. Extension lookup via ``mimetypes.guess_type(path)`` — fast and reliable
   for well-known formats (``.txt``, ``.json``, ``.png``…).
2. Content sniff (first 512 bytes) — for unknown extensions or extensionless
   files.  Uses ``mimetypes``-stdlib helper; falls back to
   ``application/octet-stream`` for opaque binary content.

HEAD / TAIL — progressive disclosure
-------------------------------------
``head(path, n=10)`` and ``tail(path, n=10)`` decode the file as UTF-8 text
and return the first / last *n* non-empty lines.  They raise
``UnicodeDecodeError`` for binary files — the agent should check
``mime_type`` first and only call ``head``/``tail`` on text files.
"""

from __future__ import annotations

import datetime
import io
import mimetypes
import posixpath
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union, overload

import fsspec
from fsspec.spec import AbstractFileSystem


# ---------------------------------------------------------------------------
# Registration — called at import so fsspec.filesystem("sqlite", ...) works
# ---------------------------------------------------------------------------


def _register() -> None:
    """Register SqliteFileSystem with fsspec under the ``sqlite`` protocol."""
    try:
        fsspec.register_implementation(
            "sqlite",
            "kest.deepagents.sqlitefs.SqliteFileSystem",
            clobber=False,
        )
    except Exception:
        pass  # Already registered or registration not supported


# ---------------------------------------------------------------------------
# MIME detection helper
# ---------------------------------------------------------------------------

# Sniff tokens → MIME.  Ordered by specificity (longer/more specific first).
_MAGIC: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "audio/x-wav"),        # WAV (needs further check, good enough)
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"BZh", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "application/x-xz"),
    (b"7z\xbc\xaf'\x1c", "application/x-7z-compressed"),
    (b"\x00\x00\x00 ftyp", "video/mp4"),
    (b"\x00\x00\x00\x18ftyp", "video/mp4"),
    (b"OggS", "audio/ogg"),
    (b"fLaC", "audio/flac"),
    (b"ID3", "audio/mpeg"),
    (b"<!DOCTYPE html", "text/html"),
    (b"<!doctype html", "text/html"),
    (b"<html", "text/html"),
    (b"<?xml", "application/xml"),
    (b"<svg", "image/svg+xml"),
    (b"{", "application/json"),       # heuristic prefix — only for unknown ext
    (b"[", "application/json"),       # heuristic prefix — only for unknown ext
]

_TEXT_SUFFIXES = {
    ".txt", ".md", ".rst", ".csv", ".tsv", ".log", ".ini", ".cfg", ".conf",
    ".yaml", ".yml", ".toml", ".json", ".xml", ".html", ".htm", ".css",
    ".js", ".ts", ".py", ".sh", ".bash", ".zsh", ".fish", ".rb", ".go",
    ".rs", ".c", ".cpp", ".h", ".java", ".kt", ".swift", ".r", ".sql",
    ".graphql", ".tf", ".hcl",
}


def _detect_mime(path: str, content: bytes) -> str:
    """
    Return the MIME type for *path* + *content*.

    Strategy (applied in order, first wins):
    1. ``mimetypes.guess_type(path)`` — reliable for registered extensions.
    2. Magic-byte sniff against *_MAGIC* table.
    3. Heuristic: if all bytes < 0x80, assume ``text/plain``.
    4. Final fallback: ``application/octet-stream``.
    """
    # 1. Extension lookup
    mime, _ = mimetypes.guess_type(path, strict=False)
    if mime:
        return mime

    suffix = posixpath.splitext(path)[1].lower()
    if suffix in _TEXT_SUFFIXES:
        return "text/plain"

    sniff = content[:512]

    # 2. Magic bytes
    for magic, detected_mime in _MAGIC:
        if sniff.startswith(magic):
            return detected_mime

    if not sniff:
        return "application/octet-stream"

    # 3. High-ASCII heuristic
    text_chars = bytes(
        range(0x20, 0x7F)
    ) + b"\t\n\r\x0b\x0c"
    non_text = sum(1 for b in sniff if b not in text_chars)
    if non_text / len(sniff) < 0.05:  # < 5% non-text bytes → text
        return "text/plain"

    return "application/octet-stream"


# ---------------------------------------------------------------------------
# Core filesystem
# ---------------------------------------------------------------------------


class SqliteFileSystem(AbstractFileSystem):
    """
    An ``AbstractFileSystem`` that stores files as BLOBs in a SQLite database.

    One database = one personal filesystem.  The entire state is a single
    portable ``.db`` file.

    Args:
        db_path:  Path to the SQLite database file.  Use ``\":memory:\"`` for
                  a transient, in-process filesystem (useful in tests).
    """

    protocol = "sqlite"

    # Setting cachable = False tells the fsspec ``_Cached`` metaclass to never
    # read from or write to the class-level instance cache.  Each call to
    # ``SqliteFileSystem(...)`` always creates a fresh connection — essential
    # after ``close()`` and in tests where many independent filesystems are
    # opened against the same ``":memory:"`` path.
    cachable = False

    # SQLite connections are not safe to share across threads without a lock.
    _lock: threading.RLock

    def __init__(self, db_path: str = ":memory:", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._db_path = str(db_path)
        if self._db_path not in (":memory:",) and not self._db_path.startswith(":"):
            # Expand ~ and relative paths for on-disk databases
            self._db_path = str(Path(self._db_path).expanduser().resolve())
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = sqlite3.connect(self._db_path, check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._init_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._lock:
            self._con.executescript("""
                CREATE TABLE IF NOT EXISTS files (
                    path        TEXT PRIMARY KEY,
                    content     BLOB,
                    size        INTEGER NOT NULL DEFAULT 0,
                    is_dir      INTEGER NOT NULL DEFAULT 0,
                    mime_type   TEXT,
                    created_at  REAL    NOT NULL DEFAULT 0,
                    modified_at REAL    NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_files_is_dir ON files(is_dir);
            """)
            # Migrate existing databases that lack the mime_type column.
            cols = {
                row[1]
                for row in self._con.execute("PRAGMA table_info(files)")
            }
            if "mime_type" not in cols:
                self._con.execute(
                    "ALTER TABLE files ADD COLUMN mime_type TEXT"
                )
            self._con.commit()

    # ------------------------------------------------------------------
    # Path normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _norm(path: str) -> str:
        """Normalise to an absolute POSIX path with no trailing slash."""
        if not path:
            return "/"
        # Strip any protocol prefix (sqlite:// or sqlite:)
        for prefix in ("sqlite://", "sqlite:"):
            if path.startswith(prefix):
                path = path[len(prefix):]
                break
        return posixpath.normpath("/" + path.lstrip("/"))

    # ------------------------------------------------------------------
    # AbstractFileSystem interface
    # ------------------------------------------------------------------

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> List:
        """
        List the direct children of *path*.

        Returns a list of info dicts when *detail=True*, or plain path strings
        when *detail=False*.
        """
        path = self._norm(path)

        # Validate the path exists (root is always valid)
        if path != "/" and not self._row_exists(path):
            raise FileNotFoundError(f"No such file or directory: {path!r}")

        prefix = "/" if path == "/" else path + "/"

        with self._lock:
            rows = self._con.execute(
                "SELECT path, size, is_dir, mime_type, created_at, modified_at "
                "FROM files WHERE path LIKE ? AND path != ?",
                (prefix + "%", path),
            ).fetchall()

        results = []
        for row in rows:
            child = row["path"]
            # Keep only *direct* children (no further slashes after the prefix)
            tail = child[len(prefix):]
            if "/" in tail:
                continue
            info = self._row_to_info(dict(row))
            results.append(info if detail else info["name"])

        return results

    def info(self, path: str, **kwargs: Any) -> Dict[str, Any]:
        """Return a metadata dict for *path*."""
        path = self._norm(path)
        if path == "/":
            return {"name": "/", "size": 0, "type": "directory"}

        with self._lock:
            row = self._con.execute(
                "SELECT path, size, is_dir, mime_type, created_at, modified_at "
                "FROM files WHERE path = ?",
                (path,),
            ).fetchone()

        if row is None:
            raise FileNotFoundError(f"No such file or directory: {path!r}")
        return self._row_to_info(dict(row))

    def exists(self, path: str, **kwargs: Any) -> bool:
        path = self._norm(path)
        if path == "/":
            return True
        return self._row_exists(path)

    def created(self, path: str) -> datetime.datetime:
        """
        Return the creation timestamp of *path* as a ``datetime.datetime``.

        The value is in local time (naive, no tzinfo).  Use
        ``datetime.timezone.utc`` if you need UTC-aware datetimes.

        Raises:
            FileNotFoundError: If *path* does not exist.
        """
        info = self.info(path)  # raises FileNotFoundError
        ts: float = info.get("created") or 0.0
        return datetime.datetime.fromtimestamp(ts)

    def modified(self, path: str) -> datetime.datetime:
        """
        Return the last-modified timestamp of *path* as a ``datetime.datetime``.

        The value is in local time (naive, no tzinfo).

        Raises:
            FileNotFoundError: If *path* does not exist.
        """
        info = self.info(path)  # raises FileNotFoundError
        ts: float = info.get("modified") or 0.0
        return datetime.datetime.fromtimestamp(ts)

    def mkdir(self, path: str, create_parents: bool = True, **kwargs: Any) -> None:
        """Create a directory (and parents if *create_parents* is True)."""
        path = self._norm(path)
        if path == "/":
            return
        now = time.time()
        with self._lock:
            if create_parents:
                parts = path.lstrip("/").split("/")
                for i in range(1, len(parts) + 1):
                    p = "/" + "/".join(parts[:i])
                    self._con.execute(
                        "INSERT OR IGNORE INTO files"
                        "(path, content, size, is_dir, mime_type, created_at, modified_at)"
                        " VALUES (?,NULL,0,1,NULL,?,?)",
                        (p, now, now),
                    )
            else:
                self._con.execute(
                    "INSERT OR IGNORE INTO files"
                    "(path, content, size, is_dir, mime_type, created_at, modified_at)"
                    " VALUES (?,NULL,0,1,NULL,?,?)",
                    (path, now, now),
                )
            self._con.commit()

    def makedirs(self, path: str, exist_ok: bool = False, **kwargs: Any) -> None:
        self.mkdir(path, create_parents=True)

    def rm_file(self, path: str) -> None:
        path = self._norm(path)
        with self._lock:
            self._con.execute("DELETE FROM files WHERE path = ?", (path,))
            self._con.commit()

    def _rm(self, path: str) -> None:
        """Delete a single file — the per-file primitive used by the base ``rm()`` loop."""
        self.rm_file(path)

    def rm(self, path: str, recursive: bool = False, **kwargs: Any) -> None:
        """Remove a file or directory."""
        path = self._norm(path)
        with self._lock:
            if recursive:
                self._con.execute(
                    "DELETE FROM files WHERE path = ? OR path LIKE ?",
                    (path, path + "/%"),
                )
            else:
                self._con.execute("DELETE FROM files WHERE path = ?", (path,))
            self._con.commit()

    @overload
    def cat_file(self, path: str, *, encoding: None = ..., start: Optional[int] = ..., end: Optional[int] = ..., **kwargs: Any) -> bytes: ...
    @overload
    def cat_file(self, path: str, *, encoding: str, start: Optional[int] = ..., end: Optional[int] = ..., **kwargs: Any) -> str: ...

    def cat_file(  # type: ignore[override]  -- adds optional encoding/start/end kwargs
        self,
        path: str,
        *,
        encoding: Optional[str] = None,
        start: Optional[int] = None,
        end: Optional[int] = None,
        **kwargs: Any,
    ) -> Union[bytes, str]:
        """
        Read the full (or partial) contents of *path*.

        Args:
            path:     Target file.
            encoding: If ``None`` (default), returns raw ``bytes``.  If an
                      encoding name is given, decodes and returns ``str``.
            start:    First byte offset (inclusive).  Negative values count
                      from the end, like Python slices.
            end:      Last byte offset (exclusive).  Negative values count
                      from the end.

        Raises:
            FileNotFoundError:  If *path* does not exist.
            IsADirectoryError:  If *path* is a directory.
            UnicodeDecodeError: If *encoding* is set and decoding fails.
        """
        path = self._norm(path)
        with self._lock:
            row = self._con.execute(
                "SELECT content, is_dir FROM files WHERE path = ?", (path,)
            ).fetchone()
        if row is None:
            raise FileNotFoundError(f"No such file: {path!r}")
        if row["is_dir"]:
            raise IsADirectoryError(f"Is a directory: {path!r}")
        raw: bytes = bytes(row["content"] or b"")
        # Apply byte-range slice (matches fsspec's cat_file contract)
        if start is not None or end is not None:
            size = len(raw)
            s = start if start is not None else 0
            e = end if end is not None else size
            # Resolve negatives the same way the base class does
            if s < 0:
                s = max(0, size + s)
            if e < 0:
                e = size + e
            raw = raw[s:e]
        if encoding is not None:
            return raw.decode(encoding)
        return raw

    def pipe_file(self, path: str, value: bytes, **kwargs: Any) -> None:
        """Write *value* bytes to *path*, creating or replacing the file."""
        path = self._norm(path)
        now = time.time()
        mime = _detect_mime(path, value)
        self._ensure_parents(path)
        with self._lock:
            self._con.execute(
                """
                INSERT INTO files(path, content, size, is_dir, mime_type, created_at, modified_at)
                VALUES (?, ?, ?, 0, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    content     = excluded.content,
                    size        = excluded.size,
                    mime_type   = excluded.mime_type,
                    modified_at = excluded.modified_at,
                    is_dir      = 0
                """,
                (path, value, len(value), mime, now, now),
            )
            self._con.commit()

    def cp_file(self, path1: str, path2: str, **kwargs: Any) -> None:
        """Copy a single file (the per-file primitive required by the fsspec spec)."""
        data = self.cat_file(path1)  # raises FileNotFoundError if missing
        self.pipe_file(path2, data)

    def copy(self, path1: str, path2: str, **kwargs: Any) -> None:
        """Copy a file."""
        self.cp_file(path1, path2)

    def mv(self, path1: str, path2: str, recursive: bool = False, **kwargs: Any) -> None:
        """Move/rename a file or directory."""
        path1 = self._norm(path1)
        path2 = self._norm(path2)
        if path1 == path2:
            return
        with self._lock:
            if recursive:
                # Rename all rows under path1 tree to path2 tree
                rows = self._con.execute(
                    "SELECT path FROM files WHERE path = ? OR path LIKE ?",
                    (path1, path1 + "/%"),
                ).fetchall()
                for (old_path,) in rows:
                    new_path = path2 + old_path[len(path1):]
                    self._con.execute(
                        "UPDATE files SET path = ? WHERE path = ?",
                        (new_path, old_path),
                    )
            else:
                self._con.execute(
                    "UPDATE files SET path = ? WHERE path = ?", (path2, path1)
                )
            self._con.commit()

    def touch(self, path: str, truncate: bool = True, **kwargs: Any) -> None:
        """Create *path* if it doesn't exist; update modified_at if it does."""
        path = self._norm(path)
        now = time.time()
        self._ensure_parents(path)
        with self._lock:
            existing = self._con.execute(
                "SELECT 1 FROM files WHERE path = ?", (path,)
            ).fetchone()
            if existing is None or truncate:
                self.pipe_file(path, b"")
            else:
                self._con.execute(
                    "UPDATE files SET modified_at = ? WHERE path = ?", (now, path)
                )
                self._con.commit()

    def put_file(self, lpath: str, rpath: str, **kwargs: Any) -> None:
        """Upload a local file into the SQLite filesystem."""
        with open(lpath, "rb") as f:
            self.pipe_file(rpath, f.read())

    def get_file(self, rpath: str, lpath: str, **kwargs: Any) -> None:
        """Download a file from the SQLite filesystem to local disk."""
        data = self.cat_file(rpath)
        Path(lpath).parent.mkdir(parents=True, exist_ok=True)
        with open(lpath, "wb") as f:
            f.write(data)

    def _open(  # type: ignore[override]  -- returns io.IOBase (BytesIO/StringIO); base annotates AbstractBufferedFile but these satisfy the protocol
        self,
        path: str,
        mode: str = "rb",
        block_size: Optional[int] = None,
        autocommit: bool = True,
        cache_options: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> io.IOBase:
        """
        Return a file-like object for *path*.

        Extra fsspec params ``block_size``, ``autocommit``, and
        ``cache_options`` are accepted but ignored (SQLite is local/atomic).
        """
        path = self._norm(path)
        if "r" in mode:
            data = self.cat_file(path)
            if "b" not in mode:
                return io.StringIO(data.decode("utf-8", errors="replace"))
            return io.BytesIO(data)
        if "w" in mode or "a" in mode or "x" in mode:
            return _SqliteWriteBuffer(self, path, mode=mode)
        raise ValueError(f"Unsupported mode: {mode!r}")

    # ------------------------------------------------------------------
    # Progressive disclosure — head / tail
    # ------------------------------------------------------------------

    def head(  # type: ignore[override]  -- intentionally different signature from AbstractFileSystem.head
        self, path: str, n: int = 10, encoding: str = "utf-8"
    ) -> List[str]:
        """
        Return the first *n* lines of *path* as a list of strings.

        .. note::
            This deliberately overrides ``AbstractFileSystem.head`` which returns
            raw bytes.  We return decoded lines instead — the parameter name
            ``n`` (number of lines) differs from the base ``size`` (byte count).

        Args:
            path:     File to read.
            n:        Number of lines to return (default 10, like ``head -n 10``).
            encoding: Character encoding used to decode the bytes (default
                      ``"utf-8"``).  Pass ``"latin-1"``, ``"utf-16"``, etc.
                      for files written in other encodings.

        Raises:
            FileNotFoundError:  If *path* does not exist.
            IsADirectoryError:  If *path* is a directory.
            UnicodeDecodeError: If the bytes cannot be decoded with *encoding*.
        """
        raw = self.cat_file(path)  # raises FileNotFoundError / IsADirectoryError
        lines = raw.decode(encoding).splitlines()
        return lines[:n]

    def tail(  # type: ignore[override]  -- intentionally different signature from AbstractFileSystem.tail
        self, path: str, n: int = 10, encoding: str = "utf-8"
    ) -> List[str]:
        """
        Return the last *n* lines of *path* as a list of strings.

        .. note::
            This deliberately overrides ``AbstractFileSystem.tail`` which returns
            raw bytes.  We return decoded lines instead — the parameter name
            ``n`` (number of lines) differs from the base ``size`` (byte count).

        Args:
            path:     File to read.
            n:        Number of lines to return (default 10, like ``tail -n 10``).
            encoding: Character encoding used to decode the bytes (default
                      ``"utf-8"``).  Pass ``"latin-1"``, ``"utf-16"``, etc.
                      for files written in other encodings.

        Raises:
            FileNotFoundError:  If *path* does not exist.
            IsADirectoryError:  If *path* is a directory.
            UnicodeDecodeError: If the bytes cannot be decoded with *encoding*.
        """
        raw = self.cat_file(path)  # raises FileNotFoundError / IsADirectoryError
        lines = raw.decode(encoding).splitlines()
        return lines[-n:] if n > 0 else []

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def db_path(self) -> str:
        """Path to the backing SQLite database file."""
        return self._db_path

    def stat(self, path: str) -> Dict[str, Any]:
        """Alias for ``info()`` that mirrors ``os.stat``-style calls."""
        return self.info(path)

    def walk(  # type: ignore[override]  -- returns Iterator; base annotates Generator but Iterator is the correct supertype
        self,
        path: str,
        maxdepth: Optional[int] = None,
        topdown: bool = True,
        on_error: str = "omit",
        **kwargs: Any,
    ) -> Iterator[tuple[str, List[str], List[str]]]:
        """
        Yield ``(dirpath, dirnames, filenames)`` tuples, like ``os.walk``.

        Args:
            path:      Root of the walk.
            maxdepth:  Maximum depth (``None`` = unlimited).
            topdown:   If ``True`` (default), yield a directory before its
                       children.  If ``False``, yield children first (bottom-up).
            on_error:  ``"omit"`` (default) silently skips unreadable paths;
                       ``"raise"`` propagates exceptions.
        """
        path = self._norm(path)
        yield from self._walk(path, maxdepth, 0, topdown=topdown, on_error=on_error)

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._con.close()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _row_exists(self, path: str) -> bool:
        with self._lock:
            row = self._con.execute(
                "SELECT 1 FROM files WHERE path = ?", (path,)
            ).fetchone()
        return row is not None

    @staticmethod
    def _row_to_info(row: Dict[str, Any]) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "name": row["path"],
            "size": row["size"] if not row["is_dir"] else 0,
            "type": "directory" if row["is_dir"] else "file",
            "created": row["created_at"],
            "modified": row["modified_at"],
        }
        if not row["is_dir"]:
            info["mime_type"] = row.get("mime_type")
        return info

    def _ensure_parents(self, path: str) -> None:
        parent = posixpath.dirname(path)
        if parent and parent != "/" and parent != path:
            self.mkdir(parent, create_parents=True)

    def _walk(
        self,
        path: str,
        maxdepth: Optional[int],
        depth: int,
        topdown: bool = True,
        on_error: str = "omit",
    ) -> Iterator[tuple[str, List[str], List[str]]]:
        try:
            entries = self.ls(path, detail=True)
        except Exception:
            if on_error == "raise":
                raise
            return
        dirs = [e["name"] for e in entries if e["type"] == "directory"]
        files = [e["name"] for e in entries if e["type"] == "file"]
        item = (path, [posixpath.basename(d) for d in dirs], [posixpath.basename(f) for f in files])
        if topdown:
            yield item
        if maxdepth is None or depth < maxdepth - 1:
            for d in dirs:
                yield from self._walk(d, maxdepth, depth + 1, topdown=topdown, on_error=on_error)
        if not topdown:
            yield item


# ---------------------------------------------------------------------------
# Write-mode file-like buffer
# ---------------------------------------------------------------------------


class _SqliteWriteBuffer(io.RawIOBase):
    """
    A writable file-like object that commits its contents to SQLite on close.

    In append mode (``"a"``), existing file content is loaded into the buffer
    first so writes are appended correctly.
    """

    def __init__(self, fs: SqliteFileSystem, path: str, mode: str = "wb") -> None:
        super().__init__()
        self._fs = fs
        self._path = path
        self._buf = io.BytesIO()
        if "a" in mode:
            try:
                existing = fs.cat_file(path)
                self._buf.write(existing)
            except (FileNotFoundError, IsADirectoryError):
                pass

    def readable(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def write(self, data: bytes) -> int:  # type: ignore[override]
        return self._buf.write(data)

    def close(self) -> None:
        if not self.closed:
            self._buf.seek(0)
            self._fs.pipe_file(self._path, self._buf.read())
        super().close()

    def __enter__(self) -> "_SqliteWriteBuffer":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Register on import
# ---------------------------------------------------------------------------

_register()
