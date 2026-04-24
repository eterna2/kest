"""
FsspecAgent — A zero-trust agent for any fsspec-compatible filesystem.

Exposes common filesystem operations as kest-verified LangChain tools using
standard Unix command names. The agent works against any filesystem that
fsspec supports, defaulting to the local filesystem:

    # Local filesystem (default)
    agent = FsspecAgent(root="/tmp/sandbox")

    # In-memory (great for testing)
    agent = FsspecAgent(fs=fsspec.filesystem("memory"), root="test-data/")

    # AWS S3 / RustFS / MinIO
    agent = FsspecAgent(
        fs=fsspec.filesystem("s3", key="...", secret="..."),
        root="my-bucket/workspace",
    )

    # Interactive mount from TUI or agent conversation:
    mount_result_json = agent.get_mount_tool().invoke({"scheme": "s3"})
    # → {"type": "ParamRequest", "missing": [{"name": "key", ...}, ...]}

Security layers
---------------
1. **Root sandbox** (``_resolve``) — every path is resolved relative to
   ``root`` and checked not to escape it, regardless of the underlying
   filesystem. Path traversal (``../../``) is rejected before kest fires.

2. **Policy engine** (``@kest_verified``) — the resolved path and protocol
   are forwarded via ``context_map`` so policies can inspect them.

Trust tiers:

    ls / cat / grep  →  trust 85–95  (read-only)
    tee              →  trust 70      (write)
    rm               →  trust 50      (destructive)
    exec (opt-in)    →  trust 60      (local shell only)
    mount            →  trust 70      (switches active filesystem)
"""

from __future__ import annotations

import importlib
import json
import posixpath
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from fsspec import AbstractFileSystem
from fsspec.implementations.local import LocalFileSystem

from langchain_core.tools import BaseTool, tool

from kest.core import kest_verified


# ---------------------------------------------------------------------------
# Filesystem registry — schema for interactive param collection
# ---------------------------------------------------------------------------


@dataclass
class ParamSpec:
    """
    Describes one credential/configuration field for a filesystem.

    Used by ``FILESYSTEM_REGISTRY`` and serialised in ``ParamRequest`` so that
    any UI (TUI modal, CLI prompt, chatbot) can render appropriate input fields
    without knowing the internals of each driver.
    """

    name: str
    """Keyword argument name passed to ``fsspec.filesystem()``."""
    label: str
    """Human-readable label shown in the input form."""
    default: str = ""
    """Pre-filled value; empty string means no default."""
    password: bool = False
    """If True the UI should mask the input."""
    required: bool = True
    """If False the field may be skipped."""


@dataclass
class FilesystemSpec:
    """Registry entry describing a supported filesystem scheme."""

    label: str
    """Human-readable name shown in scheme selectors."""
    params: List[ParamSpec] = field(default_factory=list)
    """
    Ordered list of params to collect before building the filesystem.
    The ``root`` (bucket prefix / working dir) is always appended last
    by ``build_fs`` and does not need to be listed here.
    """
    import_check: str = ""
    """
    Optional Python package that must be importable for this driver
    (e.g. ``"s3fs"`` for S3, ``"gcsfs"`` for GCS). Empty means no extra
    dependency needed.
    """


# ---------------------------------------------------------------------------
# Mount tool response types — serialised as JSON for LangChain compatibility
# ---------------------------------------------------------------------------


@dataclass
class ParamRequest:
    """
    The mount tool returns this when required params are still missing.

    The UI should render an input field for each entry in ``missing``
    (masking ``password=True`` fields), then call the mount tool again
    with all params populated in ``params``.
    """

    scheme: str
    missing: List[Dict[str, Any]]   # serialised ParamSpec dicts
    provided: Dict[str, str]         # already-supplied values (no secrets)
    type: str = "ParamRequest"


@dataclass
class ConfirmRequest:
    """
    All required params are present. The mount tool returns this to ask
    the user to confirm before the filesystem is actually switched.

    The UI should show ``summary`` and prompt ``[y/N]``. To confirm,
    call the mount tool again with ``confirmed=true`` in ``params``.
    """

    scheme: str
    summary: str
    safe_params: Dict[str, str]  # sanitised: password fields redacted
    type: str = "ConfirmRequest"


@dataclass
class MountResult:
    """Returned after a successful mount. The UI updates its banner/status."""

    protocol: str
    root: str
    message: str
    type: str = "MountResult"
    shell_disabled: bool = False
    """True when allow_shell was automatically set to False because the new
    filesystem is remote. The TUI should surface a visible warning to the user."""


# ---------------------------------------------------------------------------
# FILESYSTEM_REGISTRY — the canonical list of supported schemes
# ---------------------------------------------------------------------------

#: Maps fsspec scheme names to their UI/validation metadata.
#: Add new entries here to expose new protocols in TUI mount dialogs.
FILESYSTEM_REGISTRY: Dict[str, FilesystemSpec] = {
    "file": FilesystemSpec(
        label="Local filesystem",
        params=[],
    ),
    "memory": FilesystemSpec(
        label="In-memory (volatile, ideal for testing)",
        params=[],
    ),
    "s3": FilesystemSpec(
        label="S3 / RustFS / MinIO (S3-compatible)",
        import_check="s3fs",
        params=[
            ParamSpec("endpoint_url", "Endpoint URL",  default="http://localhost:9000"),
            ParamSpec("key",          "Access key",    default="minioadmin"),
            ParamSpec("secret",       "Secret key",    password=True),
        ],
    ),
    "ftp": FilesystemSpec(
        label="FTP",
        params=[
            ParamSpec("host",     "Host",     default="localhost"),
            ParamSpec("port",     "Port",     default="21"),
            ParamSpec("username", "Username", default="anonymous"),
            ParamSpec("password", "Password", password=True, required=False),
        ],
    ),
    "sftp": FilesystemSpec(
        label="SFTP / SSH",
        params=[
            ParamSpec("host",     "Host"),
            ParamSpec("port",     "Port",     default="22"),
            ParamSpec("username", "Username"),
            ParamSpec("password", "Password", password=True, required=False),
        ],
    ),
    "gcs": FilesystemSpec(
        label="Google Cloud Storage",
        import_check="gcsfs",
        params=[
            ParamSpec("project", "GCP Project", required=False),
            ParamSpec("token",   "Auth token / service-account path", default="anon", required=False),
        ],
    ),
    "sqlite": FilesystemSpec(
        label="SQLite personal filesystem (portable .db file)",
        params=[
            ParamSpec(
                "db_path",
                "Database file path",
                default="~/.kest/personal.db",
            ),
        ],
    ),
}


class FsspecAgent:
    """
    Zero-trust agent for any fsspec-compatible filesystem.

    Satisfies ``SubagentProtocol`` so it can be registered with ``KestAgent``.

    Every tool is delivered as a LangChain ``BaseTool`` using the idiomatic
    ``@tool + @kest_verified`` stacking pattern with standard Unix tool names.

    Args:
        fs:               Any ``fsspec.AbstractFileSystem`` instance.
                          Defaults to ``LocalFileSystem`` when omitted.
        root:             Base path within the filesystem. All relative paths
                          are joined here; all paths must resolve under this
                          root (sandbox check). For local FS this maps to the
                          working directory. For S3 this is the bucket/prefix.
        allow_shell:      Enable the ``exec`` tool. Only valid when ``fs`` is a
                          ``LocalFileSystem``. Defaults to ``False``.
        allowed_commands: **Required** when ``allow_shell=True``. Explicit
                          allowlist of executable names, e.g.
                          ``["echo", "git", "uv"]``.

    Raises:
        ValueError:  If ``allow_shell=True`` with an empty/missing
                     ``allowed_commands``.
        RuntimeError: If ``allow_shell=True`` but ``fs`` is not a
                      ``LocalFileSystem``.
    """

    name: str = "fs"
    description: str = "Zero-trust filesystem operations"

    def __init__(
        self,
        fs: Optional[AbstractFileSystem] = None,
        root: str = ".",
        allow_shell: bool = False,
        allowed_commands: Optional[List[str]] = None,
    ) -> None:
        self.allow_shell = allow_shell
        self.allowed_commands: List[str] = list(allowed_commands or [])

        # Validate exec requirements up front (before setting properties)
        _chosen_fs = fs or LocalFileSystem()
        if allow_shell:
            if not isinstance(_chosen_fs, LocalFileSystem):
                raise RuntimeError(
                    "exec is only supported with a LocalFileSystem. "
                    "Remote filesystems cannot run shell commands."
                )
            if not allowed_commands:
                raise ValueError(
                    "allowed_commands must be a non-empty list when allow_shell=True. "
                    "Provide an explicit allowlist (e.g. ['echo', 'git', 'uv']) as a "
                    "local first-gate before the kest policy engine."
                )

        self._fs: AbstractFileSystem = _chosen_fs
        self._root: str = posixpath.normpath(root)

    # ------------------------------------------------------------------
    # fs / root — validated properties
    # ------------------------------------------------------------------

    @property
    def fs(self) -> AbstractFileSystem:
        """The underlying fsspec filesystem."""
        return self._fs

    @fs.setter
    def fs(self, new_fs: AbstractFileSystem) -> None:
        """
        Switch to a different filesystem.

        Raises:
            RuntimeError: If ``allow_shell=True`` and *new_fs* is not a
                          ``LocalFileSystem``.
        """
        if self.allow_shell and not isinstance(new_fs, LocalFileSystem):
            raise RuntimeError(
                "Cannot switch to a non-local filesystem while allow_shell=True. "
                "Set allow_shell=False first, or use mount() to change both fs and "
                "root atomically."
            )
        self._fs = new_fs

    @property
    def root(self) -> str:
        """The base path within the filesystem. All paths are resolved under this root."""
        return self._root

    @root.setter
    def root(self, new_root: str) -> None:
        """Change the root (sandbox) path. The value is normalised with ``posixpath.normpath``."""
        self._root = posixpath.normpath(new_root)

    def chroot(self, new_root: str) -> "FsspecAgent":
        """
        Change the root path and return *self* for chaining.

        Example::

            agent.chroot("/tmp/new-sandbox")
            # or chain:
            agent.chroot("/tmp/new-sandbox").get_cat_tool().invoke({"path": "file.txt"})

        Args:
            new_root: New base path within the current filesystem.

        Returns:
            The same ``FsspecAgent`` instance (for method chaining).
        """
        self.root = new_root
        return self

    def mount(
        self,
        new_fs: AbstractFileSystem,
        root: str = ".",
    ) -> "FsspecAgent":
        """
        Atomically switch to a new filesystem **and** root path.

        This is the safe way to swap both at once — it validates the new
        combination before committing either change.

        Example::

            import fsspec

            # Switch to S3
            agent.mount(
                fsspec.filesystem("s3", key="...", secret="..."),
                root="my-bucket/workspace",
            )

            # Switch back to local
            from fsspec.implementations.local import LocalFileSystem
            agent.mount(LocalFileSystem(), root="/tmp/sandbox")

        Args:
            new_fs:   Any fsspec-compatible ``AbstractFileSystem``.
            root:     Base path within *new_fs*.

        Raises:
            RuntimeError: If ``allow_shell=True`` and *new_fs* is not a
                          ``LocalFileSystem``.

        Returns:
            The same ``FsspecAgent`` instance (for method chaining).
        """
        if self.allow_shell and not isinstance(new_fs, LocalFileSystem):
            raise RuntimeError(
                "Cannot mount a non-local filesystem while allow_shell=True. "
                "Set allow_shell=False first, or construct a new FsspecAgent."
            )
        self._fs = new_fs
        self._root = posixpath.normpath(root)
        return self

    # ------------------------------------------------------------------
    # Path resolution & sandbox
    # ------------------------------------------------------------------

    def _resolve(self, path: str) -> str:
        """
        Resolve *path* relative to ``root`` and assert it stays inside.

        Works for any fsspec filesystem protocol because the check is
        performed at the path-string level using POSIX semantics.

        Raises:
            PermissionError: If the normalised path escapes ``root``.
        """
        # Join relative paths with root; leave absolute paths as-is
        if posixpath.isabs(path):
            full = path
        else:
            full = posixpath.join(self.root, path)

        # Collapse .., ., double slashes
        normalised = posixpath.normpath(full)

        # Sandbox check: must be equal to root or a child of root.
        # Use a trailing-slash form of root to avoid a false match where root="/tmp"
        # would incorrectly allow "/tmpother". Special-case root="/" so we don't
        # build the double-slash "//" which would never match anything.
        root_prefix = self.root if self.root == "/" else self.root + "/"
        if normalised != self.root and not normalised.startswith(root_prefix):
            raise PermissionError(
                f"Path '{path}' resolves to '{normalised}' which is outside "
                f"root '{self.root}'. Path traversal is not permitted."
            )
        return normalised

    # ------------------------------------------------------------------
    # Protocol info (forwarded to policy context_map)
    # ------------------------------------------------------------------

    @property
    def protocol(self) -> str:
        """fsspec protocol string of the underlying filesystem."""
        proto = getattr(self.fs, "protocol", "file")
        if isinstance(proto, (list, tuple)):
            proto = proto[0]
        return str(proto)

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def get_cat_tool(self) -> BaseTool:
        """
        Exposes ``cat`` — read a file — as a kest-verified LangChain tool.

        Supports progressive disclosure via *head* and *tail* parameters,
        mirroring the Unix semantics of ``head -n N`` and ``tail -n N``.
        The agent should inspect ``mime_type`` from ``ls`` first and only
        request text content on text/* files.
        """

        agent = self

        @tool
        @kest_verified(
            policy="fs_read_policy",
            trust_override=90,
            context_map={"path": "file_path"},
        )
        def cat(
            path: str,
            head: Optional[int] = None,
            tail: Optional[int] = None,
            encoding: str = "utf-8",
        ) -> str:
            """
            Print the contents of a file on the configured filesystem.

            Args:
                path:     Path to the file (relative to the current root).
                head:     If given, return only the first *head* lines (like ``head -n N``).
                tail:     If given, return only the last *tail* lines (like ``tail -n N``).
                          *head* and *tail* are mutually exclusive; *head* takes priority.
                encoding: Character encoding for text decoding (default ``"utf-8"``).  Use
                          ``"latin-1"``, ``"utf-16"``, etc. for files in other encodings.
                          Check ``mime_type`` from ``ls`` first; pass ``encoding`` only if
                          the file is a text file.  For binary files, omit head/tail and
                          leave encoding as-is — you will receive a hex preview instead.
            """
            from kest.deepagents.sqlitefs import SqliteFileSystem as _SqliteFS

            resolved = agent._resolve(path)
            fs = agent.fs

            if head is not None:
                # Progressive: first N lines
                if isinstance(fs, _SqliteFS):
                    lines: list[str] = fs.head(resolved, n=head, encoding=encoding)
                else:
                    with fs.open(resolved, "r") as f:
                        text = f.read()
                    if isinstance(text, bytes):
                        text = text.decode(encoding)
                    lines = text.splitlines()[:head]
                return "\n".join(lines)

            if tail is not None:
                # Progressive: last N lines
                if isinstance(fs, _SqliteFS):
                    lines = fs.tail(resolved, n=tail, encoding=encoding)
                else:
                    with fs.open(resolved, "r") as f:
                        text = f.read()
                    if isinstance(text, bytes):
                        text = text.decode(encoding)
                    lines = text.splitlines()[-tail:] if tail > 0 else []
                return "\n".join(lines)

            # Full file read
            if isinstance(fs, _SqliteFS):
                return fs.cat_file(resolved, encoding=encoding)
            with fs.open(resolved, "rb") as f:
                raw = f.read()
            data: bytes = raw if isinstance(raw, bytes) else raw.encode(encoding)
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                # Binary — return hex preview
                preview = data[:256]
                return (
                    f"[binary file — {len(data)} bytes, "
                    f"hex preview: {preview.hex(' ', 1)}]"
                )

        return cat

    def get_head_tool(self) -> BaseTool:
        """
        Exposes ``head`` — first N lines of a text file — as a kest-verified tool.

        Equivalent to ``cat(path, head=N)`` but presented as a dedicated tool
        so the agent can discover it directly from the tool roster.
        """

        agent = self

        @tool
        @kest_verified(
            policy="fs_read_policy",
            trust_override=90,
            context_map={"path": "file_path"},
        )
        def head(path: str, n: int = 10, encoding: str = "utf-8") -> str:
            """
            Return the first *n* lines of a text file (default 10, like ``head -n 10``).

            Args:
                path:     File to read.
                n:        Number of lines (default 10).
                encoding: Character encoding (default ``"utf-8"``).  Check
                          ``mime_type`` from ``ls`` first — only call on ``text/*`` files.
            """
            from kest.deepagents.sqlitefs import SqliteFileSystem as _SqliteFS

            resolved = agent._resolve(path)
            fs = agent.fs
            if isinstance(fs, _SqliteFS):
                lines: list[str] = fs.head(resolved, n=n, encoding=encoding)
            else:
                with fs.open(resolved, "r") as f:
                    text = f.read()
                if isinstance(text, bytes):
                    text = text.decode(encoding)
                lines = text.splitlines()[:n]
            return "\n".join(lines)

        return head

    def get_tail_tool(self) -> BaseTool:
        """
        Exposes ``tail`` — last N lines of a text file — as a kest-verified tool.

        Equivalent to ``cat(path, tail=N)`` but presented as a dedicated tool
        so the agent can discover it directly from the tool roster.
        """

        agent = self

        @tool
        @kest_verified(
            policy="fs_read_policy",
            trust_override=90,
            context_map={"path": "file_path"},
        )
        def tail(path: str, n: int = 10, encoding: str = "utf-8") -> str:
            """
            Return the last *n* lines of a text file (default 10, like ``tail -n 10``).

            Args:
                path:     File to read.
                n:        Number of lines (default 10).
                encoding: Character encoding (default ``"utf-8"``).  Check
                          ``mime_type`` from ``ls`` first — only call on ``text/*`` files.
            """
            from kest.deepagents.sqlitefs import SqliteFileSystem as _SqliteFS

            resolved = agent._resolve(path)
            fs = agent.fs
            if isinstance(fs, _SqliteFS):
                lines: list[str] = fs.tail(resolved, n=n, encoding=encoding)
            else:
                with fs.open(resolved, "r") as f:
                    text = f.read()
                if isinstance(text, bytes):
                    text = text.decode(encoding)
                lines = text.splitlines()[-n:] if n > 0 else []
            return "\n".join(lines)

        return tail

    def get_tee_tool(self) -> BaseTool:
        """Exposes ``tee`` — write to a file — as a kest-verified LangChain tool."""

        @tool
        @kest_verified(
            policy="fs_write_policy",
            trust_override=70,
            added_taints=["file_write"],
            context_map={"path": "file_path"},
        )
        def tee(path: str, content: str) -> str:
            """Write content to a file on the configured filesystem."""
            resolved = self._resolve(path)
            # For local FS ensure parent dirs exist (fsspec file:// doesn't do this)
            if isinstance(self.fs, LocalFileSystem):
                Path(resolved).parent.mkdir(parents=True, exist_ok=True)
            with self.fs.open(resolved, "w") as f:
                f.write(content)
            return f"Written {len(content)} bytes to '{path}'."

        return tee

    def get_append_tool(self) -> BaseTool:
        """Exposes ``append`` — append text to a file — as a kest-verified LangChain tool."""

        agent = self

        @tool
        @kest_verified(
            policy="fs_write_policy",
            trust_override=70,
            added_taints=["file_write"],
            context_map={"path": "file_path"},
        )
        def append(path: str, content: str) -> str:
            """
            Append *content* to the end of a file on the configured filesystem.

            If the file does not exist it is created.  A newline is inserted
            between the existing content and the appended text if the existing
            content does not already end with one.

            Args:
                path:    Target file (relative to root or absolute within root).
                content: Text to append.

            Returns:
                Confirmation string with the number of bytes appended.
            """
            resolved = agent._resolve(path)
            # Read existing content (empty string for new files)
            try:
                _raw = agent.fs.cat_file(resolved, encoding="utf-8")
                existing: str = _raw if isinstance(_raw, str) else _raw.decode("utf-8")
            except FileNotFoundError:
                existing = ""
            # Join with a newline separator only when needed
            if existing and not existing.endswith("\n"):
                body = existing + "\n" + content
            else:
                body = existing + content
            if isinstance(agent.fs, LocalFileSystem):
                Path(resolved).parent.mkdir(parents=True, exist_ok=True)
            with agent.fs.open(resolved, "w") as f:
                f.write(body)
            return f"Appended {len(content)} bytes to '{path}'."

        return append

    def get_ls_tool(self) -> BaseTool:
        """Exposes ``ls`` — list directory entries — as a kest-verified LangChain tool."""

        @tool
        @kest_verified(
            policy="fs_read_policy",
            trust_override=95,
            context_map={"path": "dir_path"},
        )
        def ls(path: str = ".") -> str:
            """List the entries of a directory on the configured filesystem."""
            resolved = self._resolve(path)
            raw = self.fs.ls(resolved, detail=False)
            entries = sorted(e.rstrip("/").split("/")[-1] for e in raw)
            return "\n".join(entries) if entries else "(empty directory)"

        return ls

    def get_rm_tool(self) -> BaseTool:
        """Exposes ``rm`` — delete a file — as a kest-verified LangChain tool."""

        @tool
        @kest_verified(
            policy="fs_delete_policy",
            trust_override=50,
            added_taints=["file_delete"],
            context_map={"path": "file_path"},
        )
        def rm(path: str) -> str:
            """Delete a file on the configured filesystem."""
            resolved = self._resolve(path)
            self.fs.rm(resolved)
            return f"Deleted '{path}'."

        return rm

    def get_grep_tool(self) -> BaseTool:
        """Exposes ``grep`` — recursive pattern search — as a kest-verified LangChain tool."""

        @tool
        @kest_verified(
            policy="fs_read_policy",
            trust_override=85,
            context_map={"pattern": "search_pattern", "path": "search_path"},
        )
        def grep(pattern: str, path: str = ".") -> str:
            """Search recursively for a pattern in files on the configured filesystem."""
            resolved = self._resolve(path)
            matches: list[str] = []
            for entry in self.fs.find(resolved):
                if self.fs.isdir(entry):
                    continue
                try:
                    with self.fs.open(entry, "r") as fh:
                        raw = fh.read()
                        text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
                        for lineno, line in enumerate(text.splitlines(), 1):
                            if pattern in line:
                                # Show path relative to root when possible
                                display = entry[len(resolved):].lstrip("/") or entry
                                matches.append(f"{display}:{lineno}: {line}")
                except (UnicodeDecodeError, PermissionError, IsADirectoryError):
                    continue
            return "\n".join(matches)

        return grep

    def get_exec_tool(self) -> BaseTool:
        """
        Exposes ``exec`` — run an allow-listed local shell command — as a kest-verified tool.

        Only available when ``fs`` is a ``LocalFileSystem`` and
        ``allow_shell=True``.

        Raises:
            RuntimeError: If ``allow_shell=False``.
        """
        if not self.allow_shell:
            raise RuntimeError(
                "exec is disabled. Construct FsspecAgent with "
                "allow_shell=True and a non-empty allowed_commands list to enable it."
            )

        @tool
        @kest_verified(
            policy="fs_exec_policy",
            trust_override=60,
            added_taints=["shell_exec"],
            context_map={"command": "shell_command"},
        )
        def exec(command: str, argv: Optional[List[str]] = None) -> str:  # noqa: A001
            """
            Run an allow-listed command inside the local root directory.

            Args:
                command: Executable name (must be in allowed_commands).
                argv:    Optional list of arguments.

            Returns:
                Combined stdout + stderr as a single string.
            """
            if command not in self.allowed_commands:
                raise PermissionError(
                    f"'{command}' is not in allowed_commands {self.allowed_commands}. "
                    "Add it to the FsspecAgent allowlist to permit execution."
                )

            cmd = [command] + (argv or [])
            lines: list[str] = []
            with subprocess.Popen(
                cmd,
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            ) as proc:
                assert proc.stdout is not None
                for line in proc.stdout:
                    lines.append(line.rstrip())

            return "\n".join(lines)

        return exec

    def get_mkdir_tool(self) -> BaseTool:
        """
        Exposes ``mkdir`` — create a directory — as a kest-verified tool.

        Uses ``create_parents=True`` so intermediate directories are always
        created (like ``mkdir -p``).
        """

        agent = self

        @tool
        @kest_verified(
            policy="fs_write_policy",
            trust_override=70,
            context_map={"path": "file_path"},
        )
        def mkdir(path: str) -> str:
            """
            Create a directory (and any missing parents) on the filesystem.

            Args:
                path: Directory path to create (relative to the current root).

            Returns:
                Confirmation string with the resolved absolute path.
            """
            resolved = agent._resolve(path)
            agent.fs.mkdir(resolved, create_parents=True)
            return f"created: {resolved}"

        return mkdir

    # ------------------------------------------------------------------
    # Mount tool (interactive, HITL)
    # ------------------------------------------------------------------

    @classmethod
    def build_fs(cls, scheme: str, params: Dict[str, str]) -> AbstractFileSystem:
        """
        Construct an ``AbstractFileSystem`` from a registry scheme and a
        flat dict of driver params.

        Raises:
            ValueError:    If *scheme* is not in ``FILESYSTEM_REGISTRY``.
            ImportError:   If the required driver package is not installed.
        """
        import fsspec  # local import — optional driver deps may be absent

        spec = FILESYSTEM_REGISTRY.get(scheme)
        if spec is None:
            known = ", ".join(FILESYSTEM_REGISTRY)
            raise ValueError(f"Unknown scheme '{scheme}'. Known: {known}")

        if spec.import_check:
            try:
                importlib.import_module(spec.import_check)
            except ModuleNotFoundError as exc:
                raise ImportError(
                    f"The '{spec.import_check}' package is required for the '{scheme}' driver.\n"
                    f"Install it with:  uv add kest-deepagents[{scheme}]  "
                    f"or  pip install {spec.import_check}"
                ) from exc

        if scheme == "file":
            return LocalFileSystem()
        if scheme == "memory":
            import fsspec as _fsspec
            return _fsspec.filesystem("memory")
        if scheme == "sqlite":
            from kest.deepagents.sqlitefs import SqliteFileSystem
            return SqliteFileSystem(db_path=params.get("db_path", ":memory:"))

        # Cast numeric params (port) to int where the driver expects it
        _cast: Dict[str, Any] = {}
        for k, v in params.items():
            try:
                _cast[k] = int(v)
            except (ValueError, TypeError):
                _cast[k] = v

        if scheme == "s3":
            # s3fs requires endpoint_url inside client_kwargs AND as a top-level
            # kwarg for path-style access against non-AWS endpoints (e.g. RustFS)
            endpoint_url = str(params.get("endpoint_url", ""))
            _cast.setdefault("client_kwargs", {"endpoint_url": endpoint_url})

        return fsspec.filesystem(scheme, **_cast)

    def get_mount_tool(self) -> BaseTool:
        """
        Expose an interactive ``mount_fs`` tool that drives a HITL credential
        collection conversation.

        The tool uses a 3-step JSON protocol:

        1. **ParamRequest** — call with only ``scheme`` (and optional ``params``).
           The tool returns which required fields are still missing so the UI
           can render appropriate input fields (password fields masked).

        2. **ConfirmRequest** — call once all params are supplied but without
           ``"confirmed": "true"`` in ``params``. The tool returns a sanitised
           summary (no passwords) for the user to review.

        3. **MountResult** — call with all params *plus* ``"confirmed": "true"``.
           The filesystem is switched; the tool returns the updated
           protocol/root for the UI banner.

        The ``params`` argument is a JSON-encoded ``dict[str, str]``.  Using a
        single JSON string avoids variadic kwargs, keeping the tool signature
        static and compatible with kest's introspection.
        """

        @tool
        @kest_verified(
            policy="fs_mount_policy",
            trust_override=70,
            added_taints=["fs_mount"],
            context_map={"scheme": "target_scheme"},
        )
        def mount_fs(scheme: str, params: str = "{}") -> str:
            """
            Interactively switch the agent to a different filesystem.

            Args:
                scheme: fsspec protocol name (e.g. "s3", "ftp", "file", "memory").
                params: JSON object with driver credentials and options.
                        Include ``"root"`` for the base path.
                        Include ``"confirmed": "true"`` to commit the mount.

            Returns:
                JSON-encoded ParamRequest | ConfirmRequest | MountResult.
            """
            try:
                kw: Dict[str, str] = json.loads(params) if params.strip() else {}
            except json.JSONDecodeError as exc:
                raise ValueError(f"params must be a valid JSON object: {exc}") from exc

            spec = FILESYSTEM_REGISTRY.get(scheme)
            if spec is None:
                known = ", ".join(FILESYSTEM_REGISTRY)
                raise ValueError(f"Unknown scheme '{scheme}'. Known schemes: {known}")

            # Check optional driver dependency
            if spec.import_check:
                try:
                    importlib.import_module(spec.import_check)
                except ModuleNotFoundError:
                    return json.dumps({
                        "type": "ImportError",
                        "scheme": scheme,
                        "message": (
                            f"The '{spec.import_check}' package is required.\n"
                            f"Install it with: uv add kest-deepagents[{scheme}]"
                        ),
                    })

            # --- Step 1: discover missing required params ---
            missing = [
                asdict(p)
                for p in spec.params
                if p.required and p.name not in kw and not p.default
            ]
            provided_safe = {
                k: ("****" if any(p.password and p.name == k for p in spec.params) else v)
                for k, v in kw.items()
                if k not in ("confirmed",)
            }

            if missing:
                # Apply defaults for any missing optional / defaulted params so
                # the TUI form pre-fills them correctly.
                return json.dumps(asdict(ParamRequest(
                    scheme=scheme,
                    missing=missing,
                    provided=provided_safe,
                )))

            # --- Step 2: await confirmation ---
            confirmed = kw.pop("confirmed", "").lower() in ("true", "1", "yes", "y")
            if not confirmed:
                root = kw.get("root", ".")
                display_parts = [f"scheme={scheme}", f"root={root}"]
                for p in spec.params:
                    val = kw.get(p.name, p.default)
                    if val:
                        display_parts.append(
                            f"{p.name}={'****' if p.password else val}"
                        )
                summary = "Mount: " + ", ".join(display_parts)
                return json.dumps(asdict(ConfirmRequest(
                    scheme=scheme,
                    summary=summary,
                    safe_params=provided_safe,
                )))

            # --- Step 3: build & mount ---
            root = kw.pop("root", ".")
            driver_kw = {k: v for k, v in kw.items() if k != "root"}
            new_fs = FsspecAgent.build_fs(scheme, driver_kw)

            shell_disabled = False
            if self.allow_shell and not isinstance(new_fs, LocalFileSystem):
                # Auto-disable shell rather than rejecting the mount.
                # The TUI will surface a prominent warning to the user.
                self.allow_shell = False
                shell_disabled = True

            self._fs = new_fs
            self._root = posixpath.normpath(root)
            proto = self.protocol

            return json.dumps(asdict(MountResult(
                protocol=proto,
                root=self._root,
                message=f"Mounted {proto}::{self._root} successfully.",
                shell_disabled=shell_disabled,
            )))

        return mount_fs

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def get_tools(self) -> List[BaseTool]:
        """
        Return all available tools as a list suitable for a LangChain agent executor.

        ``exec`` is included only when ``allow_shell=True``.
        ``mount_fs`` is always included.
        """
        tools: List[BaseTool] = [
            self.get_ls_tool(),
            self.get_cat_tool(),
            self.get_head_tool(),
            self.get_tail_tool(),
            self.get_grep_tool(),
            self.get_tee_tool(),
            self.get_append_tool(),
            self.get_rm_tool(),
            self.get_mkdir_tool(),
            self.get_mount_tool(),
        ]
        if self.allow_shell:
            tools.append(self.get_exec_tool())
        return tools
