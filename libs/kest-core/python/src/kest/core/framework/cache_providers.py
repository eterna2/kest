"""
Concrete CacheProvider implementations for HandleVault.

Backends
--------
- SQLiteCache      — stdlib sqlite3, in-memory or persistent file (no extra dep)
- LMDBCache        — lightning memory-mapped KV store (kest[lmdb])
- CachetoolsCache  — pure-Python LRU/TTL dict (kest[cachetools])
- RedisCache       — Redis protocol cache (kest[redis])
- ValkeyCache      — Valkey protocol cache (kest[valkey])

All five implement the CacheProvider interface and are drop-in backends for
HandleVault.
"""

from __future__ import annotations

import importlib.util
import pickle
import sqlite3
import tempfile
import threading
import time
from typing import Any, Optional

from kest.core.framework.cache import CacheProvider

# ---------------------------------------------------------------------------
# SQLiteCache
# ---------------------------------------------------------------------------


class SQLiteCache(CacheProvider):
    """
    SQLite-backed cache (stdlib — no extra dependency).

    Supports both in-memory (``db_path=":memory:"``) and persistent file
    storage. Uses WAL mode and a threading.Lock for concurrent access.
    TTL is stored as an absolute POSIX timestamp and checked lazily on ``get()``.

    Args:
        db_path: Path to the SQLite database file, or ``":memory:"`` for a
            purely in-process store (default).
        table: Name of the KV table (default ``"kv"``).
    """

    def __init__(self, db_path: str = ":memory:", table: str = "kv") -> None:
        self._db_path = db_path
        self._table = table
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection = sqlite3.connect(
            db_path, check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._setup()

    def _setup(self) -> None:
        self._conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self._table} (
                key        TEXT PRIMARY KEY,
                value      BLOB NOT NULL,
                expires_at REAL
            )
            """
        )
        self._conn.commit()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            row = self._conn.execute(
                f"SELECT value, expires_at FROM {self._table} WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        value_blob, expires_at = row
        if expires_at is not None and time.time() >= expires_at:
            with self._lock:
                self._conn.execute(f"DELETE FROM {self._table} WHERE key = ?", (key,))
                self._conn.commit()
            return None
        return pickle.loads(value_blob)

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        expires_at = (time.time() + ttl) if ttl is not None else None
        blob = pickle.dumps(value)
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO {self._table} (key, value, expires_at)"
                f" VALUES (?, ?, ?)",
                (key, blob, expires_at),
            )
            self._conn.commit()


# ---------------------------------------------------------------------------
# LMDBCache
# ---------------------------------------------------------------------------


class LMDBCache(CacheProvider):
    """
    LMDB (Lightning Memory-Mapped Database) backed cache.

    Requires: ``kest[lmdb]`` (``lmdb>=1.4``).

    Provides fastest read latency of all backends via memory-mapped B+tree.
    When ``path=None`` (default) a temporary directory is auto-created and
    deleted when the cache object is garbage-collected.

    Args:
        path: Directory path for the LMDB environment, or ``None`` to use a
            temporary directory.
        map_size: Maximum database size in bytes (default 10 MiB).
    """

    _TTL_PREFIX = b"__ttl__"

    def __init__(
        self, path: Optional[str] = None, map_size: int = 10 * 1024 * 1024
    ) -> None:
        if importlib.util.find_spec("lmdb") is None:
            raise ImportError(
                "Install kest[lmdb] to use LMDBCache: pip install kest[lmdb]"
            )
        import lmdb  # type: ignore[import]

        self._tmpdir: Optional[str] = None
        if path is None:
            self._tmpdir = tempfile.mkdtemp(prefix="kest-lmdb-")
            path = self._tmpdir

        self._env = lmdb.open(path, map_size=map_size, subdir=True)

    def __del__(self) -> None:
        try:
            self._env.close()
        except Exception:
            pass
        if self._tmpdir is not None:
            import shutil

            shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _ttl_key(self, key: str) -> bytes:
        return self._TTL_PREFIX + key.encode()

    def get(self, key: str) -> Optional[Any]:
        bkey = key.encode()
        with self._env.begin() as txn:
            ttl_data = txn.get(self._ttl_key(key))
            if ttl_data is not None:
                expires_at: float = pickle.loads(ttl_data)
                if time.time() >= expires_at:
                    return None
            data = txn.get(bkey)
        if data is None:
            return None
        return pickle.loads(data)

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        bkey = key.encode()
        blob = pickle.dumps(value)
        with self._env.begin(write=True) as txn:
            txn.put(bkey, blob)
            if ttl is not None:
                txn.put(self._ttl_key(key), pickle.dumps(time.time() + ttl))


# ---------------------------------------------------------------------------
# CachetoolsCache
# ---------------------------------------------------------------------------


class CachetoolsCache(CacheProvider):
    """
    Pure-Python in-memory cache backed by ``cachetools``.

    Requires: ``kest[cachetools]`` (``cachetools>=5.0``).

    Uses ``cachetools.TTLCache`` when ``default_ttl`` is set (evicts entries
    after the configured TTL), or ``cachetools.LRUCache`` otherwise (evicts
    least-recently-used entries when ``maxsize`` is reached).

    Note:
        Per-key TTL via ``set(ttl=...)`` is not natively supported by
        cachetools. The ``default_ttl`` acts as a cache-level eviction backstop;
        ``HandleVault``'s own lazy TTL check on ``OpaqueHandle.expires_at``
        provides per-handle expiry correctness.

    Args:
        maxsize: Maximum number of entries before eviction (default 1024).
        default_ttl: Default TTL in seconds for TTLCache mode; ``None`` uses
            LRU mode.
    """

    def __init__(
        self, maxsize: int = 1024, default_ttl: Optional[float] = None
    ) -> None:
        if importlib.util.find_spec("cachetools") is None:
            raise ImportError(
                "Install kest[cachetools] to use CachetoolsCache: "
                "pip install kest[cachetools]"
            )
        import cachetools  # type: ignore[import]

        if default_ttl is not None:
            self._cache: Any = cachetools.TTLCache(maxsize=maxsize, ttl=default_ttl)
        else:
            self._cache = cachetools.LRUCache(maxsize=maxsize)
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            return self._cache.get(key)

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        with self._lock:
            self._cache[key] = value


# ---------------------------------------------------------------------------
# _RESPCache base (Redis / Valkey / KeyDB share the same RESP protocol)
# ---------------------------------------------------------------------------


class _RESPCache(CacheProvider):
    """
    Internal base class for RESP-protocol caches (Redis, Valkey, KeyDB).

    Values are pickle-serialised before storage; TTL is delegated to the
    server's native key expiry (``SETEX``).
    """

    _client: Any  # set by subclasses

    def get(self, key: str) -> Optional[Any]:
        data = self._client.get(key)
        if data is None:
            return None
        return pickle.loads(data)

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        blob = pickle.dumps(value)
        if ttl is not None:
            self._client.setex(key, ttl, blob)
        else:
            self._client.set(key, blob)


class RedisCache(_RESPCache):
    """
    Redis-backed cache.

    Requires: ``kest[redis]`` (``redis>=5.0``).

    Also compatible with **KeyDB** — point ``host``/``port`` at your KeyDB
    endpoint and this class works without modification.

    Args:
        host: Redis host (default ``"localhost"``).
        port: Redis port (default ``6379``).
        db: Redis database index (default ``0``).
        **kwargs: Passed through to ``redis.Redis()``.
    """

    def __init__(
        self, host: str = "localhost", port: int = 6379, db: int = 0, **kwargs: Any
    ) -> None:
        if importlib.util.find_spec("redis") is None:
            raise ImportError(
                "Install kest[redis] to use RedisCache: pip install kest[redis]"
            )
        import redis  # type: ignore[import]

        self._client = redis.Redis(host=host, port=port, db=db, **kwargs)


class ValkeyCache(_RESPCache):
    """
    Valkey-backed cache.

    Requires: ``kest[valkey]`` (``valkey>=6.0``).

    Valkey is a BSD-3 open-source Redis fork maintained by the Linux
    Foundation. It is a drop-in replacement for Redis at the protocol level.

    Args:
        host: Valkey host (default ``"localhost"``).
        port: Valkey port (default ``6379``).
        db: Valkey database index (default ``0``).
        **kwargs: Passed through to ``valkey.Valkey()``.
    """

    def __init__(
        self, host: str = "localhost", port: int = 6379, db: int = 0, **kwargs: Any
    ) -> None:
        if importlib.util.find_spec("valkey") is None:
            raise ImportError(
                "Install kest[valkey] to use ValkeyCache: pip install kest[valkey]"
            )
        import valkey  # type: ignore[import]

        self._client = valkey.Valkey(host=host, port=port, db=db, **kwargs)
