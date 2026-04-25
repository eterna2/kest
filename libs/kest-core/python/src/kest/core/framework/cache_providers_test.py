"""TDD tests for CacheProvider backends — written before implementation."""

import threading
import time

import pytest

from kest.core.framework.cache_providers import SQLiteCache

# ---------------------------------------------------------------------------
# SQLiteCache (stdlib — always available)
# ---------------------------------------------------------------------------


class TestSQLiteCache:
    def test_get_missing_returns_none(self):
        cache = SQLiteCache()
        assert cache.get("missing") is None

    def test_set_and_get(self):
        cache = SQLiteCache()
        cache.set("k", {"value": 42})
        assert cache.get("k") == {"value": 42}

    def test_overwrite(self):
        cache = SQLiteCache()
        cache.set("k", "first")
        cache.set("k", "second")
        assert cache.get("k") == "second"

    def test_ttl_expiry(self):
        cache = SQLiteCache()
        cache.set("k", "v", ttl=1)
        assert cache.get("k") == "v"
        time.sleep(1.1)
        assert cache.get("k") is None

    def test_no_ttl_persists(self):
        cache = SQLiteCache()
        cache.set("k", "v")
        time.sleep(0.1)
        assert cache.get("k") == "v"

    def test_stores_various_types(self):
        cache = SQLiteCache()
        for obj in [42, "str", [1, 2], {"a": 1}, None, b"bytes"]:
            cache.set("key", obj)
            assert cache.get("key") == obj

    def test_thread_safety(self):
        cache = SQLiteCache()
        errors = []

        def worker(i):
            try:
                cache.set(f"k{i}", i)
                assert cache.get(f"k{i}") == i
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors

    def test_persistent_file(self, tmp_path):
        db = str(tmp_path / "vault.db")
        cache = SQLiteCache(db_path=db)
        cache.set("persistent", "value")
        # Re-open the same file
        cache2 = SQLiteCache(db_path=db)
        assert cache2.get("persistent") == "value"


# ---------------------------------------------------------------------------
# LMDBCache — skip if not installed
# ---------------------------------------------------------------------------

lmdb_skip = pytest.mark.skipif(
    __import__("importlib").util.find_spec("lmdb") is None,
    reason="lmdb not installed — install kest[lmdb]",
)


@lmdb_skip
class TestLMDBCache:
    def _cache(self):
        from kest.core.framework.cache_providers import LMDBCache

        return LMDBCache()

    def test_get_missing_returns_none(self):
        assert self._cache().get("nope") is None

    def test_set_and_get(self):
        c = self._cache()
        c.set("k", {"x": 1})
        assert c.get("k") == {"x": 1}

    def test_ttl_expiry(self):
        c = self._cache()
        c.set("k", "v", ttl=1)
        assert c.get("k") == "v"
        time.sleep(1.1)
        assert c.get("k") is None

    def test_missing_dep_raises(self, monkeypatch):
        import sys

        monkeypatch.setitem(sys.modules, "lmdb", None)
        import importlib

        from kest.core.framework import cache_providers

        importlib.reload(cache_providers)
        with pytest.raises(ImportError, match="kest\\[lmdb\\]"):
            cache_providers.LMDBCache()


# ---------------------------------------------------------------------------
# CachetoolsCache — skip if not installed
# ---------------------------------------------------------------------------

cachetools_skip = pytest.mark.skipif(
    __import__("importlib").util.find_spec("cachetools") is None,
    reason="cachetools not installed — install kest[cachetools]",
)


@cachetools_skip
class TestCachetoolsCache:
    def _lru(self):
        from kest.core.framework.cache_providers import CachetoolsCache

        return CachetoolsCache(maxsize=16)

    def _ttl(self, ttl=10):
        from kest.core.framework.cache_providers import CachetoolsCache

        return CachetoolsCache(maxsize=16, default_ttl=ttl)

    def test_get_missing_returns_none(self):
        assert self._lru().get("nope") is None

    def test_set_and_get_lru(self):
        c = self._lru()
        c.set("k", 99)
        assert c.get("k") == 99

    def test_set_and_get_ttl(self):
        c = self._ttl(ttl=10)
        c.set("k", "v")
        assert c.get("k") == "v"

    def test_ttl_eviction(self):
        c = self._ttl(ttl=1)
        c.set("k", "v")
        time.sleep(1.1)
        assert c.get("k") is None

    def test_lru_eviction(self):
        c = self._lru()
        # maxsize=16 — fill it up then add one more
        for i in range(17):
            c.set(f"k{i}", i)
        # At least one key should be evicted (LRU)
        evicted = sum(1 for i in range(17) if c.get(f"k{i}") is None)
        assert evicted >= 1


# ---------------------------------------------------------------------------
# RedisCache — skip if not installed, use fakeredis
# ---------------------------------------------------------------------------

redis_skip = pytest.mark.skipif(
    __import__("importlib").util.find_spec("redis") is None
    or __import__("importlib").util.find_spec("fakeredis") is None,
    reason="redis/fakeredis not installed",
)


@redis_skip
class TestRedisCache:
    def _cache(self):
        import fakeredis

        from kest.core.framework.cache_providers import RedisCache

        c = RedisCache.__new__(RedisCache)
        c._client = fakeredis.FakeRedis()
        return c

    def test_get_missing_returns_none(self):
        assert self._cache().get("nope") is None

    def test_set_and_get(self):
        c = self._cache()
        c.set("k", {"data": 1})
        assert c.get("k") == {"data": 1}

    def test_ttl_expiry(self):
        c = self._cache()
        c.set("k", "v", ttl=1)
        assert c.get("k") == "v"
        time.sleep(1.1)
        assert c.get("k") is None

    def test_overwrite(self):
        c = self._cache()
        c.set("k", "a")
        c.set("k", "b")
        assert c.get("k") == "b"

    def test_missing_dep_raises(self, monkeypatch):
        import sys

        monkeypatch.setitem(sys.modules, "redis", None)
        import importlib

        from kest.core.framework import cache_providers

        importlib.reload(cache_providers)
        with pytest.raises(ImportError, match="kest\\[redis\\]"):
            cache_providers.RedisCache()


# ---------------------------------------------------------------------------
# ValkeyCache — skip if not installed, use fakeredis (RESP-compatible)
# ---------------------------------------------------------------------------

valkey_skip = pytest.mark.skipif(
    __import__("importlib").util.find_spec("valkey") is None
    or __import__("importlib").util.find_spec("fakeredis") is None,
    reason="valkey/fakeredis not installed",
)


@valkey_skip
class TestValkeyCache:
    def _cache(self):
        import fakeredis

        from kest.core.framework.cache_providers import ValkeyCache

        c = ValkeyCache.__new__(ValkeyCache)
        c._client = fakeredis.FakeRedis()
        return c

    def test_get_missing_returns_none(self):
        assert self._cache().get("nope") is None

    def test_set_and_get(self):
        c = self._cache()
        c.set("k", {"data": 1})
        assert c.get("k") == {"data": 1}

    def test_ttl_expiry(self):
        c = self._cache()
        c.set("k", "v", ttl=1)
        assert c.get("k") == "v"
        time.sleep(1.1)
        assert c.get("k") is None
