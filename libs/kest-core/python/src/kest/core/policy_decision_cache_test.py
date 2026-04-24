"""
Tests for _PolicyDecisionCache (decorators.py).

Covers:
  B-01 — Cross-request identity collision: cache must NOT collapse distinct
          (user, agent, task) combinations onto a single decision.
  R-01 — invalidate_policy_cache() clears all entries; KEST_POLICY_CACHE_TTL=0
          disables caching so every call is evaluated fresh.
"""

from kest.core.engines.engine import MockPolicyEngine
from kest.core.framework.decorators import _PolicyDecisionCache, invalidate_policy_cache

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(
    user="alice",
    agent="svc-a",
    task="read:data",
    principal="spiffe://kest.internal/workload/hop1",
):
    """Minimal context dict mirroring what @kest_verified builds."""
    return {
        "principal": principal,
        "trust_score": 80,
        "classification": "internal",
        "user": user,
        "agent": agent,
        "task": task,
    }


class _CountingEngine(MockPolicyEngine):
    """MockPolicyEngine that tracks how many times evaluate() is called."""

    def __init__(self, allow_all: bool = True):
        super().__init__(allow_all=allow_all)
        self.call_count = 0

    def evaluate(self, entry_id, policy_names, context):
        self.call_count += 1
        return super().evaluate(entry_id, policy_names, context)


# ---------------------------------------------------------------------------
# B-01: Cross-request identity isolation
# ---------------------------------------------------------------------------


def test_cache_different_user_produces_distinct_key():
    """
    B-01: Two requests from the same workload but different `kest.user` values
    must NOT share a cached decision — the second must call the engine again.
    """
    engine = _CountingEngine()
    cache = _PolicyDecisionCache(maxsize=128, ttl_seconds=60.0)

    ctx_alice = _ctx(user="alice")
    ctx_bob = _ctx(user="bob")

    cache.get_or_evaluate(engine, "eid-1", ["allow"], ctx_alice)
    cache.get_or_evaluate(engine, "eid-2", ["allow"], ctx_bob)

    assert engine.call_count == 2, (
        "Different users must not share a cached decision (B-01)"
    )


def test_cache_different_agent_produces_distinct_key():
    """
    B-01: Requests where only `kest.agent` differs must produce distinct keys.
    """
    engine = _CountingEngine()
    cache = _PolicyDecisionCache(maxsize=128, ttl_seconds=60.0)

    cache.get_or_evaluate(engine, "eid-1", ["allow"], _ctx(agent="svc-a"))
    cache.get_or_evaluate(engine, "eid-2", ["allow"], _ctx(agent="svc-b"))

    assert engine.call_count == 2, (
        "Different agents must not share a cached decision (B-01)"
    )


def test_cache_different_task_produces_distinct_key():
    """
    B-01: Requests where only `kest.task` differs must produce distinct keys.
    """
    engine = _CountingEngine()
    cache = _PolicyDecisionCache(maxsize=128, ttl_seconds=60.0)

    cache.get_or_evaluate(engine, "eid-1", ["allow"], _ctx(task="read:data"))
    cache.get_or_evaluate(engine, "eid-2", ["allow"], _ctx(task="write:data"))

    assert engine.call_count == 2, (
        "Different tasks must not share a cached decision (B-01)"
    )


def test_cache_hit_identical_identity():
    """
    B-01 (positive case): Two requests with the identical full context DO share
    a cache entry — the engine is called exactly once.
    """
    engine = _CountingEngine()
    cache = _PolicyDecisionCache(maxsize=128, ttl_seconds=60.0)

    ctx = _ctx()
    cache.get_or_evaluate(engine, "eid-1", ["allow"], ctx)
    cache.get_or_evaluate(engine, "eid-2", ["allow"], ctx)

    assert engine.call_count == 1, (
        "Identical context must hit the cache (B-01 positive case)"
    )


# ---------------------------------------------------------------------------
# R-01: invalidate_policy_cache and TTL=0
# ---------------------------------------------------------------------------


def test_invalidate_clears_module_cache():
    """
    R-01: After a cached allow decision, invalidate_policy_cache() forces a
    fresh evaluation on the next call.
    """
    from kest.core.framework.decorators import _POLICY_CACHE

    engine = _CountingEngine()
    ctx = _ctx(user="alice-r01")

    _POLICY_CACHE.get_or_evaluate(engine, "eid-1", ["allow"], ctx)
    assert engine.call_count == 1

    invalidate_policy_cache()

    _POLICY_CACHE.get_or_evaluate(engine, "eid-2", ["allow"], ctx)
    assert engine.call_count == 2, (
        "invalidate_policy_cache() must force a fresh evaluation (R-01)"
    )


def test_ttl_zero_disables_caching():
    """
    R-01: A cache with TTL=0 must call the engine on every invocation
    because every entry is immediately stale.
    """
    engine = _CountingEngine()
    cache = _PolicyDecisionCache(maxsize=128, ttl_seconds=0.0)

    ctx = _ctx(user="alice-ttl0")
    for i in range(3):
        cache.get_or_evaluate(engine, f"eid-{i}", ["allow"], ctx)

    assert engine.call_count == 3, "TTL=0 must disable caching (R-01)"
