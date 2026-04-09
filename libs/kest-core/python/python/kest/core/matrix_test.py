import opentelemetry.context as otel_context
from opentelemetry import baggage

from kest.core import (
    MockIdentityProvider,
    MockPolicyEngine,
    SimpleCache,
    configure,
    kest_verified,
)


def test_matrix_multi_policy_allow():
    # Scenario: Multi-policy aggregation (AND logic)
    class MultiAllowEngine(MockPolicyEngine):
        def evaluate(self, entry_id, policy_names, context):
            return "p1" in policy_names and "p2" in policy_names

    configure(engine=MultiAllowEngine(), identity=MockIdentityProvider(), clear=True)

    @kest_verified(policy=["p1", "p2"])
    def multi_func():
        return "allowed"

    assert multi_func() == "allowed"


def test_matrix_task_level_override():
    # Scenario: Task-level engine override
    global_engine = MockPolicyEngine(allow_all=False)
    task_engine = MockPolicyEngine(allow_all=True)

    configure(engine=global_engine, identity=MockIdentityProvider(), clear=True)

    @kest_verified(policy="test", engine=task_engine)
    def override_func():
        return "allowed"

    # Should succeed because of task-level override
    assert override_func() == "allowed"


def test_matrix_trust_bootstrap_internet():
    # Scenario: Trust bootstrapping for root node (internet source)
    engine = MockPolicyEngine()
    configure(engine=engine, identity=MockIdentityProvider(), clear=True)

    @kest_verified(policy="test", origin="internet")
    def root_func():
        return "ok"

    assert root_func() == "ok"


def test_matrix_hybrid_baggage_claim_check():
    # Scenario: Baggage > 4KB triggers Claim Check
    cache = SimpleCache()
    configure(
        engine=MockPolicyEngine(),
        identity=MockIdentityProvider(),
        cache=cache,
        clear=True,
    )

    # Mock a large passport by manually setting baggage
    large_data = "x" * 5000
    ctx = baggage.set_baggage("kest.passport", f'["{large_data}"]')
    token = otel_context.attach(ctx)

    try:

        @kest_verified(policy="test")
        def big_lineage_func():
            # In latest implementation, pack happens at the END of the decorator wrapper.
            # So inside big_lineage_func, the claim_check won't be in context yet
            # unless it was passed from a parent.
            return True

        big_lineage_func()
        # After execution, the current context (new context returned by set_baggage)
        # should have the claim_check if we were able to capture the returned context.
        # But decorators in OTEL are tricky with context propagation to the caller.
        # We verify via the cache.
        assert any(k.startswith("kest.claim.") for k in cache._data.keys())
    finally:
        otel_context.detach(token)


def test_matrix_lazy_signing():
    # Scenario: Lazy signing returns pending hash
    from kest.core import LazySigningProvider

    real_id = MockIdentityProvider()
    lazy_id = LazySigningProvider(real_id)

    configure(engine=MockPolicyEngine(), identity=lazy_id, clear=True)

    @kest_verified(policy="test")
    def lazy_func():
        # Inside the function, the baggage hasn't been updated yet with the CURRENT signature
        # because the decorator updates it AFTER calling identity.sign() but BEFORE calling func.
        # Wait, the decorator DOES update context before calling func.
        return baggage.get_baggage("kest.chain_tip")

    pending_root = lazy_func()
    assert pending_root is not None
    assert len(pending_root) == 64
