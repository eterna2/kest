import pytest
from opentelemetry import baggage
from kest.core import kest_verified, configure, MockIdentityProvider, MockPolicyEngine


def test_merkle_chain_propagation():
    # 1. Setup
    configure(engine=MockPolicyEngine(), identity=MockIdentityProvider(), clear=True)

    @kest_verified(policy="step1")
    def step1():
        # Inside step1, baggage should have 1 entry.
        # We call step2 INSIDE step1 to ensure context propagation.
        return step2()

    @kest_verified(policy="step2")
    def step2():
        # Inside step2, baggage should have 2 entries.
        return baggage.get_baggage("kest.passport")

    # 2. Execution
    assert baggage.get_baggage("kest.passport") is None

    passport_final = step1()
    assert passport_final is not None
    # Serialized list: ["sig1", "sig2"]
    assert passport_final.count("mock-sig") == 2


def test_fail_closed_no_engine():
    configure(engine=None, identity=MockIdentityProvider(), clear=True)

    @kest_verified(policy="test")
    def fail_func():
        return "ok"

    with pytest.raises(PermissionError, match="No PolicyEngine configured"):
        fail_func()


def test_fail_closed_policy_deny():
    configure(
        engine=MockPolicyEngine(allow_all=False),
        identity=MockIdentityProvider(),
        clear=True,
    )

    @kest_verified(policy="test")
    def deny_func():
        return "ok"

    with pytest.raises(PermissionError, match="denied execution"):
        deny_func()
