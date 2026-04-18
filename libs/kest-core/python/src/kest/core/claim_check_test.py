import hashlib
import os

import opentelemetry.context as otel_context
from opentelemetry import baggage

from kest.core import (
    BaggageManager,
    MockIdentityProvider,
    MockPolicyEngine,
    Passport,
    SimpleCache,
    configure,
    kest_verified,
)
from kest.core.framework.decorators import invalidate_policy_cache


def _incompressible_signature(target_bytes: int = 6400) -> str:
    """Generate an incompressible, URL-safe string of approximately target_bytes length."""
    chunk = hashlib.sha256(os.urandom(32)).hexdigest()  # 64 chars, high entropy
    repeats = (target_bytes // len(chunk)) + 1
    # Mix different hashes to prevent any repetition pattern
    return "".join(
        hashlib.sha256(f"{i}{chunk}".encode()).hexdigest() for i in range(repeats)
    )[:target_bytes]


def test_full_claim_check_lifecycle():
    """
    Requirement 2.1: Transition to Claim Check Pattern when Passport > 4KB (incompressible).
    We test the pack -> cache -> unpack flow.
    """
    invalidate_policy_cache()
    # 1. Setup with a shared cache
    shared_cache = SimpleCache()
    configure(
        engine=MockPolicyEngine(),
        identity=MockIdentityProvider(),
        cache=shared_cache,
        clear=True,
    )

    # 2. Use an incompressible large signature that exceeds 4KB even after compression
    large_signature = _incompressible_signature(6400)

    @kest_verified(policy="p1")
    def hop1():
        # Manually bloat the passport before return
        p = Passport(entries=[large_signature])
        # Force pack into context (BaggageManager logic)
        packed = BaggageManager.pack(p, cache=shared_cache)
        return packed

    packed_baggage = hop1()

    # Verify Hop 1 used a claim check (incompressible data stays >4KB even compressed)
    assert "kest.claim_check" in packed_baggage
    assert "kest.passport" not in packed_baggage

    # 3. Simulate Hop 2: Receives the baggage and must unpack via cache
    # Setup Hop 2 context
    ctx = otel_context.get_current()
    for k, v in packed_baggage.items():
        ctx = baggage.set_baggage(k, v, context=ctx)

    token = otel_context.attach(ctx)
    try:

        @kest_verified(policy="p2")
        def hop2():
            # The decorator inside hop2 will call BaggageManager.unpack(baggage.get_baggage, cache=shared_cache)
            # We verify by checking if the passport was correctly reconstructed.
            # (In this test, we check the baggage inside the function)
            p = BaggageManager.unpack(baggage.get_baggage, cache=shared_cache)
            return len(p.entries)

        assert (
            hop2() == 2
        )  # 1 (from Hop 1) + 1 (from Hop 2's own entry before func call)

    finally:
        otel_context.detach(token)


def test_claim_check_failure_no_cache():
    """
    F-GC-01: Verify fail-secure behavior when cache is missing for a claim check.
    """
    invalidate_policy_cache()
    configure(
        engine=MockPolicyEngine(),
        identity=MockIdentityProvider(),
        cache=None,
        clear=True,
    )

    ctx = baggage.set_baggage("kest.claim_check", "some-id")
    token = otel_context.attach(ctx)

    try:
        import pytest

        with pytest.raises(
            RuntimeError, match="no cache backend configured for retrieval"
        ):
            BaggageManager.unpack(baggage.get_baggage, cache=None)
    finally:
        otel_context.detach(token)


def test_claim_check_expired_ttl_fails_closed():
    """
    F-GC-02: If the Cache TTL expires... the claim check fails.
    The implementation MUST fail securely.
    """
    invalidate_policy_cache()
    shared_cache = SimpleCache()
    configure(
        engine=MockPolicyEngine(),
        identity=MockIdentityProvider(),
        cache=shared_cache,
        clear=True,
    )

    ctx = baggage.set_baggage("kest.claim_check", "some-expired-id")
    token = otel_context.attach(ctx)

    try:
        import pytest

        with pytest.raises(RuntimeError, match="NOT FOUND in cache"):
            BaggageManager.unpack(baggage.get_baggage, cache=shared_cache)
    finally:
        otel_context.detach(token)
