import pytest
import base64
import os
from opentelemetry import baggage
import opentelemetry.context as otel_context
from kest.core import (
    kest_verified,
    configure,
    OPAPolicyEngine,
    MockIdentityProvider,
    SimpleCache,
    BaggageManager,
    Passport,
)

@pytest.mark.live
@pytest.mark.asyncio
async def test_live_claim_check_rehydration():
    """
    F-CP-04, F-CP-05, F-GC-01: Verifies that live OPAPolicyEngine execution successfully
    parses and rehydrates passports that arrived via a cache Claim Check reference,
    simulating Baggage limits > 4096 bytes.

    Uses cryptographically random (incompressible) JWS payload data so that zlib
    compression cannot deflate the passport below the 4096-byte inline threshold,
    ensuring the claim-check path is exercised even post-Fix-3 (compressed baggage).
    """
    engine = OPAPolicyEngine(url="http://opa:8181")
    shared_cache = SimpleCache()
    configure(
        engine=engine,
        identity=MockIdentityProvider(
            principal="spiffe://kest.internal/workload/hop_giant"
        ),
        cache=shared_cache,
        clear=True,
    )

    # 1. Create a massive passport using unique, incompressible random payloads.
    # Each entry has a distinct random signature so zlib cannot compress the set.
    def _make_incompressible_entry():
        random_sig = base64.urlsafe_b64encode(os.urandom(400)).decode()
        payload = base64.urlsafe_b64encode(
            b'{"parent_ids":["0"],"trust_score":100,"timestamp_ms":1000000}'
        ).decode()
        return f"header.{payload}.{random_sig}"

    large_passport = Passport(entries=[_make_incompressible_entry() for _ in range(15)])

    # 2. Pack it — the random data should force the claim-check path
    packed_baggage = BaggageManager.pack(large_passport, cache=shared_cache)

    assert "kest.claim_check" in packed_baggage, (
        f"Expected claim-check with incompressible data (15 random entries), "
        f"got keys: {list(packed_baggage.keys())}"
    )
    assert "kest.passport" not in packed_baggage

    # 3. Attach only the claim check to ambient OTel Context
    ctx = otel_context.get_current()
    for k, v in packed_baggage.items():
        ctx = baggage.set_baggage(k, v, context=ctx)
        
    token = otel_context.attach(ctx)

    try:
        # 4. Invoke a live verified operation. The `kest_verified` hook must correctly
        # unpack from the cache, evaluate via OPA, and append.
        @kest_verified(policy="allow")
        async def downstream_consumer():
            return BaggageManager.unpack(baggage.get_baggage, cache=shared_cache)
            
        final_passport = await downstream_consumer()
        
        # 5. Assert that the rehydrated lineage contains the original 15 entries + the new 1 entry.
        assert len(final_passport.entries) == 16
        print("SUCCESS: Live claim-check baggage correctly bypassed string limits and rehydrated for OPA evaluation.")
        
    finally:
        otel_context.detach(token)
