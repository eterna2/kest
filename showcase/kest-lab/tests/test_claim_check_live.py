import pytest
import base64
import json
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

    # 1. Create a massive fake baggage entry simulating upstream
    gigantic_signature = "header." + base64.urlsafe_b64encode(b'{"parent_ids":["0"],"labels":{},"trust_score":100,"added_taints":[],"removed_taints":[],"taints":[],"schema_version":"0.3.0","runtime":{"name":"kest-python","version":"0.3.0"},"operation":"mock","classification":"system","policy_context":{"enterprise_policies":[],"platform_policies":[],"app_policies":[],"function_policies":[],"deviations":[]},"entry_id":"00000000-0000-7000-8000-000000000000","timestamp_ms":1000000}').decode() + ".sig"
    # Bloat the payload to ensure it is > 4096 bytes
    large_passport = Passport(entries=[gigantic_signature] * 15)
    
    # 2. Pack it to force generate a kest.claim_check
    packed_baggage = BaggageManager.pack(large_passport, cache=shared_cache)
    
    assert "kest.claim_check" in packed_baggage
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
