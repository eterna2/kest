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
)
from kest.core.models import PolicyDeviation

@pytest.mark.live
@pytest.mark.asyncio
async def test_policy_deviations_live():
    """
    F-PE-07, F-PE-11, F-PE-12: Verifies that global enterprise/platform policies
    and explicit deviations configured at the application level are correctly embedded
    into the generated cryptographic signature and bypass engine evaluation.
    """
    engine = OPAPolicyEngine(url="http://opa:8181")
    
    # Simulate a deployment environment where an enterprise policy 'require_mfa'
    # is mandated, but this specific application declares an approved deviation.
    deviation = PolicyDeviation(
        policy="require_mfa",
        tier="enterprise",
        reason="Service account automated task without human MFA",
        approver="secops_team"
    )
    
    configure(
        engine=engine,
        identity=MockIdentityProvider(
            principal="spiffe://kest.internal/workload/hop_deviant"
        ),
        enterprise_policies=["require_mfa"],
        deviations=[deviation],
        clear=True,
    )

    ctx = baggage.set_baggage("kest.passport", "[]")
    token = otel_context.attach(ctx)

    try:
        # A function-level policy is evaluated IN ADDITION to enterprise policies
        @kest_verified(policy="allow")
        async def deviant_function():
            return otel_context.get_current()
            
        current_ctx = await deviant_function()
        
        # Verify the generated signature embeds the deviation context
        sig = baggage.get_baggage("kest.passport", context=current_ctx)
        
        # Pull out the first (and only) hop in this local test
        jws = json.loads(sig)[0]
        
        parts = jws.split(".")
        p_b64 = parts[1]
        p_b64 += "=" * ((4 - len(p_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(p_b64).decode())
        
        pc = payload["policy_context"]
        
        assert "require_mfa" in pc["enterprise_policies"]
        assert "allow" in pc["function_policies"]
        
        dev_record = pc["deviations"][0]
        assert dev_record["policy"] == "require_mfa"
        assert dev_record["tier"] == "enterprise"
        assert dev_record["reason"] == "Service account automated task without human MFA"
        assert dev_record["approver"] == "secops_team"

        print("SUCCESS: Deviations correctly generated into tamper-evident JWS context.")
        
    finally:
        otel_context.detach(token)
