import pytest
import httpx


@pytest.mark.live
@pytest.mark.asyncio
async def test_opa_policy_enforcement():
    """
    F-PE-01, F-PE-02: Test that OPA properly enforces rules based on Kest
    identities and trust scores on the 0-100 integer scale.

    The rego policy (kest.rego) uses:
      - trust_score >= 50 for machine-to-machine (no user)
      - trust_score >= 10 when user is present (spec key: input.user per SPEC-v0.3.0 §8.4)
    """
    opa_url = "http://opa:8181/v1/data/kest"

    async with httpx.AsyncClient() as client:
        # Positive Match - hop2 with trust >= 50 (machine-to-machine)
        payload_pass = {
            "input": {
                "principal": "spiffe://kest.internal/workload/hop2",
                "trust_score": 80,
            }
        }
        res_pass = await client.post(opa_url, json=payload_pass)
        assert res_pass.status_code == 200
        assert res_pass.json().get("result", {}).get("allow") is True

        # Negative Match - trust score below both thresholds (no user)
        payload_fail = {
            "input": {
                "principal": "spiffe://kest.internal/workload/hop2",
                "trust_score": 5,
            }
        }
        res_fail = await client.post(opa_url, json=payload_fail)
        assert res_fail.status_code == 200
        assert res_fail.json().get("result", {}).get("allow") is False, (
            f"trust_score=5 should be denied without user, "
            f"got: {res_fail.json()}"
        )

        # Edge case: trust_score=20 with user present should be allowed
        # (>= 10 threshold with user identity)
        payload_user = {
            "input": {
                "principal": "spiffe://kest.internal/workload/hop2",
                "trust_score": 20,
                "user": "alice",
            }
        }
        res_user = await client.post(opa_url, json=payload_user)
        assert res_user.status_code == 200
        assert res_user.json().get("result", {}).get("allow") is True, (
            f"trust_score=20 with user should be allowed, "
            f"got: {res_user.json()}"
        )

        # Edge case: trust_score=5 with user should also be denied
        # (below the 10 threshold)
        payload_user_low = {
            "input": {
                "principal": "spiffe://kest.internal/workload/hop2",
                "trust_score": 5,
                "user": "alice",
            }
        }
        res_user_low = await client.post(opa_url, json=payload_user_low)
        assert res_user_low.status_code == 200
        assert res_user_low.json().get("result", {}).get("allow") is False, (
            f"trust_score=5 with user should still be denied, "
            f"got: {res_user_low.json()}"
        )
