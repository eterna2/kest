import pytest
import httpx


@pytest.mark.live
@pytest.mark.asyncio
async def test_opa_policy_enforcement():
    """
    Test that OPA properly enforces rules based on Kest identities and baggage contexts natively.
    """
    opa_url = "http://opa:8181/v1/data/kest"

    async with httpx.AsyncClient() as client:
        # Positive Match - hop2 with trust >= 50
        payload_pass = {
            "input": {
                "principal": "spiffe://kest.internal/workload/hop2",
                "trust_score": 80,
            }
        }
        res_pass = await client.post(opa_url, json=payload_pass)
        assert res_pass.status_code == 200
        # When querying the package root /v1/data/kest, result is the package object
        assert res_pass.json().get("result", {}).get("allow") is True

        # Negative Match - low trust score
        payload_fail = {
            "input": {
                "principal": "spiffe://kest.internal/workload/hop2",
                "trust_score": 20,
            }
        }
        res_fail = await client.post(opa_url, json=payload_fail)
        assert res_fail.status_code == 200
        assert res_fail.json().get("result", {}).get("allow") is False
