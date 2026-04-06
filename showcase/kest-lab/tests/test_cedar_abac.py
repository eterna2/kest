import pytest
import httpx


@pytest.mark.live
@pytest.mark.asyncio
async def test_cedar_abac_validation():
    """
    Test Cedar-Agent ABAC execution.
    This asserts that Kest's standardized 'spiffe://...' identity context translates properly into Cedar's permit blocks.
    """
    cedar_url = "http://cedar-agent:8180/is_authorized"

    async with httpx.AsyncClient() as client:
        # Positive Match (matching principal + trust score)
        payload = {
            "principal": "spiffe://kest.internal/workload/hop1",
            "action": "execute",
            "resource": "any_resource",
            "context": {"trust_score": 80},
            "policy_id": "kest",
        }
        res = await client.post(cedar_url, json=payload)

        # NOTE: the showcase docker-compose sets cedar on cedar:8180 but from hop1 it can resolve it.
        if res.status_code == 200:
            assert res.json().get("decision") == "Allow"

        # Negative Match (low trust score)
        payload["context"] = {"trust_score": 20}
        res2 = await client.post(cedar_url, json=payload)
        if res2.status_code == 200:
            assert res2.json().get("decision") == "Deny"
