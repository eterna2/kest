import httpx
import pytest
import respx

from kest.core import (
    AVPPolicyEngine,
    CedarLocalEngine,
    CedarPolicyEngine,
    MockPolicyEngine,
    OPAPolicyEngine,
    PolicyCache,
)


@pytest.mark.asyncio
@respx.mock
async def test_opa_engine_aggregation_and_logic():
    engine = OPAPolicyEngine(url="http://opa:8181")

    respx.post("http://opa:8181/v1/data/kest/p1").mock(
        return_value=httpx.Response(200, json={"result": {"allow": True}})
    )
    respx.post("http://opa:8181/v1/data/kest/p2").mock(
        return_value=httpx.Response(200, json={"result": {"allow": False}})
    )

    assert engine.evaluate("id", ["p1"], {"principal": "test"}) is True
    assert engine.evaluate("id", ["p1", "p2"], {"principal": "test"}) is False

    # Async evaluation
    assert await engine.async_evaluate("id", ["p1"], {"principal": "test"}) is True
    assert (
        await engine.async_evaluate("id", ["p1", "p2"], {"principal": "test"}) is False
    )


@pytest.mark.asyncio
@respx.mock
async def test_opa_engine_fail_secure():
    engine = OPAPolicyEngine(url="http://opa:8181")

    respx.post("http://opa:8181/v1/data/kest/p1").mock(return_value=httpx.Response(500))

    assert engine.evaluate("id", ["p1"], {}) is False
    assert await engine.async_evaluate("id", ["p1"], {}) is False

    respx.post("http://opa:8181/v1/data/kest/p2").mock(
        side_effect=httpx.ConnectError("Network Error")
    )
    assert engine.evaluate("id", ["p2"], {}) is False
    assert await engine.async_evaluate("id", ["p2"], {}) is False


@pytest.mark.asyncio
@respx.mock
async def test_cedar_engine():
    engine = CedarPolicyEngine(url="http://cedar:8180")

    respx.post("http://cedar:8180/is_authorized").mock(
        return_value=httpx.Response(200, json={"decision": "Allow"})
    )
    assert engine.evaluate("id", ["p1"], {}) is True
    assert await engine.async_evaluate("id", ["p1"], {}) is True

    respx.post("http://cedar:8180/is_authorized").mock(
        return_value=httpx.Response(200, json={"decision": "Deny"})
    )
    assert engine.evaluate("id", ["p1"], {}) is False
    assert await engine.async_evaluate("id", ["p1"], {}) is False

    respx.post("http://cedar:8180/is_authorized").mock(
        side_effect=httpx.ConnectError("Network Error")
    )
    assert engine.evaluate("id", ["p1"], {}) is False
    assert await engine.async_evaluate("id", ["p1"], {}) is False


def test_cedar_local_engine():
    import importlib.util

    if importlib.util.find_spec("cedarpy") is None:
        pytest.skip("cedarpy not installed")

    engine = CedarLocalEngine({"p1": "permit(principal, action, resource);"}, [])
    assert engine.evaluate("id", ["p1"], {}) is True


@pytest.mark.asyncio
async def test_cedar_local_engine_async():
    import importlib.util

    if importlib.util.find_spec("cedarpy") is None:
        pytest.skip("cedarpy not installed")

    engine = CedarLocalEngine({"p1": "permit(principal, action, resource);"}, [])
    assert await engine.async_evaluate("id", ["p1"], {}) is True


def test_avp_engine_no_boto3():
    # If boto3 is not installed, it should raise ImportError on evaluate.
    # We can simulate this by instantiating and explicitly clearing boto3.
    engine = AVPPolicyEngine("store-123")
    boto3_bak = engine.boto3
    engine.boto3 = None
    with pytest.raises(ImportError):
        engine.evaluate("id", ["p1"], {})
    engine.boto3 = boto3_bak


@pytest.mark.asyncio
async def test_avp_engine_no_aioboto3():
    engine = AVPPolicyEngine("store-123")
    aioboto3_bak = engine.aioboto3
    boto3_bak = engine.boto3
    engine.aioboto3 = None
    engine.boto3 = None
    with pytest.raises(ImportError):
        await engine.async_evaluate("id", ["p1"], {})
    engine.aioboto3 = aioboto3_bak
    engine.boto3 = boto3_bak


def test_mock_engine_logic():
    engine = MockPolicyEngine(allow_all=True)
    assert engine.evaluate("id", ["p1"], {}) is True

    engine.allow_all = False
    assert engine.evaluate("id", ["p1"], {}) is False


def test_policy_cache_hits():
    cache = PolicyCache()
    cache.set("some-policy", "compiled-bytecode")
    assert cache.get("some-policy") == "compiled-bytecode"
    assert cache.get("missing") is None
