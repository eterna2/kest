import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest
from opentelemetry import trace

import kest.core
from kest.core.engines.engine import PolicyEngine
from kest.core.framework.decorators import kest_verified
from kest.core.identity import IdentityProvider

# Mock Tracer to avoid OTel overhead in tests
tracer = trace.get_tracer(__name__)

class MockEngine(PolicyEngine):
    def __init__(self):
        self.last_context = None
        self.evaluate_result = True

    def evaluate(self, entry_id, policy_names, context):
        self.last_context = context
        return self.evaluate_result

class MockIdentity(IdentityProvider):
    def get_identity(self):
        return "test-principal"
    def sign(self, payload):
        return "header.payload.signature"

@pytest.fixture(autouse=True)
def mock_kest_globals():
    engine = MockEngine()
    identity = MockIdentity()
    kest.core.configure(engine=engine, identity=identity)
    kest.core.invalidate_policy_cache()
    yield engine, identity
    kest.core.configure(clear=True)
    kest.core.invalidate_policy_cache()

def test_static_resource_id_and_attr(mock_kest_globals):
    engine, identity = mock_kest_globals

    @kest_verified(
        policy="test-policy",
        resource_id="static-res-1",
        resource_attr={"type": "document", "owner": "alice"}
    )
    def my_function():
        return "ok"

    with patch("kest.core.framework.decorators.sign_entry", wraps=kest.core.sign_entry) as mock_sign:
        my_function()

        # Verify context passed to engine
        assert engine.last_context["object"]["id"] == "static-res-1"
        assert engine.last_context["object"]["attributes"] == {"type": "document", "owner": "alice"}

        # Verify labels in signed entry
        assert mock_sign.called
        args, _ = mock_sign.call_args
        entry = args[0]
        assert entry.labels["kest.resource_id"] == "static-res-1"
        assert entry.labels["kest.resource_attr"] == json.dumps({"type": "document", "owner": "alice"})

def test_resolver_resource_id_and_attr(mock_kest_globals):
    engine, identity = mock_kest_globals

    def res_id_resolver(args):
        return f"res-{args['doc_id']}"

    def res_attr_resolver(args):
        return {"category": args["cat"], "priority": args["pri"]}

    @kest_verified(
        policy="test-policy",
        resource_id=res_id_resolver,
        resource_attr=res_attr_resolver
    )
    def my_function(doc_id, cat, pri=1):
        return "ok"

    with patch("kest.core.framework.decorators.sign_entry", wraps=kest.core.sign_entry) as mock_sign:
        my_function("123", "legal", pri=5)

        assert engine.last_context["object"]["id"] == "res-123"
        assert engine.last_context["object"]["attributes"] == {"category": "legal", "priority": 5}

        args, _ = mock_sign.call_args
        entry = args[0]
        assert entry.labels["kest.resource_id"] == "res-123"
        assert entry.labels["kest.resource_attr"] == json.dumps({"category": "legal", "priority": 5})

@pytest.mark.asyncio
async def test_async_resource_id_and_attr(mock_kest_globals):
    engine, identity = mock_kest_globals

    @kest_verified(
        policy="test-policy",
        resource_id=lambda args: f"async-{args['id']}",
        resource_attr={"mode": "async"}
    )
    async def my_async_function(id):
        await asyncio.sleep(0)
        return "async-ok"

    with patch("kest.core.framework.decorators.sign_entry", wraps=kest.core.sign_entry) as mock_sign:
        result = await my_async_function("999")
        assert result == "async-ok"

        assert engine.last_context["object"]["id"] == "async-999"
        assert engine.last_context["object"]["attributes"] == {"mode": "async"}

        args, _ = mock_sign.call_args
        entry = args[0]
        assert entry.labels["kest.resource_id"] == "async-999"
        assert entry.labels["kest.resource_attr"] == json.dumps({"mode": "async"})

def test_no_resource_provided(mock_kest_globals):
    engine, identity = mock_kest_globals

    @kest_verified(policy="test-policy")
    def my_function():
        return "ok"

    with patch("kest.core.framework.decorators.sign_entry", wraps=kest.core.sign_entry) as mock_sign:
        my_function()

        assert engine.last_context["object"]["id"] == ""
        assert engine.last_context["object"]["attributes"] == {}

        args, _ = mock_sign.call_args
        entry = args[0]
        assert "kest.resource_attr" not in entry.labels
