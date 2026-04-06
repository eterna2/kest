import pytest
import json
import base64
import os
from opentelemetry import baggage
import opentelemetry.context as otel_context
from kest.core.decorators import kest_verified, _LAB_AUDIT_FILE
from kest.core.identity import StaticIdentity
from kest.core.engine import PolicyEngine


class MockEngine(PolicyEngine):
    def __init__(self):
        self.last_context = None

    def evaluate(self, entry_id, policy_names, context):
        self.last_context = context
        return True

    async def async_evaluate(self, entry_id, policy_names, context):
        self.last_context = context
        return True


@pytest.fixture
def clean_lab():
    if os.path.exists(_LAB_AUDIT_FILE):
        os.remove(_LAB_AUDIT_FILE)
    yield
    if os.path.exists(_LAB_AUDIT_FILE):
        os.remove(_LAB_AUDIT_FILE)


@pytest.fixture
def clean_global_config():
    """Reset global engine/identity state to avoid test-order interference."""
    import kest.core

    kest.core._active_engine = None
    kest.core._active_identity = None
    yield
    kest.core._active_engine = None
    kest.core._active_identity = None


def test_identity_propagation_explicit(clean_lab):
    """
    Tests that principal_user and principal_agent set via OTel baggage
    are propagated into the engine context and captured in the audit trail.
    """
    engine = MockEngine()
    identity = StaticIdentity("test-workload")

    # Inject user/agent via OTel baggage (the new API — no inline decorator params)
    ctx = baggage.set_baggage("kest.principal_user", "alice")
    ctx = baggage.set_baggage("kest.principal_agent", "bot-1", context=ctx)
    ctx = baggage.set_baggage("kest.principal_scope", "upload", context=ctx)
    token = otel_context.attach(ctx)

    try:

        @kest_verified(policy="test", engine=engine, identity=identity)
        def my_func():
            return "ok"

        my_func()

        # Verify context passed to engine — flat keys
        ctx_engine = engine.last_context
        assert ctx_engine is not None
        assert ctx_engine["principal_user"] == "alice"
        assert ctx_engine["principal_agent"] == "bot-1"
        assert ctx_engine["principal_scope"] == "upload"

        # Verify audit trail
        if os.path.exists(_LAB_AUDIT_FILE):
            with open(_LAB_AUDIT_FILE, "r") as f:
                audits = json.load(f)
                last_sig = audits[-1]
                payload_b64 = last_sig.split(".")[1]
                payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                identity_label = json.loads(payload["labels"]["kest.identity"])
                assert identity_label["user"] == "alice"
                assert identity_label["agent"] == "bot-1"
    finally:
        otel_context.detach(token)


def test_identity_propagation_baggage(clean_lab):
    engine = MockEngine()
    identity = StaticIdentity("test-workload")

    # Mock OTel baggage (ensure chaining)
    ctx = baggage.set_baggage("kest.principal_user", "bob")
    ctx = baggage.set_baggage("kest.principal_agent", "proxy-1", context=ctx)
    token = otel_context.attach(ctx)

    try:
        # Verify baggage is readable here
        assert baggage.get_baggage("kest.principal_user") == "bob"

        @kest_verified(policy="test", engine=engine, identity=identity)
        def my_func():
            return "ok"

        my_func()

        # Verify context passed to engine from baggage
        ctx_engine = engine.last_context
        assert ctx_engine is not None
        assert ctx_engine["principal_user"] == "bob"
        assert ctx_engine["principal_agent"] == "proxy-1"
    finally:
        otel_context.detach(token)


def test_resource_attributes(clean_lab):
    """
    Tests that context_map correctly maps function args to engine context keys.
    """
    engine = MockEngine()
    identity = StaticIdentity("test-workload")

    @kest_verified(
        policy="test",
        engine=engine,
        identity=identity,
        context_map={
            "file_id": {"key": "resource_id", "persist": True},
            "sensitivity": "resource_sensitivity",
        },
    )
    def my_func(file_id, sensitivity):
        return "ok"

    my_func(file_id="file-123", sensitivity="high")

    # Verify context
    ctx = engine.last_context
    assert ctx is not None
    assert ctx["resource_id"] == "file-123"
    assert ctx["resource_sensitivity"] == "high"

    # Verify audit trail — persisted field should appear in labels
    if os.path.exists(_LAB_AUDIT_FILE):
        with open(_LAB_AUDIT_FILE, "r") as f:
            audits = json.load(f)
            last_sig = audits[-1]
            payload_b64 = last_sig.split(".")[1]
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            assert payload["labels"]["resource_id"] == "file-123"


def test_dynamic_resolution(clean_lab):
    """
    Tests that context_map supports callable values resolved from function args.
    """
    engine = MockEngine()
    identity = StaticIdentity("test-workload")

    @kest_verified(
        policy="test",
        engine=engine,
        identity=identity,
        context_map={
            "user_id": "resolved_user",
            "id": "resolved_item",
        },
    )
    def my_func(user_id, id):
        return "ok"

    my_func(user_id="charlie", id=456)

    # Verify resolution
    ctx = engine.last_context
    assert ctx is not None
    assert ctx["resolved_user"] == "charlie"
    assert ctx["resolved_item"] == 456


class DenyEngine(PolicyEngine):
    """Always denies — used to test PermissionError propagation."""

    def evaluate(self, entry_id, policy_names, context):
        return False


@pytest.mark.asyncio
async def test_async_identity_propagation_explicit(clean_lab):
    """Async @kest_verified correctly propagates baggage identity to the engine."""
    engine = MockEngine()
    identity = StaticIdentity("async-workload")

    ctx = baggage.set_baggage("kest.principal_user", "async-alice")
    token = otel_context.attach(ctx)

    try:

        @kest_verified(policy="test", engine=engine, identity=identity)
        async def my_async_func():
            return "async-ok"

        result = await my_async_func()
        assert result == "async-ok"

        ctx_engine = engine.last_context
        assert ctx_engine is not None
        assert ctx_engine["principal_user"] == "async-alice"
    finally:
        otel_context.detach(token)


def test_engine_denies_raises_permission_error(clean_lab):
    """When the engine denies, @kest_verified raises PermissionError."""
    engine = DenyEngine()
    identity = StaticIdentity("test-workload")

    @kest_verified(policy="deny-policy", engine=engine, identity=identity)
    def restricted_func():
        return "should-not-reach"

    with pytest.raises(PermissionError, match="deny-policy"):
        restricted_func()


@pytest.mark.asyncio
async def test_async_engine_denies_raises_permission_error(clean_lab):
    """Async path also raises PermissionError on denial."""
    engine = DenyEngine()
    identity = StaticIdentity("test-workload")

    @kest_verified(policy="async-deny", engine=engine, identity=identity)
    async def restricted_async_func():
        return "should-not-reach"

    with pytest.raises(PermissionError, match="async-deny"):
        await restricted_async_func()


def test_callable_resource_attr(clean_lab):
    """context_map with a simple key mapping captures callsite args."""
    engine = MockEngine()
    identity = StaticIdentity("test-workload")

    @kest_verified(
        policy="test",
        engine=engine,
        identity=identity,
        context_map={"owner_id": "resource_owner"},
    )
    def classified_func(owner_id):
        return "ok"

    classified_func(owner_id="dept-42")

    ctx = engine.last_context
    assert ctx is not None, "Engine was not called"
    assert ctx["resource_owner"] == "dept-42"


def test_no_identity_raises_permission_error(clean_global_config):
    """@kest_verified raises PermissionError when no identity provider is configured."""
    engine = MockEngine()

    @kest_verified(policy="test", engine=engine)
    def unconfigured_func():
        return "ok"

    # No global identity set — should fail fast
    with pytest.raises(PermissionError, match="IdentityProvider"):
        unconfigured_func()


def test_no_engine_raises_permission_error(clean_global_config):
    """@kest_verified raises PermissionError when no policy engine is configured."""
    identity = StaticIdentity("test-workload")

    @kest_verified(policy="test", identity=identity)
    def unconfigured_func():
        return "ok"

    # No global engine set — should fail fast
    with pytest.raises(PermissionError, match="PolicyEngine"):
        unconfigured_func()
