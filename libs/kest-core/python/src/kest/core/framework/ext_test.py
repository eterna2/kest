import base64
import json
import os

import httpx
import opentelemetry.context as otel_context
import pytest
from opentelemetry import baggage, trace

from kest.core.framework.ext import (
    _LAB_BAGGAGE_STORE,
    _LAB_LOCK,
    KestHttpxInterceptor,
    KestIdentityMiddleware,
    KestMiddleware,
)


@pytest.mark.asyncio
async def test_middleware_basic():
    # Setup a mock ASGI app
    async def mock_app(scope, receive, send):
        # Verify baggage is in OTel context within the app
        all_baggage = baggage.get_all()
        assert all_baggage.get("user_id") == "123"
        return "OK"

    middleware = KestMiddleware(mock_app)

    # Mock ASGI scope
    scope = {
        "type": "http",
        "headers": [(b"baggage", b"user_id=123,org_id=abc"), (b"host", b"localhost")],
    }

    async def receive():
        return {}

    async def send(message):
        pass

    await middleware(scope, receive, send)

    # Verify that the trace_id was used to store baggage in the lab store
    # This is tricky because we don't have a specific span yet.
    # But we can verify it doesn't crash.

    # Test cases for malformed baggage
    malformed_values = [
        (b"valid=yes,invalid", "yes"),  # "invalid" is skipped
        (b"valid=yes,,=empty,key=", "yes"),  # empty parts or missing keys are skipped
        (
            b"valid=yes;prop=val",
            "yes;prop=val",
        ),  # semicolon is NOT a separator in W3C Baggage
    ]

    for val, expected in malformed_values:

        async def mock_app_dynamic(scope, receive, send):
            all_baggage = baggage.get_all()
            assert all_baggage.get("valid") == expected
            return "OK"

        scope = {"type": "http", "headers": [(b"baggage", val)]}
        await KestMiddleware(mock_app_dynamic)(scope, lambda: None, lambda _: None)


@pytest.mark.asyncio
async def test_middleware_no_headers():
    async def mock_app(scope, receive, send):
        return "OK"

    middleware = KestMiddleware(mock_app)
    # Scope missing 'headers'
    scope = {"type": "http"}
    await middleware(scope, None, None)


@pytest.mark.asyncio
async def test_middleware_non_http_scope():
    async def mock_app(scope, receive, send):
        return "NON_HTTP"

    middleware = KestMiddleware(mock_app)
    scope = {"type": "lifespan"}
    result = await middleware(scope, None, None)
    assert result == "NON_HTTP"


@pytest.mark.asyncio
async def test_middleware_exception_handling():
    async def mock_app_err(scope, receive, send):
        raise ValueError("simulated crash")

    middleware = KestMiddleware(mock_app_err)
    scope = {"type": "http", "headers": [(b"baggage", b"k=v")]}

    # Get current context count
    # OTel uses a thread-local stack for context.
    # We want to ensure that if its attached, it's detached.

    with pytest.raises(ValueError, match="simulated crash"):
        await middleware(scope, None, None)

    # If detach failed, context would still have k=v.
    assert baggage.get_baggage("k") is None


def test_interceptor_basic():
    interceptor = KestHttpxInterceptor()
    request = httpx.Request("GET", "https://example.com")

    # 1. Test with OTel baggage
    ctx = baggage.set_baggage("foo", "bar")
    token = otel_context.attach(ctx)
    try:
        modified_request = interceptor(request)
        assert "baggage" in modified_request.headers
        assert "foo=bar" in modified_request.headers["baggage"]
    finally:
        otel_context.detach(token)


def test_interceptor_lab_store_fallback():
    interceptor = KestHttpxInterceptor()
    request = httpx.Request("GET", "https://example.com")

    # 2. Test with lab store lookup via trace_id
    tracer = trace.get_tracer("test")
    with tracer.start_as_current_span("parent") as span:
        trace_id = span.get_span_context().trace_id
        with _LAB_LOCK:
            _LAB_BAGGAGE_STORE[trace_id] = {"lab_key": "lab_val"}

        try:
            modified_request = interceptor(request)
            assert "lab_key=lab_val" in modified_request.headers["baggage"]
        finally:
            with _LAB_LOCK:
                if trace_id in _LAB_BAGGAGE_STORE:
                    del _LAB_BAGGAGE_STORE[trace_id]


def test_interceptor_no_context():
    interceptor = KestHttpxInterceptor()
    request = httpx.Request("GET", "https://example.com")

    # Verify it doesn't crash when no context is active
    modified_request = interceptor(request)
    assert "baggage" not in modified_request.headers


# ---------------------------------------------------------------------------
# Helpers for KestIdentityMiddleware tests
# ---------------------------------------------------------------------------


def _make_jwt(claims: dict) -> str:
    """Produce a structurally valid but *unverified* JWT for unit tests."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    )
    return f"{header}.{payload}.fakesig"


async def _noop_receive():
    return {}


async def _noop_send(msg):
    pass


# ---------------------------------------------------------------------------
# D-01: KestIdentityMiddleware writes spec-compliant baggage keys
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_identity_middleware_writes_spec_keys():
    """
    D-01: A JWT decoded by KestIdentityMiddleware must populate
    kest.user / kest.agent / kest.task — NOT the old principal_user names.
    """
    captured: dict = {}

    async def inner_app(scope, receive, send):
        # KestIdentityMiddleware attaches the OTel context before calling
        # self.app, so baggage is readable here.
        captured.update(baggage.get_all())

    os.environ["KEST_INSECURE_NO_VERIFY"] = "true"
    try:
        mw = KestIdentityMiddleware(app=inner_app, jwks_uri=None)
        token = _make_jwt(
            {
                "preferred_username": "alice",
                "azp": "my-client",
                "scope": "read:data",
            }
        )
        scope = {
            "type": "http",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
        }
        await mw(scope, _noop_receive, _noop_send)
    finally:
        del os.environ["KEST_INSECURE_NO_VERIFY"]

    # Spec-compliant keys must be present
    assert captured.get("kest.user") == "alice", (
        f"Expected kest.user=alice, got {captured}"
    )
    assert captured.get("kest.agent") == "my-client", (
        f"Expected kest.agent=my-client, got {captured}"
    )
    assert captured.get("kest.task") == "read:data", (
        f"Expected kest.task=read:data, got {captured}"
    )

    # Old non-spec keys must NOT be present (regression guard for D-01)
    assert "kest.principal_user" not in captured
    assert "kest.principal_agent" not in captured
    assert "kest.principal_scope" not in captured


# ---------------------------------------------------------------------------
# R-03: JWT verification gate
# ---------------------------------------------------------------------------


def test_identity_middleware_no_jwks_no_env_raises():
    """
    R-03: Constructing KestIdentityMiddleware with jwks_uri=None and without
    KEST_INSECURE_NO_VERIFY=true must raise RuntimeError immediately.
    """
    os.environ.pop("KEST_INSECURE_NO_VERIFY", None)
    with pytest.raises(RuntimeError, match="KEST_INSECURE_NO_VERIFY"):
        KestIdentityMiddleware(app=lambda s, r, sd: None, jwks_uri=None)


def test_identity_middleware_no_jwks_with_env_succeeds():
    """
    R-03: Constructing KestIdentityMiddleware with jwks_uri=None IS allowed
    when KEST_INSECURE_NO_VERIFY=true — the guard must not interfere with
    explicitly acknowledged insecure dev/test mode.
    """
    os.environ["KEST_INSECURE_NO_VERIFY"] = "true"
    try:
        mw = KestIdentityMiddleware(app=lambda s, r, sd: None, jwks_uri=None)
        assert mw._jwks_client is None  # confirmed unverified path
    finally:
        del os.environ["KEST_INSECURE_NO_VERIFY"]
