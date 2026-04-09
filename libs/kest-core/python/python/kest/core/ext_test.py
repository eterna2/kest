import httpx
import opentelemetry.context as otel_context
import pytest
from opentelemetry import baggage, trace

from kest.core.ext import (
    _LAB_BAGGAGE_STORE,
    _LAB_LOCK,
    KestHttpxInterceptor,
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
