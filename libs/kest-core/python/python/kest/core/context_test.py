from opentelemetry import baggage
from kest.core.context import get_current_passport, get_current_jwt


def test_get_current_passport():
    ctx = baggage.set_baggage("kest.passport", "test-passport")
    # Note: set_baggage returns a new context, but for testing if it's set in the active baggage
    # we might need to attach it if we were using the full SDK, but here we just want to see
    # if our functions call the right thing.

    # In a real scenario, we'd use baggage.set_baggage and then ensure it's in the current context.
    # However, baggage.get_baggage(key, context=None) uses the current context.

    import opentelemetry.context as otel_context

    token = otel_context.attach(ctx)
    try:
        assert get_current_passport() == "test-passport"
    finally:
        otel_context.detach(token)


def test_get_current_jwt():
    ctx = baggage.set_baggage("kest.jwt", "test-jwt")
    import opentelemetry.context as otel_context

    token = otel_context.attach(ctx)
    try:
        assert get_current_jwt() == "test-jwt"
    finally:
        otel_context.detach(token)
