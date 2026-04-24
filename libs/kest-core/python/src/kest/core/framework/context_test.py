import opentelemetry.context as otel_context
from opentelemetry import baggage

from kest.core.framework.context import (
    get_current_agent,
    get_current_jwt,
    get_current_passport,
    get_current_task,
    get_current_user,
)


def test_get_current_user():
    ctx = baggage.set_baggage("kest.user", "alice")
    token = otel_context.attach(ctx)
    try:
        assert get_current_user() == "alice"
    finally:
        otel_context.detach(token)


def test_get_current_agent():
    ctx = baggage.set_baggage("kest.agent", "bot-123")
    token = otel_context.attach(ctx)
    try:
        assert get_current_agent() == "bot-123"
    finally:
        otel_context.detach(token)


def test_get_current_task():
    ctx = baggage.set_baggage("kest.task", "process-data")
    token = otel_context.attach(ctx)
    try:
        assert get_current_task() == "process-data"
    finally:
        otel_context.detach(token)


def test_get_current_passport():
    ctx = baggage.set_baggage("kest.passport", "test-passport")
    token = otel_context.attach(ctx)
    try:
        assert get_current_passport() == "test-passport"
    finally:
        otel_context.detach(token)


def test_get_current_jwt():
    ctx = baggage.set_baggage("kest.jwt", "test-jwt")
    token = otel_context.attach(ctx)
    try:
        assert get_current_jwt() == "test-jwt"
    finally:
        otel_context.detach(token)


def test_accessors_return_none_when_missing():
    # Ensure a clean context
    token = otel_context.attach(otel_context.get_current())
    try:
        assert get_current_user() is None
        assert get_current_agent() is None
        assert get_current_task() is None
        assert get_current_passport() is None
        assert get_current_jwt() is None
    finally:
        otel_context.detach(token)
