import opentelemetry.context as otel_context
from opentelemetry import baggage

from kest.core.framework.context import (
    get_current_agent,
    get_current_jwt,
    get_current_passport,
    get_current_task,
    get_current_user,
)

# --- get_current_user ---


def test_get_current_user_returns_value_when_set():
    ctx = baggage.set_baggage("kest.user", "alice@example.com")
    token = otel_context.attach(ctx)
    try:
        assert get_current_user() == "alice@example.com"
    finally:
        otel_context.detach(token)


def test_get_current_user_returns_none_when_absent():
    ctx = otel_context.get_current()
    token = otel_context.attach(ctx)
    try:
        assert get_current_user() is None
    finally:
        otel_context.detach(token)


# --- get_current_agent ---


def test_get_current_agent_returns_value_when_set():
    ctx = baggage.set_baggage("kest.agent", "my-agent-client")
    token = otel_context.attach(ctx)
    try:
        assert get_current_agent() == "my-agent-client"
    finally:
        otel_context.detach(token)


def test_get_current_agent_returns_none_when_absent():
    ctx = otel_context.get_current()
    token = otel_context.attach(ctx)
    try:
        assert get_current_agent() is None
    finally:
        otel_context.detach(token)


# --- get_current_task ---


def test_get_current_task_returns_value_when_set():
    ctx = baggage.set_baggage("kest.task", "process-data read-reports")
    token = otel_context.attach(ctx)
    try:
        assert get_current_task() == "process-data read-reports"
    finally:
        otel_context.detach(token)


def test_get_current_task_returns_none_when_absent():
    ctx = otel_context.get_current()
    token = otel_context.attach(ctx)
    try:
        assert get_current_task() is None
    finally:
        otel_context.detach(token)


# --- get_current_jwt ---


def test_get_current_jwt_returns_value_when_set():
    ctx = baggage.set_baggage("kest.jwt", "eyJhbGciOiJSUzI1NiJ9.test.sig")
    token = otel_context.attach(ctx)
    try:
        assert get_current_jwt() == "eyJhbGciOiJSUzI1NiJ9.test.sig"
    finally:
        otel_context.detach(token)


def test_get_current_jwt_returns_none_when_absent():
    ctx = otel_context.get_current()
    token = otel_context.attach(ctx)
    try:
        assert get_current_jwt() is None
    finally:
        otel_context.detach(token)


# --- get_current_passport ---


def test_get_current_passport_returns_value_when_set():
    ctx = baggage.set_baggage("kest.passport", '["header.payload.sig"]')
    token = otel_context.attach(ctx)
    try:
        assert get_current_passport() == '["header.payload.sig"]'
    finally:
        otel_context.detach(token)


def test_get_current_passport_returns_none_when_absent():
    ctx = otel_context.get_current()
    token = otel_context.attach(ctx)
    try:
        assert get_current_passport() is None
    finally:
        otel_context.detach(token)
