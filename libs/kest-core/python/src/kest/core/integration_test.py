from unittest.mock import patch

import httpx
import opentelemetry.context as otel_context
import pytest
import respx
from opentelemetry import baggage, trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from kest.core import (
    MockIdentityProvider,
    OPAPolicyEngine,
    configure,
    kest_verified,
)


@pytest.fixture
def otel_recorder():
    """
    Sets up an in-memory span exporter to capture audit logs.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    # Create a tracer from our test provider
    test_tracer = provider.get_tracer("kest.core.test")

    # Patch the tracer used in decorators.py
    with patch("kest.core.framework.decorators.tracer", test_tracer):
        yield exporter


@respx.mock
def test_e2e_flow_with_audit_logs(otel_recorder):
    # 2. Setup REAL engine (but mocked via respx) and identity
    engine = OPAPolicyEngine(url="http://opa:8181")
    configure(engine=engine, identity=MockIdentityProvider(), clear=True)

    # Mock OPA response
    respx.post("http://opa:8181/v1/data/kest/test_policy").mock(
        return_value=httpx.Response(200, json={"result": {"allow": True}})
    )

    # 3. Set baggage context
    ctx = baggage.set_baggage("kest.passport", "[]")  # Valid JSON list for Passport
    token = otel_context.attach(ctx)

    try:
        # 4. Define decorated function
        @kest_verified(policy="test_policy")
        def my_function(val: str):
            return f"success-{val}"

        # 5. Execute
        result = my_function("data")
        assert result == "success-data"

        # 6. Verify OTel Audit Logs
        spans = otel_recorder.get_finished_spans()
        assert len(spans) > 0

        # Find our audit span
        audit_span = next(
            (s for s in spans if s.name == "kest.verified.my_function"), None
        )
        assert audit_span is not None, "Audit span not found"

        # Check attributes
        attrs = audit_span.attributes
        assert attrs["kest.policy_ids"] == "test_policy"
        assert attrs["kest.allowed"] is True

    finally:
        otel_context.detach(token)


@respx.mock
def test_e2e_flow_denied(otel_recorder):
    engine = OPAPolicyEngine(url="http://opa:8181")
    configure(engine=engine, identity=MockIdentityProvider(), clear=True)

    # Mock OPA DENY response
    respx.post("http://opa:8181/v1/data/kest/restricted").mock(
        return_value=httpx.Response(200, json={"result": {"allow": False}})
    )

    @kest_verified(policy="restricted")
    def restricted_function():
        return "should not run"

    with pytest.raises(PermissionError) as excinfo:
        restricted_function()

    assert "denied execution" in str(excinfo.value)

    # Verify audit log shows failure
    spans = otel_recorder.get_finished_spans()
    audit_span = next(
        (s for s in spans if s.name == "kest.verified.restricted_function"), None
    )
    assert audit_span is not None
    assert audit_span.attributes["kest.allowed"] is False
    assert audit_span.status.status_code == trace.StatusCode.ERROR


@respx.mock
def test_e2e_taint_and_override(otel_recorder):
    engine = OPAPolicyEngine(url="http://opa:8181")
    configure(engine=engine, identity=MockIdentityProvider(), clear=True)

    respx.post("http://opa:8181/v1/data/kest/step1").mock(
        return_value=httpx.Response(200, json={"result": {"allow": True}})
    )
    respx.post("http://opa:8181/v1/data/kest/step2").mock(
        return_value=httpx.Response(200, json={"result": {"allow": True}})
    )

    ctx = baggage.set_baggage("kest.passport", "[]")
    token = otel_context.attach(ctx)

    try:

        @kest_verified(policy="step2", removed_taints=["taint_a"], trust_override=100)
        def func_step_2():
            return "step2"

        @kest_verified(
            policy="step1", added_taints=["taint_a", "taint_b"], trust_evaluator=None
        )
        def func_step_1():
            return func_step_2()

        func_step_1()

        spans = otel_recorder.get_finished_spans()
        assert len(spans) == 2

        span1 = next(s for s in spans if s.name == "kest.verified.func_step_1")
        span2 = next(s for s in spans if s.name == "kest.verified.func_step_2")

        # Check trust scores
        assert span2.attributes["kest.trust_score"] == 100

        import base64
        import json

        # Verify taints in signatures
        sig1 = span1.attributes["kest.signature"]
        payload1 = json.loads(
            base64.urlsafe_b64decode(sig1.split(".")[1] + "==").decode()
        )
        assert set(payload1["added_taints"]) == {"taint_a", "taint_b"}
        assert set(payload1["taints"]) == {"taint_a", "taint_b"}

        sig2 = span2.attributes["kest.signature"]
        payload2 = json.loads(
            base64.urlsafe_b64decode(sig2.split(".")[1] + "==").decode()
        )
        # removed_taints is applied during calculation but not present as a top-level
        # field in the Rust-signed payload; instead verify the resolved taints list.
        assert set(payload2["taints"]) == {"taint_b"}

    finally:
        otel_context.detach(token)
