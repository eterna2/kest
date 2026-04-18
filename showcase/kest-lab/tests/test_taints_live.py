import pytest
from kest.core import (
    kest_verified,
    configure,
    OPAPolicyEngine,
    MockIdentityProvider,
)
from opentelemetry import baggage
import opentelemetry.context as otel_context
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
import json
import base64
import kest.core.framework.decorators as kest_decorators


@pytest.fixture
def otel_recorder():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    test_tracer = provider.get_tracer("kest.core.test")
    # Store old tracer
    old_tracer = kest_decorators.tracer
    kest_decorators.tracer = test_tracer
    yield exporter
    # Restore
    kest_decorators.tracer = old_tracer


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_taints_and_override(otel_recorder):
    """
    F-TT-01, F-TT-02: Test the compounding/removal of taints and trust score overrides
    using the live OPA Sidecar instance in the kest-lab network.
    F-AE-01: Asserts the generated entry contains mandatory schema fields.
    """
    engine = OPAPolicyEngine(url="http://opa:8181")
    configure(
        engine=engine,
        identity=MockIdentityProvider(
            principal="spiffe://kest.internal/workload/hop2"
        ),
        clear=True,
    )

    ctx = baggage.set_baggage("kest.passport", "[]")
    token = otel_context.attach(ctx)

    try:

        @kest_verified(
            policy="allow", removed_taints=["malicious_input"], trust_override=100
        )
        async def func_sanitizer():
            return "sanitized"

        @kest_verified(
            policy="allow",
            added_taints=["malicious_input", "untrusted_source"],
            trust_evaluator=None,
        )
        async def func_entry():
            return await func_sanitizer()

        # This should execute and hit the live test_policy
        await func_entry()

        spans = otel_recorder.get_finished_spans()
        assert len(spans) == 2

        span1 = next(s for s in spans if s.name == "kest.verified.func_entry")
        span2 = next(s for s in spans if s.name == "kest.verified.func_sanitizer")

        def extract_payload(sig):
            parts = sig.split(".")
            assert len(parts) == 3, "Invalid JWS format"
            p_b64 = parts[1]
            p_b64 += "=" * ((4 - len(p_b64) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(p_b64).decode())

        # Verify taints in signatures
        sig1 = span1.attributes["kest.signature"]
        payload1 = extract_payload(sig1)
        assert set(payload1["added_taints"]) == {"malicious_input", "untrusted_source"}
        assert set(payload1["taints"]) == {
            "malicious_input",
            "untrusted_source",
        }
        assert payload1.get("schema_version") == "0.3.0"
        assert isinstance(payload1.get("policy_context"), dict)

        sig2 = span2.attributes["kest.signature"]
        payload2 = extract_payload(sig2)
        assert set(payload2["removed_taints"]) == {"malicious_input"}
        assert set(payload2["taints"]) == {"untrusted_source"}
        assert span2.attributes["kest.trust_score"] == 100
        assert payload2.get("schema_version") == "0.3.0"
        assert isinstance(payload2.get("policy_context"), dict)

    finally:
        otel_context.detach(token)
