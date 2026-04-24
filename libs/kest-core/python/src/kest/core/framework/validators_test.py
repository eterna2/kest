import base64
import json
from unittest.mock import patch

import opentelemetry.context as otel_context
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from kest.core import (
    MaxLengthValidator,
    MockIdentityProvider,
    MockPolicyEngine,
    RegexDenyListValidator,
    configure,
    kest_verified,
)
from kest.core.models.passport import BaggageManager


@pytest.fixture
def otel_recorder():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    test_tracer = provider.get_tracer("kest.core.test")

    with patch("kest.core.framework.decorators.tracer", test_tracer):
        yield exporter


@pytest.fixture(autouse=True)
def setup_kest():
    configure(engine=MockPolicyEngine(), identity=MockIdentityProvider(), clear=True)


def test_max_length_validator_pass():
    @kest_verified(
        policy="test", output_validators=[MaxLengthValidator(max_length=10)]
    )
    def my_func():
        return "short"

    assert my_func() == "short"


def test_max_length_validator_fail():
    @kest_verified(
        policy="test", output_validators=[MaxLengthValidator(max_length=5)]
    )
    def my_func():
        return "too long"

    with pytest.raises(ValueError) as excinfo:
        my_func()
    assert "exceeds maximum of 5" in str(excinfo.value)


def test_regex_deny_list_validator_pass():
    @kest_verified(
        policy="test",
        output_validators=[RegexDenyListValidator(patterns=[r"\d{3}-\d{2}-\d{4}"])]
    )
    def my_func():
        return "no ssn here"

    assert my_func() == "no ssn here"


def test_regex_deny_list_validator_fail():
    @kest_verified(
        policy="test",
        output_validators=[RegexDenyListValidator(patterns=[r"\d{3}-\d{2}-\d{4}"])]
    )
    def my_func():
        return "my ssn is 123-45-6789"

    with pytest.raises(ValueError) as excinfo:
        my_func()
    assert "Output matched deny-list pattern" in str(excinfo.value)


def test_validation_failure_adds_taint(otel_recorder):
    @kest_verified(
        policy="test", output_validators=[MaxLengthValidator(max_length=5)]
    )
    def my_func():
        return "too long"

    with pytest.raises(ValueError):
        my_func()

    spans = otel_recorder.get_finished_spans()
    # Expect 2 spans: the primary 'system' entry and the 'sanitizer' failure entry
    assert len(spans) == 2

    failure_span = next(s for s in spans if s.name == "kest.verified.my_func.validation_failed")
    sig = failure_span.attributes["kest.signature"]
    payload = json.loads(
        base64.urlsafe_b64decode(sig.split(".")[1] + "==").decode()
    )

    assert "output_validation_failed" in payload["added_taints"]
    assert "output_validation_failed" in payload["taints"]
    assert payload["classification"] == "sanitizer"


def test_input_hash_in_signature(otel_recorder):
    @kest_verified(policy="test")
    def my_func(arg1, kwarg1=None):
        return "ok"

    my_func("val1", kwarg1="val2")

    spans = otel_recorder.get_finished_spans()
    audit_span = next(s for s in spans if s.name == "kest.verified.my_func")

    sig = audit_span.attributes["kest.signature"]
    payload = json.loads(
        base64.urlsafe_b64decode(sig.split(".")[1] + "==").decode()
    )

    assert payload["input_hash"] != ""

    import hashlib
    expected_input = json.dumps({"args": ["val1"], "kwargs": {"kwarg1": "val2"}}, sort_keys=True)
    expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
    assert payload["input_hash"] == expected_hash
