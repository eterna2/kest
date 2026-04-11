import base64
import json
import json as stdlib_json

import pytest

from kest.core._core_py import KestEntry, sign_entry, version


class MockProvider:
    def sign_payload(self, payload: bytes) -> str:
        # Mock signature
        return "mock_signature_b64"

    def verify_svid(self, svid: str) -> str:
        return "mock_subject"


def test_kest_entry_defaults():
    entry = KestEntry(
        entry_id="demo-1", operation="test_op", classification="system", trust_score=100
    )
    assert entry.entry_id == "demo-1"
    assert entry.operation == "test_op"
    assert entry.trust_score == 100
    assert entry.added_taints == []
    assert entry.removed_taints == []
    assert entry.taints == []
    assert entry.content_hash == ""
    assert entry.input_hash == ""
    assert entry.environment == {}
    assert entry.metadata is None

    # check policy context
    assert isinstance(entry.policy_context, dict)
    assert "enterprise_policies" in entry.policy_context


def test_kest_entry_invalid_classification():
    with pytest.raises(ValueError):
        KestEntry(
            entry_id="demo-1",
            operation="test",
            classification="unknown_type",
            trust_score=100,
        )


def test_sign_entry_jws_format():
    entry = KestEntry(
        entry_id="demo-1", operation="test", classification="system", trust_score=100
    )
    provider = MockProvider()
    jws = sign_entry(entry, provider)
    parts = jws.split(".")
    assert len(parts) == 3

    header_b64, payload_b64, sig_b64 = parts

    header = json.loads(base64.urlsafe_b64decode(header_b64 + "==").decode())
    assert header == {"alg": "EdDSA", "typ": "JWS"}

    # Payload must be parseable
    payload_bytes = base64.urlsafe_b64decode(payload_b64 + "==")
    payload = json.loads(payload_bytes.decode())
    assert payload["entry_id"] == "demo-1"

    assert sig_b64 == "mock_signature_b64"


def test_version():
    v = version()
    assert isinstance(v, str)
    assert len(v) > 0
