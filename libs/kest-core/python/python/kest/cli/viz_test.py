import base64
import hashlib
import json

from kest.cli.viz import generate_mermaid


def test_generate_mermaid_from_json_spans():
    # Mock spans with attributes
    spans = [
        {
            "attributes": {
                "service.name": "hop1",
                "kest.passport": json.dumps({"entries": ["header.payload.sig1"]}),
                "kest.chain_tip": "0",
            }
        },
        {
            "attributes": {
                "service.name": "hop2",
                "kest.passport": json.dumps(
                    {"entries": ["header.payload.sig1", "header.payload.sig2"]}
                ),
                "kest.chain_tip": hashlib.sha256(b"header.payload.sig1").hexdigest(),
            }
        },
    ]

    mermaid = generate_mermaid(spans)

    assert "graph TD;" in mermaid
    assert "sig1[hop1];" in mermaid
    assert "sig2[hop2];" in mermaid
    # Edge: parent_hash of hop2 points to hop1
    parent_hash = hashlib.sha256(b"header.payload.sig1").hexdigest()
    assert f"{parent_hash} --> sig2" in mermaid


def test_generate_mermaid_from_raw_signatures():
    # Mock raw signature list (lab fallback)
    def make_sig(payload, secret="secret"):
        header = base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').decode().rstrip("=")
        payload_json = json.dumps(payload)
        payload_b64 = (
            base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
        )
        sig = hashlib.sha256((header + "." + payload_b64 + secret).encode()).hexdigest()
        return f"{header}.{payload_b64}.{sig}"

    sig1 = make_sig({"labels": {"principal": "service/hop1"}, "parent_ids": ["0"]})
    h1 = hashlib.sha256(sig1.encode()).hexdigest()

    sig2 = make_sig({"labels": {"principal": "service/hop2"}, "parent_ids": [h1]})
    h2 = hashlib.sha256(sig2.encode()).hexdigest()

    spans = [sig1, sig2]

    mermaid = generate_mermaid(spans)

    assert "graph TD;" in mermaid
    assert f"{h1}[hop1];" in mermaid
    assert f"{h2}[hop2];" in mermaid
    assert f"{h1} --> {h2}" in mermaid
