import base64
import json

from kest.core.identity.providers.local import MockIdentityProvider, StaticIdentity


def test_static_identity():
    provider = StaticIdentity(principal="host-1234")
    assert provider.get_identity() == "host-1234"

    payload = b"test payload"
    sig = provider.sign(payload)
    parts = sig.split(".")
    header = json.loads(
        base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4)).decode()
    )
    assert header["kid"] == "host-1234"


def test_mock_identity_provider():
    provider = MockIdentityProvider(principal="spiffe://test")
    assert provider.get_identity() == "spiffe://test"

    sig = provider.sign(b"hello")
    # sign() now returns a full JWS (header.payload.signature)
    parts = sig.split(".")
    assert len(parts) == 3, "sign() must return a full JWS"
    
    header = json.loads(
        base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4)).decode()
    )
    assert header["kid"] == "spiffe://test"
    
    decoded_sig = base64.urlsafe_b64decode(parts[2] + "=" * (4 - len(parts[2]) % 4))
    assert len(decoded_sig) == 32, "Mock signature must be 32 bytes (SHA-256 output)"
