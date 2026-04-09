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
    # sign() now returns ONLY the base64url signature portion (no dots),
    # since the Rust bridge appends it as: header.payload.<return-value>.
    # Verify it decodes to 32 bytes (SHA-256 HMAC) and contains no dots.
    assert "." not in sig, "sign() must return only the signature segment (no dots)"
    decoded = base64.urlsafe_b64decode(sig + "=" * (4 - len(sig) % 4))
    assert len(decoded) == 32, "Mock signature must be 32 bytes (SHA-256 output)"
