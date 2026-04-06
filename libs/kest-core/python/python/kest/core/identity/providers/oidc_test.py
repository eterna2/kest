import base64
import json
import tempfile
import os

from kest.core.identity.providers.oidc import OIDCIdentity


def test_oidc_identity():
    provider = OIDCIdentity(issuer="https://auth.example.com", client_id="client-xyz")
    assert provider.get_identity() == "https://auth.example.com/client-xyz"

    payload = b"test payload"
    sig = provider.sign(payload)
    parts = sig.split(".")
    header = json.loads(
        base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4)).decode()
    )
    assert header["kid"] == "https://auth.example.com/client-xyz"


def test_oidc_identity_with_token_path():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"mock.jwt.token")
        temp_path = f.name

    try:
        provider = OIDCIdentity(token_path=temp_path)
        assert provider.get_identity() == "oidc://injected-token-workload"
    finally:
        os.unlink(temp_path)
