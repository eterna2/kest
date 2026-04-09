import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric import ed25519

from kest.core.identity.base import IdentityProvider


class OIDCIdentity(IdentityProvider):
    """
    Generic identity provider using an injected OIDC token.
    Can read token from an environment path (like Kubernetes ServiceAccount tokens).
    """

    def __init__(self, issuer: str = "", client_id: str = "", token_path: str = ""):
        self.issuer = issuer
        self.client_id = client_id
        self.token_path = token_path or os.environ.get("KEST_OIDC_TOKEN_PATH", "")
        self.private_key = ed25519.Ed25519PrivateKey.generate()

        if self.token_path and os.path.exists(self.token_path):
            try:
                with open(self.token_path, "r") as f:
                    self._raw_token = f.read().strip()
                # In a real implementation, you might parse the JWT to extract issuer/client_id
                # For now, we continue using injected values or defaults.
            except Exception as e:
                print(f"[Kest.Identity] WARNING: Could not read OIDC token path: {e}")
        else:
            self._raw_token = None

    def get_identity(self) -> str:
        # If we have an issuer and client id, use them
        if self.issuer and self.client_id:
            return f"{self.issuer}/{self.client_id}"
        # If we have a token path and we read it, we might try to mock one out
        if self._raw_token:
            return "oidc://injected-token-workload"

        return "oidc://unknown-workload"

    def sign(self, payload: bytes) -> str:
        header = {"alg": "EdDSA", "typ": "JWS", "kid": self.get_identity()}
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        )
        payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")

        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = self.private_key.sign(signing_input)
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{sig_b64}"
