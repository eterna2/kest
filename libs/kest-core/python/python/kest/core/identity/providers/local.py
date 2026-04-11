import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ed25519

from kest.core.identity.base import IdentityProvider


class StaticIdentity(IdentityProvider):
    """
    Basic fallback provider for local testing or less modern infrastructure.

    Uses a static principal ID (like a hostname) and generates a fresh
    Ed25519 keypair for in-memory signing.
    """

    def __init__(self, principal: str):
        """
        Initializes the static identity provider.

        Args:
            principal: The identifier to use for this principal.
        """
        self.principal = principal
        self.private_key = ed25519.Ed25519PrivateKey.generate()

    def get_identity(self) -> str:
        """Returns the static principal ID."""
        return self.principal

    def sign(self, payload: bytes) -> str:
        """
        Signs the payload using the generated Ed25519 private key.

        Args:
            payload: The binary payload to sign.

        Returns:
            str: A valid JWS string with 'EdDSA' algorithm.
        """
        header = {"alg": "EdDSA", "typ": "JWS", "kid": self.principal}
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        )
        payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")

        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = self.private_key.sign(signing_input)
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{sig_b64}"


class LocalEd25519Provider(StaticIdentity):
    """
    Legacy alias for StaticIdentity.

    Maintains backwards compatibility with existing test suites and demos.
    """

    def __init__(self, principal: str = "spiffe://kest.internal/local-workload"):
        """Initializes with a default SPIFFE-formatted ID."""
        super().__init__(principal)


class RustEd25519Provider(IdentityProvider):
    """
    GIL-free Ed25519 provider for production Rust backend use.

    Wraps a Rust-native identity provider for high-performance signing.
    """

    def __init__(
        self,
        private_key_bytes: bytes,
        principal: str = "spiffe://kest.internal/local-workload",
    ):
        """
        Initializes the Rust-native Ed25519 provider.

        Args:
            private_key_bytes: 32-byte Ed25519 private key.
            principal: The principal ID for this provider.
        """
        from kest.core._core import RustNativeIdentityProvider as _RustNativeProvider

        self.principal = principal
        self._inner = _RustNativeProvider(private_key_bytes)

    def get_identity(self) -> str:
        """Returns the principal ID."""
        return self.principal

    def sign(self, payload: bytes) -> str:
        """
        Signs the payload using the Rust-native provider.

        Note: When using the Rust backend, this method is bypassed by sign_entry
        for a GIL-free path. This implementation remains for compatibility with
        the Python backend or direct calls.
        """
        header = {"alg": "EdDSA", "typ": "JWS", "kid": self.principal}
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        )
        payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}"

        # Use the inner Rust provider to sign
        sig_b64 = self._inner.sign_payload(signing_input.encode())

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def attest(self, entry_id: str) -> str:
        """Satisfies IdentityProvider protocol for policy evaluation."""
        return entry_id

    def sign_payload(self, payload: bytes) -> str:
        """
        Aliased bridge method for signing payloads.
        In RustEd25519Provider, this directly calls the native Rust signer.
        """
        return self._inner.sign_payload(payload)


class MockIdentityProvider(IdentityProvider):
    """
    Dummy provider for unit testing without cryptographic overhead.

    Generates a deterministic 'mock' signature string that is NOT secure.
    """

    def __init__(self, principal: str = "spiffe://kest.internal/mock-workload"):
        """Initializes the mock provider with an ID."""
        self.principal = principal

    def get_identity(self) -> str:
        """Returns the mock principal ID."""
        return self.principal

    def sign(self, payload: bytes) -> str:
        """
        Returns only the signature portion of a mock JWS.

        The Rust bridge (sign_kest_entry) constructs the full JWS as:
          header_b64 . payload_b64 . <return-value-of-sign>
        So this method MUST return only the signature segment — a structurally
        valid base64url string — NOT a full JWS itself.

        Args:
            payload: The binary payload to 'sign' (the signing input bytes
                     passed by the Rust bridge: header_b64.payload_b64).

        Returns:
            str: A base64url-encoded mock signature (no dots).
        """
        # Produce a deterministic, structurally valid base64url signature part.
        # Using HMAC-SHA256 of the payload gives a constant-length 44-char output.
        raw = hashlib.sha256(b"mock-key" + payload).digest()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
