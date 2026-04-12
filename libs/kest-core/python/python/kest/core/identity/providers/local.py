import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ed25519

from kest.core._core import RustNativeIdentityProvider
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
            base64.urlsafe_b64encode(
                json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
            )
            .decode()
            .rstrip("=")
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


class RustEd25519Provider(RustNativeIdentityProvider, IdentityProvider):
    """
    GIL-free Ed25519 provider for production Rust backend use.

    Inherits from ``RustNativeIdentityProvider`` (a PyO3 native class) which
    holds the ``ed25519-dalek`` ``SigningKey`` in Rust. When used with the Rust
    backend, ``sign_entry`` detects this type via ``downcast::<RustNativeIdentityProvider>``
    and performs the entire canonicalization + signing inside a single
    ``py.allow_threads`` block — eliminating GIL re-acquisition.

    When used with the Python backend, ``sign()`` is called directly and delegates
    to the Rust ``sign_payload`` for the actual Ed25519 operation.
    """

    def __new__(
        cls,
        private_key_bytes: bytes,
        principal: str = "spiffe://kest.internal/local-workload",
    ):
        """
        Allocates and initializes the underlying PyO3 Rust struct.

        PyO3's ``#[new]`` maps to Python ``__new__``, not ``__init__``.
        We must override ``__new__`` here to forward the arguments to the
        Rust constructor, which allocates the ``SigningKey`` in Rust memory.
        """
        return RustNativeIdentityProvider.__new__(cls, private_key_bytes, principal)

    def __init__(
        self,
        private_key_bytes: bytes,
        principal: str = "spiffe://kest.internal/local-workload",
    ):
        """
        No-op — initialization is fully handled by ``__new__`` above.

        The Rust ``#[new]`` fn constructs the struct during ``__new__``.
        ``super().__init__()`` would route to ``object.__init__()`` via MRO
        (because PyO3's ``__init__`` is ``object.__init__``), so we skip it.
        """
        pass  # Rust struct initialized in __new__

    def get_identity(self) -> str:
        """Returns the principal ID (exposed via #[pyo3(get)] on the Rust struct)."""
        return self.principal

    def sign(self, payload: bytes) -> str:
        """
        Signs a raw payload and returns a complete JWS string.

        This is the Python-backend-compatible path. The Rust backend bypasses
        this method entirely via the GIL-free ``sign_entry`` path.

        Args:
            payload: The raw bytes to sign (the canonicalized entry data).

        Returns:
            str: A complete JWS compact serialization (header.payload.sig).
        """
        header = {"alg": "EdDSA", "kid": self.principal, "typ": "JWS"}
        header_b64 = (
            base64.urlsafe_b64encode(
                json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
            )
            .decode()
            .rstrip("=")
        )
        payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}"

        # sign_payload is implemented in Rust (RustNativeIdentityProvider.sign_payload)
        # and returns the base64url-encoded raw Ed25519 signature.
        sig_b64 = self.sign_payload(signing_input.encode())

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def attest(self, entry_id: str) -> str:
        """Satisfies IdentityProvider protocol for policy evaluation (non-signing use)."""
        return entry_id


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
        Returns a mock JWS for testing.

        Args:
            payload: The binary payload to 'sign'

        Returns:
            str: A structurally valid JWS (header.payload.sig).
        """
        header = {"alg": "mock", "kid": self.principal, "typ": "JWS"}
        header_b64 = (
            base64.urlsafe_b64encode(
                json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
            )
            .decode()
            .rstrip("=")
        )
        payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        
        # Produce a deterministic, structurally valid base64url signature part.
        raw = hashlib.sha256(b"mock-key" + signing_input).digest()
        sig_b64 = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{sig_b64}"
