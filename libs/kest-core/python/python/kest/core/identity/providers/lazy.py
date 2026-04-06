import hashlib
import base64
import concurrent.futures

from kest.core.identity.base import IdentityProvider


class LazySigningProvider(IdentityProvider):
    """
    Wraps another provider to perform signing in a background thread.
    Useful for high-throughput nodes that can defer the latency of cryptographic signatures.
    """

    def __init__(self, provider: IdentityProvider):
        self.provider = provider
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

    def get_identity(self) -> str:
        return self.provider.get_identity()

    def sign(self, payload: bytes) -> str:
        # For Phase 2, we return a valid JWS-like string but mark it as pending.
        pending_hash = hashlib.sha256(payload).hexdigest()[:8]
        header = (
            base64.urlsafe_b64encode(b'{"alg":"EdDSA","typ":"JWS"}')
            .decode()
            .rstrip("=")
        )
        payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        jws = f"{header}.{payload_b64}.pending.{pending_hash}"
        self.executor.submit(self.provider.sign, payload)
        return jws
