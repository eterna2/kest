import base64
import json
import os
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from kest.core.identity.base import IdentityProvider

try:
    from spiffe import WorkloadApiClient

    HAS_SPIFFE = True
except ImportError:
    HAS_SPIFFE = False


class SPIREProvider(IdentityProvider):
    """
    Production-grade provider using SPIRE Workload API for X509-SVID signing.

    This provider communicates with the SPIRE agent's Unix Domain Socket
    to fetch identities and certificates. It supports Ed25519, ECDSA, and
    RSA keys for JWS signing.
    """

    def __init__(self, socket_path: Optional[str] = None):
        """
        Initializes the SPIRE provider.

        Args:
            socket_path: Path to the SPIRE agent socket. If None, it uses the
                SPIFFE_ENDPOINT_SOCKET environment variable.

        Raises:
            RuntimeError: If the 'spiffe' package is not installed.
        """
        if not HAS_SPIFFE:
            raise RuntimeError(
                "SPIREProvider requires the `spiffe` package. Install with `pip install kest[spiffe]`"
            )
        self.socket_path = socket_path or os.environ.get("SPIFFE_ENDPOINT_SOCKET")

    def get_identity(self) -> str:
        """
        Fetches the current SPIFFE ID from the SPIRE agent.

        Returns:
            str: The SPIFFE ID (e.g., spiffe://example.org/my-workload).

        Raises:
            PermissionError: If the principal identity cannot be fetched.
        """
        try:
            with WorkloadApiClient(socket_path=self.socket_path) as client:
                svid = client.fetch_x509_svid()
                return str(svid.spiffe_id)
        except Exception as e:
            print(f"[Kest.Identity] Failed to fetch principal from SPIRE: {e}")
            raise PermissionError(f"Principal identity unavailable: {e}")

    def sign(self, payload: bytes) -> str:
        """
        Signs a payload using the private key from the current X509-SVID.

        Includes the public certificate in the JWS 'x5c' header for
        downstream verification.

        Args:
            payload: Binary data to sign.

        Returns:
            str: A complete JWS signature.

        Raises:
            PermissionError: If signing fails.
            ValueError: If the key type is unsupported.
        """
        try:
            with WorkloadApiClient(socket_path=self.socket_path) as client:
                svid = client.fetch_x509_svid()

                # Sign using private key
                private_key = svid.private_key
                # Use type: ignore for spiffe-python X509Svid attributes until stub is available
                leaf_cert = svid.cert_chain[0]  # type: ignore

                header = {
                    "alg": "EdDSA",
                    "typ": "JWS",
                    "x5c": [
                        base64.b64encode(
                            leaf_cert.public_bytes(serialization.Encoding.DER)
                        ).decode()
                    ],
                }

                header_b64 = (
                    base64.urlsafe_b64encode(json.dumps(header).encode())
                    .decode()
                    .rstrip("=")
                )
                payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
                signing_input = f"{header_b64}.{payload_b64}".encode()

                if isinstance(private_key, ed25519.Ed25519PrivateKey):
                    signature = private_key.sign(signing_input)
                elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                    signature = private_key.sign(
                        signing_input, ec.ECDSA(hashes.SHA256())
                    )
                elif isinstance(private_key, rsa.RSAPrivateKey):
                    signature = private_key.sign(
                        signing_input, padding.PKCS1v15(), hashes.SHA256()
                    )
                else:
                    raise ValueError(
                        f"Unsupported key type for JWS signing: {type(private_key)}"
                    )

                sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
                return f"{header_b64}.{payload_b64}.{sig_b64}"
        except Exception as e:
            print(f"[Kest.Identity] SPIRE signing failed: {e}")
            raise PermissionError(f"Identity signing failed: {e}")
