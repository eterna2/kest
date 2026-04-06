import base64
import json
from typing import Optional, Any

from kest.core.identity.base import IdentityProvider

try:
    import boto3

    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


class AWSWorkloadIdentity(IdentityProvider):
    """
    Uses AWS STS to identify the workload's role and AWS KMS for signing.

    This provider is designed for workloads running on AWS (e.g., EKS,
    Lambda). It fetches the current IAM caller identity from STS and
    uses a configured KMS key for cryptographic signing of audit entries.
    """

    def __init__(
        self,
        kms_key_id: str,
        region_name: Optional[str] = None,
        role_arn: Optional[str] = None,
        signing_algorithm: str = "ECDSA_SHA_256",
        sts_client: Any = None,
        kms_client: Any = None,
    ):
        """
        Initializes the AWS workload identity provider.

        Args:
            kms_key_id: The ID, ARN, or alias of the AWS KMS key to use.
            region_name: AWS region. If None, uses the default configuration.
            role_arn: Optional override for the role ARN. If None, it is fetched
                dynamically from STS.
            signing_algorithm: The KMS signing algorithm to use.
            sts_client: Optional pre-initialized STS client.
            kms_client: Optional pre-initialized KMS client.

        Raises:
            RuntimeError: If the 'boto3' package is not installed.
        """
        if not HAS_BOTO3:
            raise RuntimeError(
                "AWSWorkloadIdentity requires the `boto3` package. Install with `pip install kest[aws]`"
            )

        self.kms_key_id = kms_key_id
        self.signing_algorithm = signing_algorithm
        self._role_arn = role_arn

        # Mapping KMS algorithm names to JWS alg names
        self._alg_map = {
            "ECDSA_SHA_256": "ES256",
            "RSASSA_PKCS1_V1_5_SHA_256": "RS256",
        }

        if sts_client and kms_client:
            self.sts = sts_client
            self.kms = kms_client
        else:
            session = boto3.Session(region_name=region_name)
            self.sts = session.client("sts")
            self.kms = session.client("kms")

    def get_identity(self) -> str:
        """
        Returns the IAM Role ARN of the current principal.

        Returns:
            str: The IAM Role ARN (e.g., arn:aws:iam::123456789012:role/my-role).

        Raises:
            PermissionError: If STS fails to return the caller identity.
        """
        if not self._role_arn:
            try:
                res = self.sts.get_caller_identity()
                self._role_arn = res["Arn"]
            except Exception as e:
                print(f"[Kest.Identity] Failed to fetch principal from STS: {e}")
                raise PermissionError(f"AWS identity unavailable: {e}")
        return self._role_arn

    def sign(self, payload: bytes) -> str:
        """
        Signs a payload using Amazon KMS.

        Args:
            payload: Binary data to sign.

        Returns:
            str: A complete JWS signature with the IAM Role ARN as the 'kid'.

        Raises:
            PermissionError: If KMS fails to sign the payload.
        """
        try:
            res = self.kms.sign(
                KeyId=self.kms_key_id,
                Message=payload,
                MessageType="RAW",
                SigningAlgorithm=self.signing_algorithm,
            )
            signature = res["Signature"]

            header = {
                "alg": self._alg_map.get(self.signing_algorithm, "Unknown"),
                "typ": "JWS",
                "kid": self.get_identity(),
            }

            header_b64 = (
                base64.urlsafe_b64encode(json.dumps(header).encode())
                .decode()
                .rstrip("=")
            )
            payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
            sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

            return f"{header_b64}.{payload_b64}.{sig_b64}"
        except Exception as e:
            print(f"[Kest.Identity] AWS KMS signing failed: {e}")
            raise PermissionError(f"Identity signing failed: {e}")
