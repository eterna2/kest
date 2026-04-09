import base64
import json
import os
from typing import Any, Optional

from kest.core.identity.base import IdentityProvider

try:
    import boto3

    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


class BedrockAgentIdentity(IdentityProvider):
    """
    Standard provider for Amazon Bedrock Agent execution environments.

    This provider resolves the Bedrock Agent ID and Alias ID from environment
    variables or configuration, and uses AWS KMS to sign execution traces
    and audit entries.
    """

    def __init__(
        self,
        kms_key_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        alias_id: Optional[str] = None,
        region_name: Optional[str] = None,
        signing_algorithm: str = "ECDSA_SHA_256",
        sts_client: Any = None,
        kms_client: Any = None,
    ):
        """
        Initializes the Bedrock agent identity provider.

        Args:
            kms_key_id: The KMS key used for signing. If None, it defaults to
                'alias/bedrock-agent-signing-key'.
            agent_id: The unique ID of the Bedrock Agent.
            alias_id: The alias ID of the Bedrock Agent.
            region_name: AWS region.
            signing_algorithm: The KMS signing algorithm.
            sts_client: Optional pre-initialized STS client.
            kms_client: Optional pre-initialized KMS client.

        Raises:
            RuntimeError: If 'boto3' is not installed.
        """
        if not HAS_BOTO3:
            raise RuntimeError(
                "BedrockAgentIdentity requires the `boto3` package. Install with `pip install kest[aws]`"
            )

        # Resolve Configuration
        self._agent_id = agent_id or os.environ.get("AWS_BEDROCK_AGENT_ID")
        self._alias_id = alias_id or os.environ.get("AWS_BEDROCK_AGENT_ALIAS_ID")

        # Automatically fall back to a default alias for agent signing if not provided
        self.kms_key_id = kms_key_id or os.environ.get(
            "KEST_BEDROCK_KMS_KEY_ID", "alias/bedrock-agent-signing-key"
        )

        self.signing_algorithm = signing_algorithm

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

        self._principal = None

    def get_identity(self) -> str:
        """
        Returns a formatted Bedrock URI for the current agent.

        Format: bedrock://{account_id}/agent/{agent_id}/alias/{alias_id}

        Returns:
            str: The Bedrock principal identifier.

        Raises:
            PermissionError: If STS fails to return identity.
        """
        if not self._principal:
            try:
                res = self.sts.get_caller_identity()
                account = res["Account"]

                if self._agent_id:
                    self._principal = f"bedrock://{account}/agent/{self._agent_id}"
                    if self._alias_id:
                        self._principal += f"/alias/{self._alias_id}"
                else:
                    # Fallback if Agent ID is not provided or injected
                    self._principal = res["Arn"]
            except Exception as e:
                print(f"[Kest.Identity] Failed to fetch principal from STS: {e}")
                raise PermissionError(f"Bedrock identity unavailable: {e}")
        return self._principal

    def sign(self, payload: bytes) -> str:
        """
        Signs a payload using AWS KMS with the Bedrock identity as 'kid'.

        Args:
            payload: Binary data to sign.

        Returns:
            str: A complete JWS signature.

        Raises:
            PermissionError: If KMS fails to sign.
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
