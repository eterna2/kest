import os

from kest.core.identity.base import IdentityProvider
from kest.core.identity.providers.spiffe import SPIREProvider, HAS_SPIFFE
from kest.core.identity.providers.aws import AWSWorkloadIdentity, HAS_BOTO3
from kest.core.identity.providers.bedrock import BedrockAgentIdentity
from kest.core.identity.providers.oidc import OIDCIdentity
from kest.core.identity.providers.local import (
    StaticIdentity,
    LocalEd25519Provider,
    MockIdentityProvider,
)
from kest.core.identity.providers.lazy import LazySigningProvider


def get_default_identity() -> IdentityProvider:
    """
    Auto-detects the appropriate identity provider based on the environment.
    """
    # 1. SPIRE
    if os.environ.get("SPIFFE_ENDPOINT_SOCKET") and HAS_SPIFFE:
        return SPIREProvider()

    # 2. Bedrock AgentCore
    if os.environ.get("AWS_BEDROCK_AGENT_ID") and HAS_BOTO3:
        return BedrockAgentIdentity()

    # 3. AWS Standard (ECS, Lambda, EKS with IAM Roles for Service Accounts)
    if os.environ.get("AWS_EXECUTION_ENV") or os.environ.get("AWS_ROLE_ARN"):
        if HAS_BOTO3:
            # We assume they have a KMS key if they are running in AWS.
            # If not, this will fail on initialization or signing.
            kms_key_id = os.environ.get("KEST_AWS_KMS_KEY_ID")
            if kms_key_id:
                return AWSWorkloadIdentity(kms_key_id=kms_key_id)
            else:
                print(
                    "[Kest.Identity] WARNING: Running in AWS but KEST_AWS_KMS_KEY_ID is not set. Falling back to local identity."
                )

    # 4. OIDC token injection
    if os.environ.get("KEST_OIDC_TOKEN_PATH"):
        return OIDCIdentity()

    # 5. Fallback
    print(
        "[Kest.Identity] WARNING: Zero-config auto-detection failed to find a production identity provider. Falling back to StaticIdentity."
    )
    return LocalEd25519Provider()


__all__ = [
    "IdentityProvider",
    "get_default_identity",
    "SPIREProvider",
    "AWSWorkloadIdentity",
    "BedrockAgentIdentity",
    "OIDCIdentity",
    "StaticIdentity",
    "LocalEd25519Provider",
    "MockIdentityProvider",
    "LazySigningProvider",
]
