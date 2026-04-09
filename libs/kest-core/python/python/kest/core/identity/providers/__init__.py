"""
Kest Identity Providers.

This module provides various identity provider implementations for identifying
workloads and signing audit entries.
"""

from kest.core.identity.providers.aws import AWSWorkloadIdentity
from kest.core.identity.providers.bedrock import BedrockAgentIdentity
from kest.core.identity.providers.lazy import LazySigningProvider
from kest.core.identity.providers.local import (
    LocalEd25519Provider,
    MockIdentityProvider,
    StaticIdentity,
)
from kest.core.identity.providers.oidc import OIDCIdentity
from kest.core.identity.providers.spiffe import SPIREProvider

__all__ = [
    "MockIdentityProvider",
    "StaticIdentity",
    "LocalEd25519Provider",
    "SPIREProvider",
    "AWSWorkloadIdentity",
    "BedrockAgentIdentity",
    "OIDCIdentity",
    "LazySigningProvider",
]
