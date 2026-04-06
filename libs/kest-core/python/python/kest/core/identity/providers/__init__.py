"""
Kest Identity Providers.

This module provides various identity provider implementations for identifying
workloads and signing audit entries.
"""

from kest.core.identity.providers.local import (
    MockIdentityProvider,
    StaticIdentity,
    LocalEd25519Provider,
)
from kest.core.identity.providers.spiffe import SPIREProvider
from kest.core.identity.providers.aws import AWSWorkloadIdentity
from kest.core.identity.providers.bedrock import BedrockAgentIdentity
from kest.core.identity.providers.oidc import OIDCIdentity
from kest.core.identity.providers.lazy import LazySigningProvider

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
