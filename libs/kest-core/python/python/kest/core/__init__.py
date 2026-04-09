"""
Kest: Key + Trust. A toolkit for cryptographically verifiable execution lineage.

This package provides the core Python implementation of Kest, including:
- Unified security policy engines (OPA, Cedar, AWS AVP).
- Cross-workload identity management (SPIRE, AWS, OIDC).
- Automatic execution graph (Merkle DAG) recording via decorators.
- Distributed propagation via OpenTelemetry.
"""

from kest.core._core import version, KestEntry
from kest.core.engine import (
    PolicyEngine,
    MockPolicyEngine,
    OPAPolicyEngine,
    CedarPolicyEngine,
    CedarLocalEngine,
    RegoLocalEngine,
    AVPPolicyEngine,
    PolicyCache,
)
from kest.core.identity import (
    IdentityProvider,
    get_default_identity,
    MockIdentityProvider,
    SPIREProvider,
    LazySigningProvider,
    AWSWorkloadIdentity,
    BedrockAgentIdentity,
    OIDCIdentity,
    StaticIdentity,
    LocalEd25519Provider,
)
from kest.core.cache import CacheProvider, SimpleCache
from kest.core.decorators import kest_verified
from kest.core.models import (
    Passport,
    TrustEvaluator,
    DefaultTrustEvaluator,
    PassportVerifier,
    BaggageManager,
    register_origin_trust,
)
from kest.core.ext import KestMiddleware, KestHttpxInterceptor
from typing import Any

_active_engine: PolicyEngine | None = None
_active_identity: IdentityProvider | None = None
_active_cache: CacheProvider | None = None
_active_enterprise_policies: list[str] = []
_active_deviations: list[Any] = []


def configure(
    engine: PolicyEngine | None = None,
    identity: IdentityProvider | None = None,
    cache: CacheProvider | None = None,
    enterprise_policies: list[str] | None = None,
    deviations: list[Any] | None = None,
    clear: bool = False,
):
    """
    Globally configures the Kest execution environment.

    This should be called once during application startup. If a parameter is
    not provided, it retains its existing value. If no identity is provided,
    Kest will attempt to auto-detect the environment (e.g., SPIRE, AWS).

    Args:
        engine: The PolicyEngine to use for @kest_verified checks.
        identity: The IdentityProvider for signing audit entries.
        cache: (Optional) Cache for policy results and lineage claim-checks.
        enterprise_policies: (Optional) List of policy names enforced at the enterprise level tier.
        deviations: (Optional) List of PolicyDeviations for bypassing baseline policies.
        clear: If True, resets all global configurations to None.
    """
    global _active_engine, _active_identity, _active_cache, _active_enterprise_policies, _active_deviations
    if clear:
        _active_engine = None
        _active_identity = None
        _active_cache = None
        _active_enterprise_policies = []
        _active_deviations = []

    if engine:
        _active_engine = engine
    if identity:
        _active_identity = identity
    else:
        # Auto-detect identity if none is provided and we are not clearing
        if not clear:
            _active_identity = get_default_identity()
    if cache:
        _active_cache = cache
    if enterprise_policies is not None:
        _active_enterprise_policies = enterprise_policies
    if deviations is not None:
        _active_deviations = deviations


__all__ = [
    "version",
    "KestEntry",
    "Passport",
    "PolicyEngine",
    "MockPolicyEngine",
    "OPAPolicyEngine",
    "CedarPolicyEngine",
    "CedarLocalEngine",
    "RegoLocalEngine",
    "AVPPolicyEngine",
    "PolicyCache",
    "IdentityProvider",
    "MockIdentityProvider",
    "SPIREProvider",
    "LazySigningProvider",
    "AWSWorkloadIdentity",
    "BedrockAgentIdentity",
    "OIDCIdentity",
    "StaticIdentity",
    "LocalEd25519Provider",
    "CacheProvider",
    "SimpleCache",
    "configure",
    "kest_verified",
    "KestMiddleware",
    "KestHttpxInterceptor",
    "TrustEvaluator",
    "DefaultTrustEvaluator",
    "PassportVerifier",
    "BaggageManager",
    "register_origin_trust",
]
