"""
Kest: Key + Trust. A toolkit for cryptographically verifiable execution lineage.

This package provides the core Python implementation of Kest, including:
- Unified security policy engines (OPA, Cedar, AWS AVP).
- Cross-workload identity management (SPIRE, AWS, OIDC).
- Automatic execution graph (Merkle DAG) recording via decorators.
- Distributed propagation via OpenTelemetry.
"""

from typing import Any

from kest.core._core import KestEntry, sign_entry, version

__version__ = version()
from kest.core.engines.engine import (  # noqa: E402
    AVPPolicyEngine,
    CedarLocalEngine,
    CedarPolicyEngine,
    MockPolicyEngine,
    OPAPolicyEngine,
    PolicyCache,
    PolicyEngine,
    RegoLocalEngine,
)
from kest.core.framework.cache import CacheProvider, SimpleCache  # noqa: E402
from kest.core.framework.cache_providers import (  # noqa: E402, F401
    CachetoolsCache,
    RedisCache,
    SQLiteCache,
    ValkeyCache,
)
from kest.core.framework.context import (  # noqa: E402
    get_current_agent,
    get_current_jwt,
    get_current_passport,
    get_current_task,
    get_current_user,
)
from kest.core.framework.decorators import (  # noqa: E402
    invalidate_policy_cache,
    kest_verified,
)
from kest.core.framework.ext import (  # noqa: E402
    KestHttpxInterceptor,
    KestIdentityMiddleware,
    KestMiddleware,
)
from kest.core.framework.validators import (  # noqa: E402
    ContentClassificationValidator,
    JsonSchemaValidator,
    LengthBoundsValidator,
    MaxLengthValidator,
    OutputValidationError,
    OutputValidator,
    RegexDenyListValidator,
    SemanticDriftDetector,
    ValidationPipeline,
    ValidationResult,
    ValidationSeverity,
    ValidationViolation,
)
from kest.core.identity import (  # noqa: E402
    AWSWorkloadIdentity,
    BedrockAgentIdentity,
    IdentityProvider,
    LazySigningProvider,
    LocalEd25519Provider,
    MockIdentityProvider,
    OIDCIdentity,
    SPIREProvider,
    StaticIdentity,
    get_default_identity,
)
from kest.core.models.passport import (  # noqa: E402
    BaggageManager,
    DefaultTrustEvaluator,
    Passport,
    PassportVerifier,
    PolicyDeviation,
    TrustEvaluator,
    register_origin_trust,
)
from kest.core.vault import (  # noqa: E402, F401
    AES256GCMEncryptor,
    Compressor,
    Encryptor,
    FernetEncryptor,
    GzipCompressor,
    HandleVault,
    LZ4Compressor,
    OpaqueHandle,
    VaultCodec,
    ZlibCompressor,
    ZstdCompressor,
)
from kest.core.vault.errors import (  # noqa: E402, F401
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)
from kest.core.vault.server import (  # noqa: E402, F401
    VaultClient,
    VaultHTTPServer,
    VaultRPCServer,
    VaultSocketServer,
)

# FastAPI integration (kest[fastapi]) — import is lazy so kest.core remains
# importable without fastapi/python-jose installed.  Consumers that install
# `kest[fastapi]` can import directly from `kest.core.integrations.fastapi`;
# the symbols are also hoisted here for convenience.
try:
    from kest.core.integrations.fastapi import (  # noqa: F401
        HandleResponse,
        HeaderPrincipalExtractor,
        JWTPrincipalExtractor,
        PrincipalExtractor,
        VaultDependency,
        VaultRouter,
        vault_seal_response,
    )

    _FASTAPI_INTEGRATION_AVAILABLE = True
except ImportError:  # fastapi / python-jose not installed
    _FASTAPI_INTEGRATION_AVAILABLE = False

_active_engine: PolicyEngine | None = None
_active_identity: IdentityProvider | None = None
_active_cache: CacheProvider | None = None
_active_enterprise_policies: list[str] = []
_active_deviations: list[Any] = []
_active_classification_taint_map: dict[str, list[str]] | None = (
    None  # None = use DEFAULT
)


def configure(
    engine: PolicyEngine | None = None,
    identity: IdentityProvider | None = None,
    cache: CacheProvider | None = None,
    enterprise_policies: list[str] | None = None,
    deviations: list[Any] | None = None,
    classification_taint_map: dict[str, list[str]] | None = None,
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
        classification_taint_map: (Optional) Mapping from classification label to list of taints
            auto-applied when a function decorated with @kest_verified uses that classification.
            Overrides the built-in DEFAULT_CLASSIFICATION_TAINT_MAP.  Pass ``None`` (or call
            ``configure(clear=True)``) to reset to the default map.
        clear: If True, resets all global configurations to None.
    """
    global \
        _active_engine, \
        _active_identity, \
        _active_cache, \
        _active_enterprise_policies, \
        _active_deviations, \
        _active_classification_taint_map
    if clear:
        _active_engine = None
        _active_identity = None
        _active_cache = None
        _active_enterprise_policies = []
        _active_deviations = []
        _active_classification_taint_map = None  # resets to DEFAULT in accessor

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
    if classification_taint_map is not None:
        _active_classification_taint_map = classification_taint_map


__all__ = [
    "__version__",
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
    "KestIdentityMiddleware",
    "KestHttpxInterceptor",
    "TrustEvaluator",
    "DefaultTrustEvaluator",
    "PassportVerifier",
    "PolicyDeviation",
    "BaggageManager",
    "register_origin_trust",
    # Operations
    "sign_entry",
    "invalidate_policy_cache",
    # Context Accessors (F-CP-06)
    "get_current_user",
    "get_current_agent",
    "get_current_task",
    "get_current_jwt",
    "get_current_passport",
    # Output Validators (Issue #78)
    "OutputValidator",
    "OutputValidationError",
    "MaxLengthValidator",
    "RegexDenyListValidator",
    # Structured Validation Framework (Issue #81)
    "ValidationSeverity",
    "ValidationViolation",
    "ValidationResult",
    "ValidationPipeline",
    "LengthBoundsValidator",
    "JsonSchemaValidator",
    "ContentClassificationValidator",
    "SemanticDriftDetector",
    # Vault — HandleVault & opaque handles
    "HandleVault",
    "OpaqueHandle",
    "VaultCodec",
    "Compressor",
    "Encryptor",
    "GzipCompressor",
    "ZlibCompressor",
    "LZ4Compressor",
    "ZstdCompressor",
    "AES256GCMEncryptor",
    "FernetEncryptor",
    "HandleAccessDeniedError",
    "HandleExpiredError",
    "HandleNotFoundError",
    # Vault servers & clients
    "VaultHTTPServer",
    "VaultRPCServer",
    "VaultSocketServer",
    "VaultClient",
    # Cache backends
    "CachetoolsCache",
    "RedisCache",
    "SQLiteCache",
    "ValkeyCache",
    # FastAPI integration (kest[fastapi]) — available only if extras installed
    "VaultRouter",
    "VaultDependency",
    "JWTPrincipalExtractor",
    "HeaderPrincipalExtractor",
    "PrincipalExtractor",
    "HandleResponse",
    "vault_seal_response",
]
