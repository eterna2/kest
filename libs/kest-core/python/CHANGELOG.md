# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- **Template & Hydrate engine** (Issue #83): New `TemplateParser` and `TemplateEngine`
  classes in `kest.core.vault` for data-safe LLM report composition:
  - `TemplateParser.parse(template)` — regex-based extraction of `{{hdl_...}}` placeholders
    from LLM-generated skeleton strings.
  - `TemplateParser.render(template, substitutions)` — substitutes each placeholder
    with its resolved string value; unknown placeholders are left untouched.
  - `TemplateEngine(vault, serializer=str)` — orchestrates the full pipeline:
    parse → ACL-checked unseal (all handles attempted, no short-circuit) →
    serialise with a configurable `Callable[[Any], str]` → post-hydration
    `OutputValidator` guardrails → return hydrated string.
  - `HydrationError(errors: dict[str, Exception])` — raised when one or more
    handles fail ACL / not-found / expiry checks; `errors` maps each failing
    handle ID to its original exception so the caller gets a complete picture
    in a single pass.
  - Exported from `kest.core.vault` and hoisted into `kest.core`.

- **FastAPI Integration Plugin** (`kest[fastapi]`): New `kest.core.integrations.fastapi` module
  providing a zero-boilerplate FastAPI integration for the HandleVault:
  - `VaultRouter(vault, extractor, gateway_principals)` — a drop-in `APIRouter` exposing
    `GET /safe-view/{handle_id}` (public) and `GET /resolve/{handle_id}` (privileged) routes.
  - `VaultDependency(vault, extractor)` — a `Depends`-compatible callable for use in custom
    routes; unseals handles and enforces vault ACLs automatically.
  - `JWTPrincipalExtractor(secret, algorithm, claim)` — extracts the caller's SPIFFE principal
    from an HS256 (or RS/ES) JWT Bearer token.
  - `HeaderPrincipalExtractor(header_name)` — extracts principal from a plain HTTP header;
    useful for trusted-proxy and sidecar setups.
  - `PrincipalExtractor` — base class / protocol; implement `async extract(request) -> str`
    to integrate any custom authentication mechanism (mTLS, OIDC, API-key, …).
  - `vault_seal_response(vault, data, safe_view, owner, granted, ttl)` — convenience helper
    that seals data and returns a `HandleResponse` TypedDict for use in route handlers.
  - Install with: `pip install kest[fastapi]`
  - All symbols are also hoisted into `kest.core` under a graceful `try/except ImportError`
    guard so `kest.core` remains importable without the optional extras.

---

## [0.4.0] - 2026-04-24

### Added

- **Resource Context** (F-IC-01, F-IC-02, F-IC-04): Added `resource_id` (str | Callable) and
  `resource_attr` (dict | Callable) parameters to `@kest_verified`. Both accept static values
  or resolver callables that are invoked with the decorated function's arguments at call time.
  Resolved values are forwarded to the policy engine as `object.id` / `object.attributes` per
  SPEC-v0.3.0 §9.2 (F-IC-01, F-IC-02) and serialized into `KestEntry.labels["kest.resource_attr"]`
  for tamper-evident audit (F-IC-04). The policy decision cache key now includes `resource_id` to
  prevent cross-resource ABAC cache collisions.
- **Classification-based Automatic Taint Tagging** (Issue #80): Added `classification` parameter
  to `@kest_verified` (default `"system"`, matching the existing behaviour). When a classification
  is mapped in the active `CLASSIFICATION_TAINT_MAP`, the corresponding taints are automatically
  merged into the decorated function's `KestEntry` without any manual `added_taints` configuration:
  - `"data"` → `"contains_data"`
  - `"critic"` → `"requires_review"`
  - `"sanitizer"` → `"sanitized"`
  The map is fully configurable via `configure(classification_taint_map=…)` and resets to
  defaults on `configure(clear=True)`. Auto-taints respect `removed_taints` (an auto-taint that
  also appears in `removed_taints` is suppressed).
- **Output Validators / Guardrail Hooks** (Issue #78): Added `output_validators` parameter to
  `@kest_verified` accepting a list of `OutputValidator` instances. Validators are run after
  function execution; any `OutputValidationError` adds the taint `"output_validation_failed"` to
  the audit entry and re-raises (the result is NOT returned to the caller). Built-in validators:
  - `MaxLengthValidator(max_chars)` — rejects outputs whose `str()` exceeds `max_chars` characters.
  - `RegexDenyListValidator(patterns)` — rejects outputs matching any regex in the deny-list.
- **Structured Output Validation Framework** (Issue #81): Expanded the `OutputValidator` ABC into a
  full composable validation pipeline with severity-aware violation tracking:
  - `ValidationSeverity` — ordered enum: `INFO`, `WARNING`, `BLOCK`.
  - `ValidationViolation` — single-validator finding with `message`, `severity`, and `validator_name`.
  - `ValidationResult` — aggregated pipeline outcome: `passed`, `violations`, and max `severity`.
  - `ValidationPipeline` — runs all validators, collects every violation before deciding to block.
    Implements `OutputValidator` itself so it can be passed directly to `output_validators`.
  - `LengthBoundsValidator(min_chars, max_chars)` — enforces minimum and/or maximum length bounds.
  - `JsonSchemaValidator(schema)` — validates outputs against a JSON Schema dict; accepts `dict`,
    `list`, or JSON-encoded `str`. Requires the optional `kest[schema]` extra (`jsonschema>=4.0.0`).
  - `ContentClassificationValidator(expected)` — verifies the output matches a label list or a
    callable predicate; supports case-insensitive matching via `case_sensitive=False`.
  - `SemanticDriftDetector` — abstract base for similarity-based drift detection; subclasses
    implement `detect(reference, output) -> float` and raise `OutputValidationError` when the
    drift score meets or exceeds `threshold`.
  All new symbols are exported from the `kest.core` public API.
- **Data Vault / Opaque Handle Primitives** (Issue #79): Implemented the `kest.core.vault` package
  providing foundational building blocks for the zero-trust Template & Hydrate composition flow.
  Raw sensitive data is sealed into a `HandleVault` and referenced by an `OpaqueHandle` — an opaque
  pointer that carries only a non-sensitive `safe_view` string safe for LLM context windows:
  - `OpaqueHandle(id, safe_view, owner_principal, created_at, expires_at, granted_principals)` —
    frozen dataclass; `id` is prefixed `hdl_<uuid4_hex>`; timestamps are UTC-aware.
  - `HandleVault(cache=None, codec=None)` — in-memory vault backed by `CacheProvider` (defaults to `SimpleCache`):
    - `seal(data, owner_principal, safe_view, ttl_seconds=300, granted_principals=())` → `OpaqueHandle`
    - `unseal(handle_id, requesting_principal)` → raw data; enforces ACL and TTL (lazy expiry check).
    - `invalidate(handle_id)` — immediate eviction; idempotent for unknown handles.
    - `get_safe_view(handle_id)` — ACL-free access to the non-sensitive summary.
  - `HandleNotFoundError`, `HandleExpiredError`, `HandleAccessDeniedError` — typed error hierarchy.
- **VaultCodec — Encryption & Compression Pipeline** (Issue #79): Added an optional, composable
  payload pipeline applied before data enters the cache. Both stages are independently optional:
  - **Compressors** (stdlib, no extra deps): `ZlibCompressor`, `GzipCompressor`; optional extras:
    `LZ4Compressor` (`kest[lz4]`), `ZstdCompressor` (`kest[zstd]`)
  - **Encryptors** (uses core `cryptography` dep): `AES256GCMEncryptor` (AES-256-GCM, authenticated,
    fresh random nonce per call), `FernetEncryptor` (AES-128-CBC+HMAC-SHA256, simple key management)
  - `VaultCodec(compressor=None, encryptor=None)` — pipeline order: pickle → compress → encrypt (seal);
    decrypt → decompress → unpickle (unseal). Both are fully optional; no codec = identity passthrough.
  All codec symbols exported from `kest.core` public API.
- **Pluggable Cache Backends** (Issue #79): Five `CacheProvider` implementations beyond the default
  `SimpleCache`, each available as an optional install extra:
  - `SQLiteCache` (stdlib, no extra dep) — ACID-compliant SQLite KV store; supports in-memory
    (`:memory:`) and persistent file modes; thread-safe with a single shared connection + lock.
  - `LMDBCache` — Lightning Memory-Mapped DB via `kest[lmdb]`; fastest reads via zero-copy B+tree;
    auto-creates a temporary directory when no path is specified.
  - `CachetoolsCache` — pure-Python TTLCache/LRUCache via `kest[cachetools]`; configurable maxsize
    and default_ttl.
  - `RedisCache` — Redis-backed store via `kest[redis]`; also compatible with KeyDB (RESP protocol).
  - `ValkeyCache` — Valkey-backed store via `kest[valkey]`; Linux Foundation open-source Redis fork.
  All backends are exported from `kest.core` public API. LMDB tests are skipped if `lmdb` not
  installed; Redis/Valkey tests use `fakeredis` in the dev dependency group.
- **Vault Service Transports** (Issue #79): Three embeddable server transports expose a `HandleVault`
  over the network; a unified `VaultClient` provides a single API for all three:
  - `VaultHTTPServer` — REST/JSON over HTTP (stdlib `http.server`); endpoints: `POST /handles`,
    `POST /handles/{id}/unseal`, `DELETE /handles/{id}`, `GET /handles/{id}/safe_view`.
  - `VaultRPCServer` — XML-RPC (stdlib `xmlrpc.server`); methods: `seal`, `unseal`, `invalidate`,
    `get_safe_view`; faults mapped to typed vault errors on the client side.
  - `VaultSocketServer` — JSON-RPC 2.0 over TCP or Unix domain socket; 4-byte length-prefixed
    framing; supports both `(host, port)` and socket file path addresses.
  - `VaultClient.http(url)`, `.rpc(host, port)`, `.socket(address)` — factory classmethods;
    all raise `HandleNotFoundError`, `HandleExpiredError`, or `HandleAccessDeniedError` natively.
  All server/client symbols exported from `kest.core` public API.


- **Context Accessor Functions** (F-CP-06): Implemented the five public context accessor functions required by SPEC-v0.3.0 §2.8:
  - `get_current_user()` — reads `kest.user` from OTel Baggage
  - `get_current_agent()` — reads `kest.agent` from OTel Baggage
  - `get_current_task()` — reads `kest.task` from OTel Baggage
  - `get_current_jwt()` — reads `kest.jwt` from OTel Baggage (previously internal, now public with type hints)
  - `get_current_passport()` — reads `kest.passport` from OTel Baggage (previously internal, now public with type hints)
- All five accessors are exported from the `kest.core` public API.

### Changed

- **Toolchain**: Upgraded moon from 2.1.3 → 2.2.3 to fix proto 0.55.4 WASM plugin incompatibility (`missing field 'working_dir'`).

## [0.3.0.post1] - 2026-04-19

- **Fix**: Added explicit `description` and `readme` parameters to the core `pyproject.toml` to correctly render documentation metadata on PyPI.
- **CI**: Hardened action triggers by specifying absolute SHAs and binding the proper `pypi` Trusted Publisher OIDC environment payload.

## [0.3.0] - 2026-04-18

> **v0.3.0 is a complete architectural rewrite.** The package has eliminated the legacy Rust backend and is now rebuilt from the ground up as a pure Python namespace package. Applications upgrading from any pre-release versions must migrate to the new `kest.core` API.

### 🐍 Pure Python Core (`kest.core`)

- **Namespace Package**: Converted `kest` into a strict Python namespace package by removing the root `kest/__init__.py`. All library logic is cleanly exposed under `kest.core`.
- **Native Canonicalization & Signing**: Deprecated the Rust core and PyO3 bindings. High-performance JSON canonicalization (RFC 8785) and Ed25519 JWS generation are now executed natively in Python via `kest.core._core` and standard cryptography dependencies. This resolves all prior GIL re-acquisition cliffs and simplifies distribution across platforms.
- **Modular Framework**: Reorganized the monolith into decoupled modules: `kest.core.models` (data schemas), `kest.core.engines` (evaluators), `kest.core.identity` (trust anchors), `kest.core.framework` (web integration), and `kest.core.telemetry`.

### 🔐 Multi-Source Identity Providers (`kest.core.identity`)

- **OAuth CLI Provider**: Introduced the `OAuthCliProvider` (`kest.core.identity.providers.oauth`) supporting standard Device Code flows for localized agent/tool authentication.
- **Deterministic Key Generation**: Implemented PBKDF2-derived deterministic Ed25519 key generation within `LocalEd25519Provider`, stabilizing identities across transient sessions.
- **Broad Provider Support**: Added specialized provider interfaces for AWS Identity (`aws`), Bedrock Contexts (`bedrock`), local ephemeral (`local`), SPIFFE runtime (`spiffe`), general OIDC (`oidc`), and deferred resolution (`lazy`). 

### 🛡️ Policy Engines & Pre-Validation (`kest.core.engines` & `kest.core.policies`)

- **Multi-Language Engines**: Consolidated dynamic evaluation engines for ABAC/RBAC, introducing parity across `RegoLocalEngine` and `CedarLocalEngine` for offline execution, with parallel remote evaluation support via `OPAPolicyEngine` and `AVPPolicyEngine`.
- **AST-based Validations**: Added proactive structural syntax validators for Cedar and Rego (`kest.core.policies.validators`) to trap malformed policy permutations before evaluation runtime.

### 📜 Data Models & Lineage (`kest.core.models`)

- **Integer Trust Scoring**: Normalized CARTA trust scores from raw floats to precise integers (0–100) integrated directly with DAG topology bounds (`kest.core.models.trust_test.py`). 
- **Taint Propagation**: Enhanced the taint module (`kest.core.taints_test.py`) with automatic origin accumulation tracking and O(1) containment isolation within the Passport.
- **Claim Checks**: Optimized large Passport chunks with deferred storage validation structures (`kest.core.claim_check_test.py`) preventing HTTP header bloat natively out of the box.

### 🕸️ Framework Integration (`kest.core.framework`)

- **Unified Decorators**: The `@kest_verified` API has been streamlined under `kest.core.framework.decorators`, supporting unified async/sync operation wrapping.
- **Ext Middleware**: Bundled FastAPI/ASGI middleware and HTTPX interceptors (`kest.core.framework.ext`) to transparently propagate telemetry context extraction and injection downstream.

---

## [0.2.0] - 2026-03-18

### Added
- **Trust Scores**: Introduced numeric data quality evaluation (`trust_score`) on the `KestEntry` model as a float (0.0–1.0). *(Migrated to integer 0–100 in v0.3.0.)*
- **Dynamic Trust Propagators**: Added `trust_score_updater` to the `@kest_verified` decorator, allowing node-specific synthesis of parent trust scores. Defaults to propagating the minimum trust score from the parents.
- **Policy Enforcement**: Integrated `trust_score` directly into the OPA payload context to allow dynamic runtime blocking on minimum trust thresholds.
- **Trust Origination**: Added `trust_score` parameter to the `originate` helper function to jump-start external data with specific trust baselines.

## [0.1.0] - 2026-03-18

### Added
- **Core Lineage Engine**: Implementation of the Attested Data Lineage specification using a Directed Acyclic Graph (DAG) for non-repudiable audit trails.
- **Taint Tracking**: Automatic propagation of risk profiles (taints) across data processing boundaries.
- **Life-cycle Decorators**: Introduced the `@verified` decorator (ingress guard/egress sealer) for transparent data tracking.
- **OPA Integration**:
    - Support for local inline Rego evaluation via `lakera-regorus`.
    - Support for remote OPA server evaluation via `opa-python-client`.
- **Cryptographic Integrity**: Recursive DAG hashing ($H_{bind}$) and ED25519 signing of project passports.
- **Implicit Origination**: Automatic passport generation for raw primitives entering the system.
- **CLI Inspector**: Visual tree representation of data lineage via `kest` CLI.
- **Developer Experience**:
    - Comprehensive `README.md` and `CONTRIBUTING.md`.
    - Automated CI/CD pipelines for testing, coverage, and PyPI publishing.
    - Pre-commit hooks for consistent code quality using `ruff`.
- **Interactive Demos**: End-to-end examples in `examples/flow.py` and Jupyter notebooks.
