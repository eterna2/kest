# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-04-06

> **v0.3.0 is a complete architectural rewrite.** The package (formerly a pure-Python prototype) is rebuilt from the ground up as a polyglot toolkit with a high-performance Rust core, replacing all v0.2.x internals. Applications upgrading from v0.2.x must migrate to the new API.

### 💯 Trust Score Model — Integer (0–100)

The trust score type has been **migrated from `float` (0.0–1.0) to `int` (0–100)**. This is a breaking change from v0.2.x.

- **Rust core**: `KestEntry.trust_score` changed from `f64` to `i32`.
- **PyO3 bindings**: `trust_score` getter and constructor updated to `i32`.
- **`DefaultTrustEvaluator`**: Now uses integer arithmetic — `(min(parent_scores) * self_score) // 100`.
- **`ORIGIN_TRUST_MAP`** (formerly `SOURCE_TRUST_MAP`): All values updated from floats to integers (`1.0 → 100`, `0.1 → 10`, etc.).
- **Policy thresholds**: OPA and Cedar policies now use integer comparisons (`trust_score >= 50` instead of `>= 0.5`).
- **Serialization fix**: `removed_taints` was missing from the manual `Serialize` impl in `models.rs` — it is now correctly included in every signed JWS payload.
- **PyO3 property getters**: Added `added_taints`, `removed_taints`, and `taints` getters to `KestEntry` for direct Python-side inspection.

| `origin` | Old (`float`) | New (`int`) |
|---|---|---|
| `system` / `internal` | `1.0` | `100` |
| `verified_rag` | `0.9` | `90` |
| `third_party_api` | `0.6` | `60` |
| `user_input` | `0.4` | `40` |
| `internet` | `0.1` | `10` |
| `llm` | `0.0` | `0` |

### 🦀 Rust Core (`libs/kest-core/rust`)

A new, standalone Rust library now implements the performance-critical primitives:

- **RFC 8785 Canonicalization** (`canonical.rs`): Deterministic JSON serialization via `serde_jcs`, ensuring consistent cross-language hashing.
- **ED25519 Signing & JWS** (`crypto.rs`): Compact JWS token generation (`header.payload.signature`) using canonical JSON as the signing payload. Exposes `IdentityProvider` and `PolicyEngine` traits for Rust-native implementations.
- **Merkle DAG Trust Propagation** (`trust.rs`): `TrustEvaluator` trait with `DefaultTrustEvaluator` — calculates `min(parent_scores) × node_trust_score` for deterministic trust decay across DAG hops.
- **PyO3 Bindings** (`src/lib.rs`): Exposes `KestEntry` and `sign_entry` to Python via `kest.core._core`, eliminating the legacy pure-Python signing path.

### 🐍 Python Core (`libs/kest-core/python`) — Full Rewrite

#### Policy Engines (`kest.core.engine`)

| Engine | Backend | Extra |
|---|---|---|
| `OPAPolicyEngine` | Remote OPA server (HTTP) | `opa` |
| `CedarPolicyEngine` | Remote Cedar server (HTTP) | — |
| `CedarLocalEngine` | In-process via `cedarpy` | `cedar` |
| `RegoLocalEngine` | In-process via `regopy` | `rego` |
| `AVPPolicyEngine` | AWS Verified Permissions | `aws` |
| `MockPolicyEngine` | Static allow/deny (testing) | — |

- **`PolicyCache`**: SHA-256-keyed in-memory cache for compiled policy objects, preventing redundant compilation for local engines.

#### Identity Providers (`kest.core.identity`)

| Provider | Source |
|---|---|
| `StaticIdentity` | Explicit workload ID + Ed25519 key |
| `LocalEd25519Provider` | Auto-generated ephemeral Ed25519 keypair |
| `MockIdentityProvider` | Fixed identity (testing) |
| `SPIREProvider` | SPIRE/SPIFFE SVID via Unix socket |
| `AWSWorkloadIdentity` | AWS STS `GetCallerIdentity` |
| `BedrockAgentIdentity` | AWS Bedrock Agent invocation context |
| `OIDCIdentity` | Generic OIDC/JWT token |
| `LazySigningProvider` | Deferred key resolution wrapper |

- **`get_default_identity()`**: Auto-detects the runtime environment (SPIRE socket → AWS → fallback to ephemeral local key).

#### Decorator API (`kest.core.decorators`)

- **`@kest_verified(policy, ...)`**: Unified sync/async decorator. For each decorated call it:
  1. Resolves identity and policy engine (per-call override or global).
  2. Evaluates all `policy` names against the engine.
  3. Calculates CARTA trust score from parent passport entries.
  4. Accumulates and propagates taints (`added_taints` / `removed_taints`).
  5. Signs a `KestEntry` and appends it to the `Passport` via OTel baggage.
- Parameters: `policy`, `engine`, `identity`, `trust_evaluator`, `source_type`, `added_taints`, `removed_taints`, `trust_override`.

#### Data Models (`kest.core.models`)

- **`Passport`**: Ordered list of JWS signatures representing the execution lineage DAG.
- **`PassportVerifier`**: Verifies a Passport's cryptographic integrity end-to-end.
- **`TrustEvaluator` / `DefaultTrustEvaluator`**: Pluggable CARTA trust score propagation — weakest-link model: `(min(parent_scores) * self_score) // 100`.
- **`BaggageManager`**: Packs and unpacks `Passport` + `PolicyCache` claim-checks into/from OTel baggage headers. Supports large passport chunking via a shared claim-check store.
- **`ORIGIN_TRUST_MAP`**: Base trust scores keyed by `origin` (e.g. `"internal"→100`, `"internet"→10`). `SOURCE_TRUST_MAP` retained as a backward-compat alias.

#### Distributed Propagation (`kest.core.ext`)

- **`KestMiddleware`**: FastAPI/ASGI middleware. Extracts incoming `baggage` headers and restores the Kest lineage context for downstream `@kest_verified` calls.
- **`KestHttpxInterceptor`**: HTTPX transport wrapper that injects the current Kest baggage into outgoing requests, enabling automatic OBO (on-behalf-of) chain propagation.

#### Telemetry (`kest.core.telemetry`)

- `configure_telemetry()`: One-call OTLP setup (traces + metrics) for the SPIRE/OPA lab environment.

#### Bundled Policy Library (`kest.core.policies`)

Ready-to-load Cedar and Rego policy files for classical access control models:

| Policy | Cedar | Rego |
|---|---|---|
| Bell-LaPadula (MLS read/write) | ✓ | ✓ |
| Biba (integrity confinement) | ✓ | ✓ |
| Brewer-Nash (Chinese Wall) | ✓ | ✓ |
| Clark-Wilson (integrity guards) | ✓ | ✓ |
| Goguen-Meseguer (non-interference) | ✓ | ✓ |
| Financial transaction limits | ✓ | ✓ |
| Security clearance enforcement | ✓ | ✓ |

#### CLI (`kest.cli`)

- **`kest-viz`**: ASCII/Rich tree renderer for visualizing the Merkle DAG lineage of a serialized `Passport`.

### 🧪 Test Suite

- **Unit tests** co-located with source (`_test.py` suffix), covering all engines, identity providers, models, and decorator logic.
- **`rego_engine_test.py`**: 12 dedicated tests for `RegoLocalEngine` including allow/deny, caching, multi-policy, and invalid Rego handling.
- **`policies/`**: Per-policy test files for all 5 formal access-control models (Bell-LaPadula, Biba, Brewer-Nash, Clark-Wilson, Goguen-Meseguer), each tested against both Cedar and Rego backends.
- **`robustness_test.py`**: Hypothesis-based property tests for trust score propagation and taint accumulation.
- **`matrix_test.py`**: Cross-engine matrix tests verifying consistent allow/deny decisions between `CedarLocalEngine` and `RegoLocalEngine` for equivalent policies.
- **`integration_test.py`**: Full decorator-to-passport round-trip tests with mock identity and engines.

### 🏗️ kest-lab Showcase (`showcase/kest-lab`)

A fully orchestrated Docker Compose environment for live integration testing:

- **Services**: SPIRE Server/Agent, OPA, Keycloak (OIDC), Jaeger (OTel), OpenTelemetry Collector, `hop1`/`hop2`/`hop3` FastAPI microservices.
- **OBO Delegation**: Multi-hop Merkle chain across 3 services via `KestMiddleware` + `KestHttpxInterceptor`.
- **Cedar ABAC**: Live Cedar policy enforcement with entity graphs.
- **SPIRE Attestation**: Workload attestation via Unix socket inside Docker.
- **Keycloak E2E**: OIDC JWT token issuance and validation across hops.
- **Tests**: `e2e_test.py`, `test_cedar_abac.py`, `test_keycloak_e2e.py`, `test_opa_enforcement.py`, `test_taints_live.py`, `test_otel_propagation.py`, `live_spire_test.py`.

### 🔧 Monorepo & CI/CD

- **`moon` task runner**: Root `moon.yml` orchestrates all polyglot tasks across `kest-core-python`, `kest-core-rust`, `kest-lab`, and `website` projects.
- **`proto` toolchain manager**: Pins Python, Rust, Node, and Bun versions via `.prototools`.
- **CI** (`ci.yml`): `proto install` → `moon run kest-core-python:test` → Coveralls on every push/PR.
- **Deploy Site** (`deploy-site.yml`): Publishes docs to `stable/` and `v0.3.0/` subfolders on `gh-pages` on merge to `main`.
- **Preview Site** (`preview-site.yml`): Publishes ephemeral docs to `preview/<branch>/` on pull requests.
- **Pages Index** (`gen-pages-index.sh`): Auto-generates a root `index.html` splash page listing all deployed versions and live previews.

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
