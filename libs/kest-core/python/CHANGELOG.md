# Changelog

All notable changes to this project will be documented in this file.

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
