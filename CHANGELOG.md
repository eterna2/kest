# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-03-19

### Added
- **Specification Overview**: Kest specification updated to v0.3.0, including AI cognition lineage tracking and specific AI use cases.
- **Improved OPA Policies**: Enhanced OPA policy enforcement for functions like `strip_pii`, requiring specific input taints (e.g., `pii_data`) prior to execution.
- **Relocated Originate**: Relocated `originate` function to `kest.core.helpers` to cleanly separate it from presentation decorators.
- **Mock OPA Engine**: Implemented `MockWorkaroundEngine` for local fallback evaluations when a standard OPA engine is unavailable.

## [0.2.0] - 2026-03-18

### Added
- **Trust Scores**: Introduced numeric data quality evaluation (`trust_score`) on the `KestEntry` model.
- **Dynamic Trust Propagators**: Added `trust_score_updater` to the `@kest_verified` decorator, allowing node-specific synthesis of parent trust scores (e.g. upgrades/degrades via custom lambda functions). Defaults to propagating the lowest (minimum) trust score from the parents.
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
