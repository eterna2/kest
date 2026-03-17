# Changelog

All notable changes to this project will be documented in this file.

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
