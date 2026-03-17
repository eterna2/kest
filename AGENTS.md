# Antigravity Agent Instructions for Kest

This document outlines the strict development environment, tooling, and architectural rules for working on the `kest` repository. 

## Development Environment & Tooling
* **Package Manager:** Use `uv` strictly. Do not use `pip` or `poetry` directly for dependency resolution.
* **Linter & Formatter:** Use `ruff` for linting and formatting. Ensure code is strictly formatted via `ruff check` and `ruff format`. You MUST run the pre-commit hook before committing any code (e.g. `uv run pre-commit run --all-files`).
* **Tests:** Use `pytest` for all unit and integration testing.
* **Imports:** Use `isort` styling (enforced out of the box by `ruff` with the `I` rule enabled).
* **CI/CD:** The package will be published to PyPI via GitHub Actions.

## Architectural Principles
1. **Test-Driven Development (TDD):** Tests MUST be written *before* the domain logic. Ensure failing tests are generated according to the specification before executing on the source code.
2. **Testing Philosophy:** Tests should be pure and simple. Avoid trivial tests. Mocking is ONLY permitted for asserting inputs passed to external systems. Unit tests MUST be co-located with the code they test, using the `_test.py` suffix. Only end-to-end or integration tests should reside in the `tests/` directory.
3. **KISS Pattern:** Keep logic simple and readable.
4. **Single Responsibility Principle (SRP):** Classes and functions must do exactly one thing.
5. **Dependency Injection (DI) & Inversion of Control:** Rely on injecting dependencies (e.g. `TelemetryExporter`, `EnvironmentCollector`, `OpaEngine`) rather than hardcoding instantiations within domain logic.
6. **Decoupling:** Separate domain logic completely from presentation and integration logic.

## Project Structure
The `kest` library is split into three strict boundaries to ensure appropriate coupling:
1. **Core Domain (`src/kest/core`):** Pure Python logic. Models, cryptography, hash bindings, and interfaces. Contains no framework-specific or presentation logic.
2. **Presentation/Wrappers (`src/kest/presentation`):** The external APIs developers interact with, e.g. the `@kest_verified` decorator, which wires together the core domain and injected dependencies. 
3. **Extras (`src/kest/cli`):** Tools like the Pyvis CLI inspector. These are strictly *optional* dependencies defined in `pyproject.toml` `[project.optional-dependencies]`.
4. **Examples (`examples`):** Sample end-to-end flows.
