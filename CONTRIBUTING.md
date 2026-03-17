# Contributing to Kest

Thank you for your interest in contributing to Kest! This guide outlines the development environment, coding standards, and architectural principles we follow.

## Development Environment

We use `uv` for dependency management and environment isolation.

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/eterna2/kest.git
    cd kest
    ```

2.  **Sync dependencies**:
    ```bash
    uv sync --all-extras --dev
    ```

3.  **Install pre-commit hooks**:
    ```bash
    uv run pre-commit install
    ```

## Coding Standards

- **Linter & Formatter**: We use `ruff` strictly. Code is validated on every commit via pre-commit hooks.
  - Run manually: `uv run ruff check .` and `uv run ruff format .`
- **Type Annotations**: All public APIs must be type-annotated.
- **Imports**: Use `isort` styling (automatically handled by `ruff`).

## Testing Philosophy (TDD)

We follow **Test-Driven Development (TDD)**:
1. Write a failing test for the new feature or bug fix.
2. Run `pytest` to ensure it fails.
3. Implement the minimal logic required to pass the test.
4. Refactor as needed while keeping tests green.

### Running Tests
```bash
uv run pytest
```

### Test Co-location
- Unit tests MUST be co-located with the code they test, using the `_test.py` suffix (e.g., `core/models.py` and `core/models_test.py`).
- Integration and end-to-end tests reside in the `tests/` directory.

## Architectural Principles

1.  **KISS (Keep It Simple, Stupid)**: Favor simple, readable logic over over-engineered solutions.
2.  **Single Responsibility (SRP)**: Each class/function should do one thing well.
3.  **Dependency Injection (DI)**: Inject dependencies (e.g., `TelemetryExporter`, `OpaEngine`) rather than hardcoding instantiations.
4.  **Decoupling**: Separate domain logic (`src/kest/core`) from presentation logic (`src/kest/presentation`).

## Project Structure

- `src/kest/core/`: Pure Python logic, models, cryptography, and interfaces.
- `src/kest/presentation/`: External APIs (e.g., `@verified` decorator).
- `src/kest/cli/`: Optional CLI tools.
- `examples/`: End-to-end flow demonstrations and notebooks.
- `tests/`: Integration and regression tests.
