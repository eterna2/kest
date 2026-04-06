# Agent Instructions for Kest (AI-Agnostic)

This document is the primary source of truth for ALL AI-powered assistants (Gemini/Antigravity, Cursor, Cline, Windsurf, etc.). It defines the strict development environment, tooling, and architectural boundaries for the `kest` toolkit. 

## 🛠 Development Environment & Toolchain
> [!IMPORTANT]
> Detailed rules for toolchain management are modularized in [toolchain.md](file:///home/eterna2/github/kest/.agents/rules/toolchain.md).
- Use `proto`, `uv`, and `moon` as the primary toolstack.

## 🤖 Workflows & Automation
> [!IMPORTANT]
> Rules for workflows are modularized in [workflows.md](file:///home/eterna2/github/kest/.agents/rules/workflows.md).
- Prioritize established workflows in `.agents/workflows/`, such as `@verify` and `@serve-docs`.

## Architectural Principles
See `.agents/skills/principles.md` for the immutable core principles regarding transparency, design consistency, and module boundaries. The following are practical implementation guidelines:
1. **Test-Driven Development (TDD):** Tests MUST be written *before* the domain logic. Ensure failing tests are generated according to the specification before executing on the source code.
2. **Testing Philosophy:** Tests should be pure and simple. Avoid trivial tests. Mocking is ONLY permitted for asserting inputs passed to external systems. Unit tests MUST be co-located with the code they test, using the `_test.py` suffix. Only end-to-end or integration tests should reside in the `showcase/` directory.
3. **KISS & SRP:** Keep logic simple and readable. Classes and functions must do exactly one thing.
4. **Dependency Injection (DI) & Inversion of Control:** Rely on injecting dependencies (e.g. `TelemetryExporter`, `EnvironmentCollector`, `OpaEngine`) rather than hardcoding instantiations within domain logic.
5. **Decoupling:** Separate domain logic completely from presentation and integration logic.
6. **Python Coding Principles:**
    - **Absolute Imports:** Use absolute imports (e.g. `from kest.core.context import ...`) instead of relative imports (e.g. `from .context import ...`) to maintain clarity and avoid issues in complex package structures.

## 🧪 Testing Workflows
> [!IMPORTANT]
> Detailed testing rules are modularized in [testing.md](file:///home/eterna2/github/kest/.agents/rules/testing.md).

This repository supports two primary testing levels, both managed via `moon`. **Both MUST pass before any code changes are committed.**

### 1. Unit Testing (Local/Host)
- **Scope:** Domain logic, core models, and pure functions.
- **Execution:** Run locally from the host environment.
- **Command:** `moon run kest-core-python:test`
- **Location:** Unit tests are co-located with the source code using the `_test.py` suffix.

### 2. Live Integration Testing (Lab/Containerized)
- **Scope:** Real identity providers (SPIRE), authorization engines (OPA/Cedar), and telemetry (OTel).
- **Execution:** Triggered from the host but **delegated to run inside the lab containers** (e.g., `hop1`). This is necessary to resolve PID namespacing/attestation requirements on shared-infrastructure environments like Docker Desktop.
- **Command:** `moon run kest-core-python:test-live` (Triggers `kest-lab:up` automatically)
- **Location:** Shared integration tests reside in `showcase/kest-lab/tests/`.

---

> [!IMPORTANT]
> **Mandatory Verification**: Every functional change to the core library MUST pass both the unit tests and the live integration tests (`test-live`). Use the `@verify` workflow to automate this complete cycle before finishing any code-related task.

## 🤖 Browser Automation & Debugging
AI agents in this repository are permitted to use browser tools for reconnaissance, UI verification, and documentation testing. To enable internal communication (CDP) and local testing, the following interfaces are implicitly trusted:
- `http://localhost:*`
- `http://127.0.0.1:*`

These permissions are codified in [.agent_allowlist](file:///home/eterna2/github/kest/.agent_allowlist) and [.agent_allowlist.json](file:///home/eterna2/github/kest/.agent_allowlist.json).

> [!CAUTION]
> **WSL2 Connectivity Note**: If the browser subagent reports `ECONNREFUSED` on port 9222, ensure that your WSL2 networking is not blocking loopback communication. In some cases, you might need to enable **mirrored networking** in your `.wslconfig`:
> ```ini
> [wsl2]
> networkingMode=mirrored
> ```

## Project Structure
The repository is a polyglot toolkit (monorepo). Libraries are split functionally:
1. **Toolkit Core (`libs/kest-core/python`)**: Pure Python logic. Models, cryptography, hash bindings, and interfaces. Contains no framework-specific or presentation logic.
2. **Presentations/Wrappers**: The external APIs developers interact with, e.g. the `@kest_verified` decorator.
3. **Showcases (`showcase/`)**: End-to-end demonstrations (Docker, k3d).
4. **Agent Skills (`.agents/skills/`)**: Contains explicit details on orchestrating the stack (Moonrepo) and maintaining system principles.
5. **Ad-hoc Testing (`scratchpad/`)**: Unversioned sandbox for intermediate testing and notebook drafts.

## Community Skills Library
This repository natively supports the [antigravity-awesome-skills](https://github.com/sickn33/antigravity-awesome-skills) library, giving AI agents access to over 1,300+ community skills.
To provision these skills into your local environment without polluting the Git repository:
1. Run `proto run moon -- :install-awesome-skills`.
2. This downloads the skills into `.agents/skills/awesome/` (which is `.gitignore`d).
3. Agents can now natively reference and trigger these skills for diverse tasks.

## Superpowers & High-Discipline Workflows
This repository integrates the [Superpowers](https://github.com/obra/superpowers) development workflow. 
*   **Optional/On-Demand**: For non-engineering tasks (brainstorming, research, project management), Superpowers are available via `.agents/superpowers/skills/` but not mandatory.
*   **Required for Software Engineering**: For pure software engineering tasks—specifically those involving new logic, refactoring, or bug fixing—the `@brainstorming` and `@writing-plans` workflows are **MANDATORY**. 
*   **TDD Enforcement**: High-discipline engineering must follow the `@test-driven-development` skill instructions to ensure reliability and maintainability.

## ♊ Gemini CLI Integration
The Kest monorepo is optimized for the [Gemini CLI](https://geminicli.com). It uses a project-specific `GEMINI.md` to provide context and integrate with local skills.

### 🚀 Setup
1. **Provision Skills**: Run `moon run setup-gemini-cli` to install all necessary local skills and Superpowers.
2. **Standard Workflow**: Use `moon run gemini` to start a session within the project context.

### 🛠 Skills Usage
- Use `@brainstorming` to refine implementation specs.
- Use `@writing-plans` for detailed design before code changes.
- All **Superpowers** and **Awesome Skills** are automatically loaded via the root `GEMINI.md`.
