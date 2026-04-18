# Contributing to Kest

Thank you for your interest in contributing to the Kest toolkit. This repository operates as a polyglot monorepo and employs a unified toolchain to manage everything from Python builds to Dockerized integration labs.

This document outlines the **Ways of Working**, **Toolchain Usage**, and **High-Level Principles** that govern the repo.

---

## 1. Development Environment & Toolchain

We strictly manage our development environment using `proto` and `moon` to guarantee deterministic builds across all platforms. 

- **[Proto](https://moonrepo.dev/proto)**: The foundational version manager. It manages the exact versions of the underlying tools (`moon`, `uv`, `node`, `rust`) used in this project.
- **[Uv](https://github.com/astral-sh/uv)**: The exclusive Python package manager (we do not use `poetry` or `pip` for internal package management).
- **[Moonrepo](https://moonrepo.dev/)**: The universal task orchestrator used to execute builds, tests, and environment provisioning.

### Initializing the Environment
When you clone the repository, ensure `proto` is installed on your system. 
```bash
# Install proto if you haven't already
curl -fsSL https://moonrepo.dev/install/proto.sh | bash

# Install the exact tool versions specified in `.prototools`
proto use
```

### Essential Moon Commands
The `moon` runner coordinates everything. You generally do not invoke `uv` or `docker` directly for high-level tasks.

- **`moon run kest-core-python:test`**: Run all isolated unit tests in the core Python library.
- **`moon run kest-lab:up`**: Provision the secure Docker sandbox (SPIRE, OPA, Keycloak, etc.).
- **`moon run kest-core-python:test-live`**: Run live integration tests against the `kest-lab` sandbox. (This runs `kest-lab:up` automatically).
- **`moon run sync-docs`** & **`moon run serve-site`**: Synchronize markdown files and spin up the local Next.js documentation site.

> **Requirement**: Every functional change to the core library MUST pass both the unit tests (`test`) and the live integration tests (`test-live`) prior to merging a pull request.

---

## 2. Organization of the Project

The monorepo is partitioned functionally to strictly separate pure logic from presentation and integration layers:

- **`libs/kest-core/python`**: The core framework. Contains pure Python logic, models, cryptography, and OpenTelemetry bindings. It contains absolutely NO framework-specific or presentation logic (e.g., no FastAPI/Flask code).
- **`showcase/`**: End-to-end demonstrations. This includes `kest-lab` (our zero-trust Docker integration lab) and other deployment examples.
- **`website/`**: The Next.js repository containing the official `eterna2.github.io/kest` documentation.
- **`.agents/`**: Contains shared intelligence, workflows, and strict rules for AI agents (Gemini, Cursor) operating within the repository.
- **`spec/`**: Home to the immutable Kest structural specifications (e.g., `SPEC-v0.3.0.md`) and the dynamic `learnings/` directory which documents known gotchas, spec deviations, and production risks.

---

## 3. General Developer Guide & Architectural Principles

Our architecture is built on a foundation of transparency, simplicity, and portability. Every contribution MUST adhere to the following principles:

1. **Test-Driven Development (TDD)**
   - Tests MUST be written *before* the domain logic.
   - Unit tests must be co-located with the source code using the `_test.py` suffix.
   - Mocking is ONLY permitted for asserting inputs passed to external boundaries (e.g., HTTP clients, file system). Do not mock internal domain logic.
2. **KISS & Single Responsibility (SRP)**
   - Favor simple, readable logic over clever abstractions. Each component must do exactly one thing.
3. **Dependency Injection (DI)**
   - Rely on injecting dependencies natively (e.g. `OPAPolicyEngine`, `OAuthCliProvider`) rather than hardcoding instantiations deep inside domain logic.
4. **Decoupling**
   - Separate domain logic completely from presentation and integration logic.
5. **Absolute Python Imports**
   - Use absolute imports (e.g., `from kest.core.context import ...`) instead of relative imports (`from .context import ...`) to maintain clarity when dealing with namespace packages.
6. **Record Architecture Learnings**
   - **Crucial**: Before beginning any task on `kest-core`, you must read the current `spec/learnings/<version>/LEARNINGS.md`. If you fix a non-trivial bug or deviate from the spec, you must append your findings to the `LEARNINGS.md` document, ensuring future developers (or AI agents) do not make the same mistake.

---

## 4. Human & AI Collaboration

This repository is optimized for autonomous and AI-assisted development, natively integrating with the [Gemini CLI](https://geminicli.com) and the **Superpowers** workflow framework.

If you are using AI to assist in your contributions:
1. Run `moon run setup-gemini-cli` to install standard multi-agent orchestration skills to your local `.agents` root. 
2. Use `moon run gemini` to boot the assistant with active context.
3. Enforce the use of the `@verify` workflow before submitting changes to ensure automated testing standards are strictly met.
