# Contributing to Kest

Thank you for your interest in contributing to the Kest toolkit. This document outlines the **Ways of Working** and **High-Level Principles** that govern the entire monorepo.

---

## 1. Architectural Principles

Our architecture is built on a foundation of transparency, simplicity, and portability. Every contribution MUST adhere to these non-negotiable principles:

- **KISS (Keep It Simple, Stupid)**: Favor simple, readable logic over cleverness.
- **Single Responsibility (SRP)**: Each component, function, or class should do exactly one thing well.
- **Dependency Injection (DI)**: Rely on injecting dependencies (telemetry, storage, policy engines) rather than hardcoding them.
- **Decoupling**: Separate domain logic from presentation or integration details (e.g., FastAPI, Keycloak).
- **Test-Driven Development (TDD)**: Write tests BEFORE logic. All unit tests MUST be co-located with the source code.

---

## 2. Ways of Working (Monorepo)

### Universal Task Runner
We use **[Moonrepo](https://moonrepo.dev/)** as the universal task orchestrator. It ensures consistent commands across all languages.

- **Sync/Install dependencies**: `moon run :install`
- **Run Tests**: `moon run :test`
- **Lint Code**: `moon run :lint`
- **Format Code**: `moon run :format`

### Global Repository Layout
The toolkit is organized into specific partitions:
- `libs/`: Highly reusable core logic, split by feature and language.
- `showcase/`: E2E demonstrations and deployable environments (e.g., Docker, k3d).
- `website/`: Documentation and project guides.
- `.agents/`: Shared intelligence for AI agents (standards, skills, workflows).

---

## 3. Standards Registry

While our principles are global, technical standards (linting, formatting, testing frameworks) vary by language. Refer to the specific guides below:

| Domain | Language/Tool | Standards Reference |
| :--- | :--- | :--- |
| **Core Libraries** | Python | [`libs/kest-core/python/CONTRIBUTING.md`](./libs/kest-core/python/CONTRIBUTING.md) |
| **Documentation** | MkDocs | [`website/CONTRIBUTING.md`](./website/CONTRIBUTING.md) |
| **Integrations** | TS (Future) | *Planned* |

---

## 4. Human & AI Collaboration

This repository is designed for seamless collaboration between human developers and AI coding assistants.

- **AI Standards**: We maintain machine-readable standards in [`.agents/skills/`](./.agents/skills/). 
- **Agent Skill-Set**: AI agents (Antigravity, Cursor, etc.) use these skills to ensure architectural consistency. Humans are encouraged to read these skills to understand the "Shared Brain" of the project.
