# Gemini Context for Kest

This file provides project-specific context and skills for the Gemini CLI in the Kest monorepo.

> [!IMPORTANT]
> You MUST strictly adhere to the foundational engineering, architectural, and toolchain instructions defined in [AGENTS.md](./AGENTS.md). That document is the primary source of truth for all AI-powered development within this repository.

## 🛠 Toolchain & Rules
- **Toolchain Manager**: `proto` (configured in `.prototools`). It manages specific versions for:
  - `moon` (Task Runner)
  - `uv` (Python Manager)
  - `node` & `bun` (JavaScript/TypeScript)
  - `rust` & `wasm-pack` (WebAssembly/Systems)
- **Python Manager**: `uv` (strict adherence, no `pip`/`poetry` as per `AGENTS.md`)
- **Task Runner**: `moon` (orchestrates all polyglot tasks, configured in `moon.yml` and `.moon/*.yml`)

> [!IMPORTANT]
> Detailed rules for toolchain management and workflows are modularized in:
> - [.agents/rules/toolchain.md](.agents/rules/toolchain.md)
> - [.agents/rules/workflows.md](.agents/rules/workflows.md)

## 🤖 Workflows & Automation
AI Agents MUST prioritize established workflows in `.agents/workflows/` and `moon` tasks over ad-hoc commands. 

### Key `moon` Tasks:
- `moon run setup-gemini-cli`: Provisions local skills and Superpowers.
- `moon run sync-docs`: Synchronizes documentation via `chub`.
- `moon run serve-site`: Starts the documentation server locally.
- `moon run gemini`: Starts a project-aware Gemini session.
- `moon run install-awesome-skills`: Locally installs 1300+ community agent skills.
- `moon run kest-core-python:test`: Runs unit tests for the Python toolkit core.
- `moon run kest-core-python:test-live`: Runs live integration tests within `kest-lab`.
- `moon run kest-lab:up` / `kest-lab:down`: Direct management of the integration lab.

> [!IMPORTANT]
> **Mandatory Verification**: Every functional change to the core library MUST pass both the unit tests (`test`) and the live integration tests (`test-live`) as defined in `AGENTS.md`. Use the `@verify` workflow to automate this complete cycle before finishing any code-related task.

Use `@brainstorming` and `@writing-plans` for all significant engineering tasks as mandated in `AGENTS.md`.

## 📐 Core Design & Planning
> [!IMPORTANT]
> The source of truth for the core toolkit design and its implementation path is located in:
> - **Design Document**: [libs/kest-core/DESIGN.md](libs/kest-core/DESIGN.md)
> - **Implementation Plan**: [libs/kest-core/PLAN.md](libs/kest-core/PLAN.md)
> 
> All related development MUST reference and align with these documents. If any changes occur during implementation, these documents MUST be updated accordingly to reflect the current state and future path.

## 🏗 Architectural Principles
Refer to the `@principles`, `@architecture`, and `@chub` skills for foundational mandates, design guidance, and API specifications. 
As defined in [AGENTS.md](./AGENTS.md):
1. **Test-Driven Development (TDD)**: Write tests BEFORE domain logic.
2. **Testing Philosophy**: Pure and simple. Mocking ONLY for external system inputs. Unit tests co-located with `_test.py` suffix.
3. **KISS & SRP**: Single responsibility, high readability.
4. **Dependency Injection (DI)**: Inject dependencies; avoid hardcoded instantiations.
5. **Decoupling & Portability**: Core logic MUST be language-agnostic and decoupled from presentation/integration (see `@architecture`).
6. **API Specifications**: Use `@chub` to fetch high-fidelity, LLM-optimized documentation for third-party libraries and APIs before implementation.

## 📂 Project Structure
- `libs/kest-core/python`: Pure Python core logic.
- `showcase/`: End-to-end demonstrations (Docker, k3s).
- `.agents/skills/`: Local skill library.
- `scratchpad/`: Unversioned sandbox for testing.

## 🧠 Skills & Frameworks
We use the **Superpowers** framework and **Awesome Skills** for high-discipline software engineering. Use the `@enhance-skill` meta-skill to ingest, structure, and persist new capabilities or conventions when new knowledge is provided.

---
@.agents/superpowers/GEMINI.md
---
@.agents/skills/architecture/SKILL.md
---
@.agents/skills/principles/SKILL.md
---
@.agents/skills/chub/SKILL.md
---
@.agents/skills/enhance-skill/SKILL.md
---
@.agents/skills/awesome/docs/users/gemini-cli-skills.md
