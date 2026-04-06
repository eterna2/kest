# Kest Toolkit: Human Developer Guide

Welcome to the Kest toolkit. This repository is a distributed Zero Trust architecture designed to solve the **Secret Zero** problem and enforce high-fidelity execution lineage across polyglot microservices via Cryptographic Merkle DAGs, SPIFFE, and OPA/Cedar.

While this codebase is highly optimized for AI-agent collaboration (see [AGENTS.md](AGENTS.md)), this guide is tailored specifically for human developers.

## 🛠 Prerequisites

Ensure you have the following tools installed:
- **[proto](https://moonrepo.dev/proto)**: Our multi-language toolchain manager.
- **Docker & k3d**: Required for running the showcases in `showcase/`.

## 🚀 Getting Started

1. **Install Proto**:
   ```bash
   curl -fsSL https://moonrepo.dev/install/proto.sh | bash
   ```

2. **Provision the Toolchain**:
   ```bash
   # Install moon, uv, bun, node, and python as defined in .prototools
   proto install
   ```

3. **Initialize the Environment**:
   ```bash
   # Sync global documentation from Context Hub (chub)
   proto run moon -- :sync-docs
   ```

2. **Run Tests**:
   ```bash
   # Run tests for a specific library (e.g., kest-core-python)
   proto run moon -- kest-core-python:test
   ```

3. **Format & Lint**:
   ```bash
   # Apply standard formatting and linting rules
   proto run moon -- kest-core-python:format
   proto run moon -- kest-core-python:lint
   ```

## 📂 Repository Structure

Our monorepo follows a strict organizational pattern to ensure modularity and clarity:

- **`libs/`**: Core toolkit libraries. Each is isolated by feature and implementation language (e.g., `libs/kest-core/python/`).
- **`showcase/`**: Polish end-to-end demonstrations. These are NOT for raw development, but for showing how the toolkit works in real environments (Docker, k3d).
- **`website/`**: The documentation source (MkDocs). Hosted as GitHub Pages.
- **`scratchpad/`**: A git-ignored directory for your local ad-hoc testing, scripts, and temporary notebooks.

## 🤖 Working with AI Agents

This repository is "Agent-Native." When using AI IDEs (Cursor, Windsurf, or Antigravity), the agents will automatically reference:
- [AGENTS.md](AGENTS.md): The primary instruction set for AI assistants.
- [.agents/](.agents/): A native plugin directory containing skills and workflows the AI will use to help you.

Feel free to collaborate with your AI agent of choice; they have been provided with the same architectural principles you see here.

## 📜 Principles & Standards

Before contributing, please review our [Core Architectural Principles](.agents/skills/principles/SKILL.md). These govern how we handle transparency, failure scenarios, and modular boundaries.

### Transparency Requirement
Every library must include documentation detailing its supported scenarios, edge cases, and explicit failure decisions.

---
*For licensing information, see the [LICENSE](LICENSE) file.*
