---
trigger: always_on
---

# Toolchain Management Rules

This document defines the strict rules for toolchain management in the `kest` toolkit.

## Tooling & Maintenance
* **Toolchain Manager:** Use `proto` to manage all tool versions (`moon`, `uv`, `node`, `bun`, `python`).
* **Package Manager:** Use `uv` strictly for Python. Do not use `pip` or `poetry` directly.
* **Maintenance Requirement:** Any update to `.prototools` MUST be reflected in:
  1. `AGENTS.md`
  2. `README.md`
  3. `.agents/workflows/setup-dev-env.md`
  4. `.prototools` (Source of Truth)
