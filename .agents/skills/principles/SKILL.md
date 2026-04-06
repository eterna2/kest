---
name: principles
description: >
  Core architectural principles governing the design, layout, and execution of the Kest toolkit.
  Strictly reference these principles before creating new components or refactoring.
---
# Core Architectural Principles

## Overview
These principles govern the design, layout, and execution of the Kest global toolkit. As an AI Agent, you must strictly reference and follow these principles before making structural or design decisions.

## 1. Global Toolkit Pattern
The repository is modular. Every package lives in `libs/<feature>/<language>` and must be independently testable and deployable. Packages do not cross-pollinate directly outside of explicit dependency declarations.

## 2. Transparency & Specification-First
Transparency is mandatory for all operations:
- **Design & Planning**: Every library must have a design document or specification detailing *how* it will be used, the different scenarios it supports, and edge cases. **This document must be co-located with the source code** (e.g., `DESIGN.md` in the package root).
- **Explicit Failure Scenarios**: We must document *all* possible failure scenarios and record our design decisions on how we handle them (e.g., "we support/fix this", or "we will not support this intentionally").
- **Version Control**: All design, plan, and usage documentation must be version-controlled in the repository. (Execution logs remain private/local).

## 3. Strict Showcase Segregation
The `showcase/` partition is strictly for deployable or runnable demonstrations (e.g., Docker environments, k3d clusters). Demos must be polished and instructional.

## 4. Test-Driven & Co-Located
Tests reside immediately alongside the logic (`_test.py`), except for extensive integration/E2E tests which belong in a dedicated test suite or showcase.

## 5. Single Responsibility (SRP) & KISS
Keep library boundaries small and focused. Favor readability over cleverness.

## 6. Agnostic Core
Core domain logic must not rely on presentation details (e.g., FastAPI, Keycloak). Integrations belong in explicit `ext` (extension) packages.

## 7. Isolated Ad-Hoc Testing
Ad-hoc scripts and internal scratchpads must be isolated in the `.gitignore`d `/scratchpad/` directory. They must not pollute the main repository. Proper examples meant for teaching will eventually live in version-tracked directories.

## Extended Knowledge (Deep Context)
To keep this prompt concise, deeper context is stored locally. If you need explicit examples or supplemental context regarding principles, use your `list_dir` or `view_file` tools to explore the `examples/` and `resources/` subdirectories in this skill folder.
