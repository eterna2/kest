---
name: testing
description: >
  Standard software engineering and testing practices (TDD, SRP, DI) for library development.
  Reference this skill before writing tests or designing new logic.
---
# Testing & Software Practices Skill

## Overview
Standard software engineering and testing practices for library development.

## Test-Driven Development (TDD)
- Write tests *before* the implementation.
- Focus on the interface and expected behavior first.
- Use `pytest` for Python and `bun test` for TypeScript.

## Property-Based Testing
- Use `Hypothesis` in Python to generate edge cases and verify invariants.
- Focus on "state-based" testing for core domain logic.

## Single Responsibility Principle (SRP)
- Each class or function should have one reason to change.
- Keep components focused and modular.

## KISS (Keep It Simple, Stupid)
- Favor readability over cleverness.
- Maintain a clear and simple domain model.

## Dependency Injection (DI)
- Inject dependencies (telemetry, storage, etc.) rather than hard-coding.
- This allows for easier testing and mocking.

## Extended Knowledge (Deep Context)
To keep this prompt concise, deeper context is stored locally. If you need explicit examples or supplemental context regarding testing, use your `list_dir` or `view_file` tools to explore the `examples/` and `resources/` subdirectories in this skill folder.
