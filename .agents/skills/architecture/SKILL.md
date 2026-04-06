---
name: architecture
description: >
  Key principles for designing reliable, polyglot libraries. Use this skill
  when making structural or design decisions for the Kest toolkit.
---
# Library Architecture & Design Skill

## Overview
Key principles for designing reliable, polyglot libraries.

## Portability
- Design the library core (domain logic) to be language-agnostic.
- Use a common data model (e.g. JSON-based) for consistency.

## Decoupling
- Separate domain code from external dependencies.
- Use interfaces instead of direct implementations.

## Extensibility
- Design the library with hooks for future implementations and plugins.

## Performance
- Optimize the library for execution speed and low resource usage.

## Error Handling
- Use structured error responses and provide clear messages.

## Extended Knowledge (Deep Context)
To keep this prompt concise, deeper context is stored locally. If you need explicit examples or supplemental context regarding architecture, use your `list_dir` or `view_file` tools to explore the `examples/` and `resources/` subdirectories in this skill folder.
