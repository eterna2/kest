# Kest Toolkit Changelog

The Kest framework operates as a polyglot monorepo. As per our architectural guidelines, we do not maintain a single monolithic changelog at the root.

All significant structural shifts, dependency updates, and feature additions are documented natively within the sub-project where they occurred.

Please refer to the specific changelog for the scope you are investigating:

- 🐍 **[Kest Core (Python) Changelog](libs/kest-core/python/CHANGELOG.md)**: Details the pure Python logic, telemetry interception, `@kest_verified` implementations, and underlying identity providers.
- 🐳 **[Kest Lab (Showcase) Changelog](showcase/kest-lab/CHANGELOG.md)**: Details modifications to the zero-trust Docker environment, component version bumps (e.g. OPA, SPIRE), and integration tests.

> For structural framework design justifications and active gotchas, refer to `spec/learnings/v0.3.0/LEARNINGS.md`.
