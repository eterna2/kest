# Documentation & Changelog Standards

Maintaining accurate, up-to-date documentation is critical in this multi-project monorepo. Agents MUST adhere to the following rules when altering code or features:

## 1. Synchronization Requirement
- **Always Update**: Every time there is a code update, feature addition, or architectural change, you MUST update the corresponding `README.md` and `CHANGELOG.md` in the exact project directory where the change occurred.
- **Prune Old Data**: Outdated information, guides, or deprecated features MUST be completely removed from the documentation. Do not leave stale instructions or API notes behind.

## 2. Project-Level Isolation
- Each sub-project (e.g., `libs/kest-core/python`, `showcase/kest-lab`) operates independently and MUST have its own dedicated `README.md` and `CHANGELOG.md`.
- All granular technical details, parameter definitions, and deep-dive architecture specifics must be organically documented in the **sub-project's** `README.md`.

## 3. Root Level Constraints
- The **Root Repository** `README.md` serves as the high-level entry point. It should contain the most important instructions, installation basics, and core feature overviews. 
- The Root `README.md` MUST explicitly link and point to the sub-project `README.md` files for deeper, granular details.
- The Root `CHANGELOG.md` should NOT duplicate granular bullet points from the sub-projects. Instead, the root documentation must reference and point users directly to the actual `CHANGELOG.md` living inside the individual projects (e.g. `libs/kest-core/python/CHANGELOG.md`).
