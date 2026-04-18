# Gemini Context for Kest

This file provides the project-specific configuration for the Gemini CLI (`geminicli.com`) operating in the Kest monorepo.

> [!IMPORTANT]
> **Source of Truth**: You MUST strictly adhere to the foundational engineering, architectural, and toolchain instructions defined in [AGENTS.md](./AGENTS.md). That document governs all autonomous logic, TDD enforcement, and monorepo boundaries.

## ♊ Gemini-Specific Setup & Workflows

1. **Provision Skills**: Run `moon run setup-gemini-cli` to install all necessary local skills and Superpowers into your `.agents` environment. This command exposes over 1,300+ capabilities to your operating context.
2. **Standard Boot**: Use `moon run gemini` to start a session within the project context securely.
3. **Skill Loading**: All Superpowers and Awesome Skills are automatically injected at runtime via the inclusions at the bottom of this file.

## 🚀 Key Orchestration Reminders
To interact effectively within the monorepo bounds dictated by `AGENTS.md`, rely heavily on these specific tasks:
- `moon run sync-docs` & `moon run serve-site`: Modifying documentation securely mapping the Next.js and python documentation sets.
- `moon run kest-core-python:test-live`: Mandatory integration testing inside the Docker zero-trust lab. Use the `@verify` workflow skill to orchestrate validations safely.
- Use `@brainstorming` to map out structural modifications before attempting changes on `libs/kest-core/`.
- Use the `@chub` skill prior to implementing new multi-agent components from external modules.

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

