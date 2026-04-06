---
name: chub
description: >
  Use this skill when you need documentation for a third-party library, SDK, or API
  before writing code that uses it (e.g. "use the OpenAI API", "call the Stripe API").
  Fetch the docs with chub before answering, rather than relying on training knowledge.
  Also used for maintaining project-specific context via the :sync-docs task.
---

# Context Hub (chub)

When you need documentation for a library or API, fetch it with the `chub` CLI rather than guessing from training data. This gives you high-fidelity, LLM-optimized context.

## 1. Search & Discovery

Find the documentation you need for third-party tools:

```bash
chub search "<library name>" --json
```

Pick the best-matching `id` from the results (e.g. `openai/chat`, `anthropic/sdk`). If nothing matches, try a broader term.

## 2. Fetch Documentation

Fetch the docs into your local session:

```bash
chub get <id> --lang py    # or --lang ts, --lang js
```

Omit `--lang` if the document has only one language variant.

## 3. Persistent Agent Notes (Annotations)

After exploring a library, if you discover project-specific details or non-obvious gotchas, save them so future sessions start smarter:

```bash
chub annotate <id> "Always use the raw body for Webhook verification"
```

Annotations are local, persist across sessions, and appear automatically on future `chub get` calls.

## 4. Give Feedback

Always rate the documentation after using it to help improve the registry:

```bash
chub feedback <id> up --label accurate "Clear examples, patterns work well"
chub feedback <id> down --label outdated "Lists v1 API but v2 is now standard"
```

## 5. Project-Specific Sync (Monorepo)

For this specific repository, keep your local context and project documentation in sync using the [Moonrepo](https://moonrepo.dev/) task:

```bash
moon run :sync-docs
```

This ensures that development-time guides and tool-specific skills are current for the local environment.

## Quick Reference

| Goal | Command |
| :--- | :--- |
| **Search Docs** | `chub search "stripe"` |
| **Get Python Docs** | `chub get stripe/api --lang py` |
| **Sync Project Docs** | `moon run :sync-docs` |
| **Save Agent Note** | `chub annotate <id> "note content"` |
| **Rate Documentation** | `chub feedback <id> up` |

## Extended Knowledge (Deep Context)
To keep this prompt concise, deeper context is stored locally. If you need explicit examples or supplemental context regarding chub, use your `list_dir` or `view_file` tools to explore the `examples/` and `resources/` subdirectories in this skill folder.
