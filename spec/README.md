# Kest Specification

This folder is the canonical home for all versioned Kest specification documents.
Each revision is a self-contained, immutable document.

## Versions

| Version | File | Status | Published |
|---|---|---|---|
| **v0.3.0** | [SPEC-v0.3.0.md](./SPEC-v0.3.0.md) | ✅ Current | 2025 |

## Rendered Documentation

The latest specification is rendered and served at:

> **[eterna2.github.io/kest → Design → Kest Specification v0.3.0](https://eterna2.github.io/kest/)**

## Conventions

- Each new specification revision gets its own file: `SPEC-vX.Y.Z.md`.
- Older revisions are **never modified** once published — open a new versioned file for changes.
- The website `sync-spec` script in `website/scripts/sync-spec.sh` must be updated to point to the latest revision when a new version is published.
- The `website/moon.yml` build input must also be updated to track the new file for cache invalidation.

---

## Implementation Learnings

> **For AI agents and engineers:** Before touching any implementation file, read the `learnings/` subdirectory for the version you are working on.

The `learnings/` directory captures **agent-discovered runtime findings** that the spec does not cover: bugs, spec deviations, production gotchas, Cedar/OPA quirks, performance cliffs, and lab workarounds.

| Version | Learnings File | Contents |
|---|---|---|
| **v0.3.0** | [learnings/v0.3.0/LEARNINGS.md](./learnings/v0.3.0/LEARNINGS.md) | Policy cache collision bug, compressed baggage variant, GIL contention cliff, Cedar policy naming, lab infrastructure gotchas |

**When to write a learning:**
- You fix a non-trivial bug — document it in the relevant `LEARNINGS.md`.
- You discover the spec is silent on something important — document the deviation.
- You find a performance cliff or security risk — document it under §6 or §9 of LEARNINGS.
- You hit a frustrating lab/test issue more than once — document it under §7 or §10.

**Never modify a published spec file** (e.g., `SPEC-v0.3.0.md`). Put corrections and clarifications in the learnings document instead.

