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
