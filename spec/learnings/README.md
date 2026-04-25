# Kest Implementation Learnings

This directory captures **agent-discovered runtime learnings** for each version of Kest. These notes record bugs found, deviations from the spec, production gotchas, and design rationale that the spec itself does not repeat.

> **These are living documents.** When you discover something non-obvious — a bug, a spec gap, a performance cliff, a Cedar/OPA gotcha — write it here. Future agents should read this *before* touching a component.

## Structure

```
spec/learnings/
├── README.md              ← this file
├── v0.3.0/
│   ├── LEARNINGS.md       ← cumulative findings for the v0.3.0 Python implementation
│   └── BENCHMARK.md       ← performance benchmark notes (cross-referenced from BENCHMARK.md)
└── sandbox-v0.1.0/
    └── LEARNINGS.md       ← runtime findings for the Sandbox subsystem (SPEC-sandbox-v0.1.0.md)
```

## How to Use

1. **Before starting any task** on `kest-core/python`, read `v0.3.0/LEARNINGS.md` end-to-end.
2. **After resolving a bug or making a non-trivial architectural decision**, add an entry to the relevant section.
3. **Key subsections match spec section numbers** so you can quickly map a finding to the normative text.

## Versioning

Each new `SPEC-vX.Y.Z.md` gets its own `vX.Y.Z/` subdirectory.
When the Python implementation is updated to a new spec version, the corresponding `LEARNINGS.md` should be started from scratch (carrying forward only items still relevant). Legacy learning files are kept for reference.

## Coverage Tracking

See `v0.3.0/LEARNINGS.md` → §Spec Compliance Matrix for a quick status table of which spec requirements are fully implemented, partially implemented, or not yet implemented.
