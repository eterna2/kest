# The Eight Immutable Design Principles

Kest is governed by eight immutable, non-negotiable design principles. They are the constitution of the framework — every API, every data structure, and every edge-case decision traces back to one of these tenets. An implementation that violates any of them cannot call itself conformant.

## P1 — Identity is the Perimeter

> There are no API keys, no static secrets, and no network segment-based trust. Every actor must prove its identity **cryptographically** before participating.

Traditional security relies on what you *have* — an API key, a token, a password. These are all instances of the **Secret Zero problem**: to access a secret, you need a secret. Kest eliminates this recursion entirely. Identity is established through **platform attestation** (SPIFFE/SPIRE, AWS IAM, OIDC), where the infrastructure itself vouches for the workload's identity based on kernel-level evidence — PID namespace, cgroup, instance metadata — not shared secrets.

This principle manifests in the `IdentityProvider` interface (§5.1 of the spec). Whether you use `SPIREProvider`, `AWSWorkloadIdentity`, or `OIDCIdentity`, the contract is invariant: prove who you are, or you cannot sign.

## P2 — Lineage Over Assertion

> Trust requires a **cryptographically verified chain of custody** that covers the entire execution path — not just the immediate caller.

A service calling another service with a valid token is not sufficient. What if the token was obtained by a compromised upstream? Kest requires every node in the chain to be accounted for. The **Passport** (§4.4) carries the entire execution history as a Merkle-linked chain of JWS signatures. Each entry's `parent_ids` field contains the SHA-256 hash of the *previous* JWS, creating a tamper-evident chain where altering any past entry breaks every subsequent hash.

## P3 — Non-Fungible Audit

> If any prior entry is altered, every subsequent hash breaks. No compromised node can forge, reorder, or silently drop audit records.

Traditional logs are fungible — they can be silently modified, dropped, or reordered after the fact. Kest audit entries are cryptographically bound to their predecessors. Each `KestEntry` is signed as a JWS (RFC 7515) with the payload canonicalized per RFC 8785, and its hash becomes the `parent_ids` of the next entry. This is the same principle that makes blockchain tamper-evident, applied to execution lineage instead of transactions.

## P4 — Fail-Secure by Default

> Any failure mode — network timeout, malformed JSON, missing identity, unreachable policy sidecar — **MUST** result in denial of execution.

There are no optimistic assumptions. If the policy sidecar is unreachable, the answer is **deny**, not "proceed and log a warning." If the identity provider is unavailable, the answer is **halt**, not "sign with a stub key." This is encoded in every error path of the Verification Hook (§5.8). The alternative — allowing degraded-but-permitted execution — would create exactly the class of exploits that Zero Trust aims to eliminate.

## P5 — Open Standards, Not Proprietary Transport

> Kest does not invent new wire protocols. It builds on W3C Trace Context, W3C Baggage, OpenTelemetry, RFC 7515 (JWS), RFC 8785 (JCS), and SPIFFE.

Every component of Kest's transport, serialization, and observability layer is a ratified open standard. Context propagation uses W3C Baggage headers. Signatures use JWS compact serialization. Canonicalization uses JSON Canonicalization Scheme. Telemetry uses OpenTelemetry spans. This means Kest integrates with any observability stack, any HTTP framework, and any service mesh that supports these standards — without vendor lock-in.

## P6 — Polyglot Core, Language-Agnostic Contracts

> Critical path operations MUST be implementable in any language that can produce byte-identical results.

The Kest specification (§13) is written so that an independent team can implement a fully conformant library in Go, Java, TypeScript, or Rust without consulting the Python reference implementation. The critical requirement is **determinism**: RFC 8785 canonicalization of the same JSON object must produce identical bytes in every language. SHA-256 of the same JWS string must produce the same hex digest. Integer trust-score arithmetic must use floor division, not floating-point.

The Python reference implementation achieves this by delegating RFC 8785 canonicalization and Ed25519 signing to a Rust core (`kest-core-rs`) exposed via PyO3 bindings — the same Rust code can be compiled to WASM for browser-based implementations.

## P7 — Sidecar for Policy, Not Inline Compilation

> Kest does not compile Rego or Cedar at runtime. Policy evaluation is delegated to a co-located sidecar.

Policy languages evolve independently of application code. By delegating evaluation to a sidecar (OPA at `localhost:8181`, Cedar Agent at `localhost:8180`), Kest achieves clean separation between the *what* (policy rules) and the *how* (application logic). Policy updates propagate without redeploying applications. The `PolicyEngine` interface (§5.2) abstracts this delegation — from the application's perspective, it's a simple `evaluate()` call regardless of the backend.

## P8 — Dependency Injection for Extensibility

> All external dependencies — IdentityProvider, PolicyEngine, TrustEvaluator, CacheProvider — are injected at configuration time.

The core framework never hardcodes instantiation of these components. This enables:
- **Testability** — inject `MockPolicyEngine` and `MockIdentityProvider` for unit tests.
- **Multi-environment deployment** — use `SPIREProvider` in production, `LocalEd25519Provider` in development, `OIDCIdentity` in CI.
- **Future extensibility** — new policy engines, identity platforms, or trust models can be added without modifying core code.

This is the `configure()` function (§2.10): set your engine, your identity, and your cache once at startup, and every `@kest_verified` call uses them automatically.

---

*These principles are not guidelines — they are invariants. The rest of the specification, the implementation, and the test suite exist to enforce them.*
