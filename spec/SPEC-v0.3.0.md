# Kest v0.3.0 — Requirements & Specification

> **Status**: Normative  
> **Version**: 0.3.0  
> **Scope**: Cryptographic distributed execution lineage and Zero Trust policy enforcement for polyglot microservice architectures.  
> **Audience**: Implementors of the Kest library in any programming language.

> [!IMPORTANT]
> **Source of Truth** — This file (`spec/SPEC-v0.3.0.md`) is the canonical editable copy of the Kest v0.3.0 specification.  
> `website/content/design/07_kest_spec_v0.3.0.md` is **generated automatically** from this file during `bun run build` / `moon run website:build`.  
> **Never edit the website copy directly.**

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Functional Requirements](#2-functional-requirements)
3. [Non-Functional Requirements](#3-non-functional-requirements)
4. [Data Model Specification](#4-data-model-specification)
5. [Interface Specification](#5-interface-specification)
6. [Protocol & Algorithm Specification](#6-protocol--algorithm-specification)
7. [Trust Model Specification](#7-trust-model-specification)
8. [Context Propagation Specification](#8-context-propagation-specification)
9. [Policy Engine Specification](#9-policy-engine-specification)
10. [Telemetry & Audit Specification](#10-telemetry--audit-specification)
11. [Edge Case Handling](#11-edge-case-handling)
12. [Compliance Mappings](#12-compliance-mappings)
13. [Implementation Guidance](#13-implementation-guidance)
14. [Normative Standards References](#14-normative-standards-references)
15. [Reference Implementations](#15-reference-implementations)


---

## 1. Design Principles

These are the **immutable, non-negotiable** principles that govern every design decision in Kest. Any implementation that violates these principles cannot call itself conformant.

### P1 — Identity is the Perimeter

There are no API keys, no static secrets, and no network segment-based trust. Every actor in the system must prove its identity cryptographically before participating in any signed execution context. The mechanism for this proof is the **IdentityProvider** abstraction; its implementations may vary by runtime environment (SPIRE, AWS KMS, OIDC), but the contract is invariant.

### P2 — Lineage Over Assertion

An action is not trusted merely because the immediate caller is authenticated. Trust requires a **cryptographically verified chain of custody** that covers the entire execution path from its entry point. A node may not assert its own trust score; it inherits the proven history of all its ancestors.

### P3 — Non-Fungible Audit

Every execution hop produces a **JSON Web Signature (JWS)** whose payload is canonicalized per RFC 8785 and whose `parent_ids` field hashes the preceding JWS. This creates a tamper-evident Merkle DAG. If any prior entry is altered, every subsequent hash breaks. This guarantees that no compromised node can forge, reorder, or silently drop audit records.

### P4 — Fail-Secure by Default

Any failure mode — network timeout, malformed canonical JSON, missing identity, unreachable policy sidecar — MUST result in **denial of execution**, not a degraded-but-allowed path. There are no optimistic assumptions.

### P5 — Open Standards, Not Proprietary Transport

Kest does not invent new wire protocols. It builds on:
- **W3C Trace Context** (`traceparent`) and **W3C Baggage** (`baggage`) for distributed context propagation.
- **OpenTelemetry (OTel) Spans** for audit emission.
- **RFC 7515 (JWS)** for signature serialization.
- **RFC 8785 (JCS)** for deterministic canonicalization.
- **SPIFFE/SPIRE** as the reference identity control plane.

### P6 — Polyglot Core, Language-Agnostic Contracts

Critical path operations (RFC 8785 canonicalization, Ed25519 signing, SHA-256 hashing) MUST be implementable in any language that can produce byte-identical results. The reference implementation uses a Rust core (`kest-core-rs`) exposed via FFI bindings (PyO3 for Python). Any conformant implementation must produce the same canonical byte arrays for identical inputs.

### P7 — Sidecar for Policy, Not Inline Compilation

Kest does not compile Rego or Cedar at runtime. Policy evaluation is delegated to a co-located sidecar (OPA at `localhost:8181`, Cedar Agent at `localhost:8180`) or an in-process engine backed by compiled policy artefacts. The `PolicyEngine` interface abstracts this delegation uniformly.

### P8 — Dependency Injection for Extensibility

All external dependencies (IdentityProvider, PolicyEngine, TrustEvaluator, CacheProvider) are injected at configuration time. The core framework never hardcodes instantiation of these components. This enables testability (mock providers), multi-environment deployment (SPIRE in prod, StaticIdentity in CI), and future extensibility.

---

## 2. Functional Requirements

The following requirements are expressed in testable, unambiguous form. An implementation passes a requirement if and only if a test that directly encodes the stated behaviour succeeds.

### 2.1 Identity & Signing

| ID | Requirement |
|---|---|
| **F-ID-01** | A Kest implementation MUST provide an `IdentityProvider` interface with two operations: `get_workload_id() → string` and `sign(payload: bytes) → string` (JWS compact serialization). |
| **F-ID-02** | `get_workload_id()` MUST return a non-empty, globally unique string identifying the workload (e.g., SPIFFE URI, AWS Role ARN, OIDC `sub`). |
| **F-ID-03** | `sign(payload)` MUST produce a valid JWS compact serialization (`header.payload.signature`) using `EdDSA` (Ed25519) as the algorithm. The header MUST contain `{"alg":"EdDSA","typ":"JWS"}`. |
| **F-ID-04** | The signing key MUST be held only in volatile memory during the workload's lifetime. It MUST NOT be written to persistent storage or transmitted over the network. |
| **F-ID-05** | An implementation that integrates with [SPIFFE/SPIRE](https://spiffe.io/) MUST connect to the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) using whatever transport SPIRE exposes (typically a Unix Domain Socket or TCP endpoint). The specific connection parameters MUST be configurable by the operator. |

> **Informative note — ephemeral local provider:** An implementation MAY provide a `LocalEd25519Provider` that generates a fresh ephemeral Ed25519 key pair in process memory as a **development convenience** (not a production workload identity). If provided, it MUST NOT reuse keys across process restarts, and MUST emit a prominent log warning so it is never silently used in production. See §5.1.

> **Informative note — test double:** An implementation SHOULD provide a deterministic `MockIdentityProvider` (or equivalent test double) to facilitate unit testing without a real identity plane. This is a testing aid, not a Kest compatibility requirement. See §5.1.

### 2.2 Audit Entry (KestEntry)

| ID | Requirement |
|---|---|
| **F-AE-01** | Each invocation of the Verification Hook MUST produce exactly one `KestEntry` (audit entry) that is cryptographically signed and appended to the current `Passport`. |
| **F-AE-02** | The `KestEntry` payload MUST be a JSON object conforming to the schema defined in §4.1. |
| **F-AE-03** | Before signing, the payload MUST be canonicalized using RFC 8785 (JSON Canonicalization Scheme). The canonicalization MUST be byte-identical across all conformant implementations for the same input object. |
| **F-AE-04** | The `entry_id` field MUST be a [UUID v7](https://datatracker.ietf.org/doc/html/rfc9562#section-5.7) (time-ordered, per [RFC 9562](https://datatracker.ietf.org/doc/html/rfc9562)) unique to each execution event. UUID v7's millisecond-precision timestamp prefix enables natural chronological ordering of entries in storage and audit systems without secondary sorting, while remaining globally unique. UUID v4 MUST NOT be used. |
| **F-AE-05** | The `schema_version` field MUST be present and MUST contain the version string of the `KestEntry` schema used to construct this entry (e.g., `"0.3.0"`). This enables future schema evolution and backward-compatible parsing by audit tools. |
| **F-AE-06** | The `runtime` field MUST be present and MUST be an object containing at least `"name"` (the Kest-compliant library name, e.g., `"kest-python"`) and `"version"` (its semantic version string, e.g., `"0.3.0"`). This enables auditability of which implementation produced an entry and aids in cross-language compatibility diagnostics. |
| **F-AE-07** | The `operation` field MUST contain the name of the protected operation or a caller-supplied label. |
| **F-AE-08** | The `parent_ids` field MUST contain an array of SHA-256 hashes of the immediately preceding JWS compact strings in the Passport chain. For the root entry (first in a chain), `parent_ids` MUST be `["0"]`. |
| **F-AE-09** | The `trust_score` field MUST be an integer in the range `[0, 100]`. |
| **F-AE-10** | The `taints` field MUST represent the cumulative set of taint labels: `taints = (parent_taints ∪ added_taints) − removed_taints`. |
| **F-AE-11** | The `labels` map MUST include `"principal"` (the `workload_id`) and `"trace_id"` (the OTel trace ID). |
| **F-AE-12** | The `timestamp_ms` field MUST record epoch milliseconds at the time of execution entry creation. |
| **F-AE-13** | The `policy_context` object MUST be present in every `KestEntry`. It MUST record all four policy lists (`enterprise_policies`, `platform_policies`, `app_policies`, `function_policies`) as evaluated at invocation time (each may be empty). The `deviations` array MUST be present and MUST contain one entry per active deviation; it MUST be an empty array `[]` when no deviations are active. This field is part of the signed payload and MUST never be omitted, so audit tools can distinguish "no deviations applied" from "field absent — record possibly tampered". See also F-PE-12, §4.1, and §9.6. |


### 2.3 Passport (Merkle DAG)

| ID | Requirement |
|---|---|
| **F-PA-01** | A `Passport` is an ordered list of JWS compact strings representing the execution lineage. |
| **F-PA-02** | The `Passport` MUST support `serialize() → string` (JSON encoding of the JWS array) and `deserialize(string) → Passport` operations. |
| **F-PA-03** | A `Passport` with zero entries MUST be a valid, serializable object representing an empty chain. |
| **F-PA-04** | The `PassportVerifier` MUST validate the entire chain by: (a) verifying each JWS signature against the public key associated with its `workload_id`; and (b) verifying that each entry's `parent_ids[0]` equals the SHA-256 hex-digest of the preceding JWS compact string. |
| **F-PA-05** | If any signature fails cryptographic verification, the `PassportVerifier` MUST raise an exception and MUST NOT proceed with further verification. |
| **F-PA-06** | If any `parent_ids[0]` hash does not match the SHA-256 of its predecessor JWS, the `PassportVerifier` MUST raise an exception. |
| **F-PA-07** | The root entry's `parent_ids[0]` value of `"0"` MUST be treated as the canonical sentinel for chain start and MUST NOT be verified as a SHA-256 hash. |

### 2.4 Policy Evaluation (Verification Hook)

A **Verification Hook** is the primary integration point that wraps business logic with the full Kest lifecycle. Implementations MAY expose this as a function decorator (Python), middleware (Go/Java), annotation (JVM), or wrapper function — the execution contract is invariant regardless of language idiom.

| ID | Requirement |
|---|---|
| **F-PE-01** | The Verification Hook MUST execute the following steps in order: (1) extract lineage from ambient context; (2) evaluate all configured policies (in tier order: enterprise → platform → application → function); (3) if all policies allow, execute the protected operation; (4) produce and sign a `KestEntry`; (5) update context with the new entry. |
| **F-PE-02** | If any configured policy returns `false` or encounters an error, the protected operation MUST NOT execute, and an **authorization error** MUST be raised to the caller. |
| **F-PE-03** | When multiple policies are specified within a tier, the evaluation MUST use strict **Logical AND** — all policies must independently return `true` for execution to proceed. |
| **F-PE-04** | Policy evaluation MUST be performed **before** the protected operation executes. |
| **F-PE-05** | The Verification Hook MUST support per-invocation overrides for `engine`, `identity`, and `trust_evaluator`, taking precedence over global configuration. |
| **F-PE-06** | The context structure passed to the policy engine MUST conform to the schema defined in §9.2. |
| **F-PE-07** | A Kest deployment MUST support at minimum three policy tiers, evaluated in strict order: **(1) Enterprise Baseline** → **(2) Platform** → **(3) Function-level**. An optional **(1a) Application** tier MAY be inserted between Platform and Function-level. |
| **F-PE-08** | **Enterprise Baseline** policies MUST be applied to every Verification Hook invocation, regardless of function-level configuration. They are configured globally (e.g., in the Kest runtime configuration) and are not overridable from application code. |
| **F-PE-09** | **Platform policies** are scoped to a logical platform or service group and MUST be configurable at the runtime or deployment level (e.g., environment variable, sidecar configuration). They are applied after Enterprise Baseline policies and before function-level policies. |
| **F-PE-10** | **Function-level policies** are the `policy` parameter passed directly to the Verification Hook. They are evaluated last and supplement (not replace) higher-tier policies. |
| **F-PE-11** | A deployment MAY declare a **policy deviation** — an explicit, operator-approved exemption from one or more named Enterprise Baseline or Platform policies for a specific scope (function or application). A deviation MUST be declared in configuration, NOT in application code, to prevent developer self-approval. |
| **F-PE-12** | Every policy deviation MUST be recorded in the `policy_context.deviations` field of the signed `KestEntry` at the time of invocation. The deviation record MUST include: the name of the deviated policy, the tier it belongs to, the stated reason (if provided), and the identity of the approver (if available). Because this field is part of the signed payload, it is tamper-evident and auditable. |
| **F-PE-13** | An invocation that applies a deviation MUST still produce a valid, signed `KestEntry`. The deviation does NOT exempt the entry from being recorded in the Passport — it only modifies which policies are enforced. |

### 2.5 Trust Score Calculation

| ID | Requirement |
|---|---|
| **F-TS-01** | A root node (the first entry in a chain, identified by `parent_ids == ["0"]`) MUST derive its initial `trust_score` from a configurable `ORIGIN_TRUST_MAP`, keyed by the `source_type` / `origin` parameter. |
| **F-TS-02** | The `ORIGIN_TRUST_MAP` MUST define the following default values: `"system"` → 100, `"internal"` → 100, `"verified_rag"` → 90, `"third_party_api"` → 60, `"user_input"` → 40, `"internet"` → 10, `"llm"` → 0. Deployments MAY register additional `source_type` → `trust_score` mappings to accommodate custom origin categories. Custom mappings MUST NOT override the mandatory default values listed above. |
| **F-TS-03** | For non-root nodes, the `DefaultTrustEvaluator` MUST compute `trust_score = (min(parent_scores) * self_score) // 100`. |
| **F-TS-04** | A `TrustEvaluator` interface MUST be defined with a single method `calculate(self_score: int, parent_scores: list[int]) → int`. |
| **F-TS-05** | A `trust_override` parameter on the Verification Hook MUST bypass the `TrustEvaluator` and hard-set the `trust_score` to the specified value, regardless of parent scores. This is the **Sanitizer** mechanism. |
| **F-TS-06** | The `trust_score` MUST be passed to the policy engine as an integer in the evaluation context. |

### 2.6 Taint Tracking

| ID | Requirement |
|---|---|
| **F-TT-01** | A taint is a non-empty string label identifying a risk or data provenance attribute (e.g., `"unverified_input"`, `"contains_pii"`). |
| **F-TT-02** | The Verification Hook MUST accept `added_taints` — a sequence of strings representing new taints introduced at this node. |
| **F-TT-03** | The Verification Hook MUST accept `removed_taints` — a sequence of strings representing taints explicitly cleared at this node. Removal requires a corresponding `trust_override` or an explicit sanitizer declaration. |
| **F-TT-04** | The accumulated `taints` at any node MUST equal `(union of all ancestor taints) ∪ added_taints − removed_taints`. |
| **F-TT-05** | All three fields (`added_taints`, `removed_taints`, `taints`) MUST be included in the signed `KestEntry` payload, making them cryptographically auditable. |
| **F-TT-06** | The `taints` set MUST be passed to the policy engine in the evaluation context. |

### 2.7 Identity Context (User, Agent, Task, Resource)

| ID | Requirement |
|---|---|
| **F-IC-01** | The Verification Hook MUST accept optional `user`, `agent`, `task`, `resource_id`, and `resource_attr` parameters at the call site. |
| **F-IC-02** | Each of these parameters MUST accept either a static value (string or map) or a **resolver** — a callable/closure that receives the invocation arguments and returns the value at call time. |
| **F-IC-03** | If no explicit `user`, `agent`, or `task` is provided, the implementation MUST fall back to reading `kest.user`, `kest.agent`, and `kest.task` from the ambient [OTel Baggage](https://opentelemetry.io/docs/specs/otel/baggage/api/) context. |
| **F-IC-04** | The resolved `user`, `agent`, `task`, and `resource_attr` MUST be embedded in the signed `KestEntry.labels` as JSON-serialized strings under the keys `kest.identity` and `kest.resource_attr`. |
| **F-IC-05** | A **Server-Side Identity Interceptor** component (see §8.2) MUST extract identity from a Bearer JWT at the service ingress and write resolved values to OTel Baggage using the mapping: `sub` → `kest.user`; `client_id` → `kest.agent`; `scope` → `kest.task`; raw token → `kest.jwt`. The JWT claim names used MUST be configurable. |

### 2.8 Context Propagation

| ID | Requirement |
|---|---|
| **F-CP-01** | The current Passport MUST be propagated between services using the [W3C Baggage](https://www.w3.org/TR/baggage/) HTTP header under the key `kest.passport`. |
| **F-CP-02** | A **Server-Side Lineage Interceptor** (see §8.1) MUST extract the `baggage` header from incoming requests, parse `kest.passport`, and make the Passport available to the Verification Hook before it executes. The Interceptor MAY run in-process (e.g., as framework middleware) or out-of-process (e.g., as a sidecar proxy that intercepts HTTP/gRPC traffic). |
| **F-CP-03** | An **Outbound Propagator** MUST serialize the current Passport to JSON and inject it into outgoing requests as a `baggage` header value. The Propagator MAY run in-process (e.g., as an HTTP client interceptor) or out-of-process (e.g., as a sidecar that intercepts egress traffic). |
| **F-CP-04** | When the serialized Passport exceeds a configurable size threshold (default: 4096 bytes), the implementation MUST engage the **Claim Check** pattern: (a) store the full Passport in a configured `CacheProvider` under a UUID key; (b) propagate only `kest.claim_check=<uuid>` in the baggage header. The `CacheProvider` entry SHOULD have a configurable TTL long enough to outlive the full request chain, and implementations SHOULD document the risk of audit gaps if a claim check expires before collection. |
| **F-CP-05** | Upon receiving a `kest.claim_check` baggage key, the Server-Side Lineage Interceptor MUST retrieve the full Passport from the `CacheProvider` and restore it to the OTel context before the Verification Hook executes. |
| **F-CP-06** | The following context accessor operations MUST be provided, reading from OTel Baggage: `get_current_user()`, `get_current_agent()`, `get_current_task()`, `get_current_jwt()`, `get_current_passport()`. Each returns the value or a null sentinel if absent. |

> **Informative note — Sidecar deployment pattern:** The Server-Side Lineage Interceptor, the Outbound Propagator, and the Verification Hook are defined as logical components; they do not need to reside in the same process as the application being protected. In environments where instrumentation of application code is not practical (e.g., legacy services, third-party containers), all three components MAY be deployed as a **sidecar proxy** (such as Envoy or a custom proxy) that intercepts inbound and outbound HTTP/gRPC traffic. The sidecar extracts and injects `kest.passport` baggage on ingress and egress, and invokes the Verification Hook against the policy engine on the workload's behalf. The contract — `KestEntry` production, Passport signing, and policy evaluation — is identical regardless of deployment topology.

> **Recommended — OTel Collector claim-check reconciliation:** When the Claim Check pattern (F-CP-04) is in use, OTel records flowing through the pipeline may carry `kest.claim_check` references instead of the full serialized Passport. A Kest-aware OTel Collector pipeline SHOULD include a **rehydration processor** that resolves these references against the `CacheProvider` before the audit records are written to long-term storage. This ensures that persisted audit logs are always self-contained — containing the complete Merkle-linked Passport — rather than dangling UUID references that become unresolvable after the cache TTL expires. The rehydration step SHOULD be the final transform in the collector pipeline, immediately before the exporter. Implementations that expose a collector extension or plugin SHOULD document the configuration interface for this processor.


### 2.9 Telemetry Emission

| ID | Requirement |
|---|---|
| **F-TE-01** | After each successful Verification Hook execution, the implementation MUST emit an [OTel](https://opentelemetry.io/docs/specs/) span or log record with the instrumentation scope `kest.core`. |
| **F-TE-02** | The OTel record MUST include at minimum: `kest.signature` (the full JWS compact string), `kest.parent_hash` (the SHA-256 of the previous JWS or `"0"` for root), and `kest.passport` (the serialized current Passport). |
| **F-TE-03** | A **telemetry bootstrap** helper MUST be provided that accepts `service_name`, `exporter_type` (at minimum: `"otlp"`, `"file"`, `"sqlite"`), and `endpoint` parameters, and configures the OTel SDK accordingly. |
| **F-TE-04** | _(Recommended)_ Implementations SHOULD provide a **lineage visualiser** that reads OTel export data (e.g., JSON or SQLite) and renders a visual representation of the Merkle DAG for debugging and audit purposes. The output format and tooling are left to the implementer (e.g., Mermaid.js graph, DOT/Graphviz, interactive web UI, CLI summary). |

### 2.10 Global Configuration

| ID | Requirement |
|---|---|
| **F-GC-01** | A `configure(engine, identity, cache?)` function MUST be provided to set global defaults for `PolicyEngine`, `IdentityProvider`, and optionally `CacheProvider`. |
| **F-GC-02** | Global configuration MUST be readable via `get_active_engine()`, `get_active_identity()`, and `get_active_cache()`. |
| **F-GC-03** | Per-invocation overrides on the Verification Hook MUST take precedence over global configuration. |
| **F-GC-04** | If no global configuration is set and no per-invocation override is provided, the implementation MUST raise a clear configuration error indicating that an `IdentityProvider` is required. Implementations MAY additionally provide an `AutoDetector` convenience helper — see §5.9. |

---

## 3. Non-Functional Requirements

These requirements constrain implementation quality and behaviour under adverse conditions. They are equally mandatory for a conformant implementation.

### 3.1 Performance

| ID | Requirement |
|---|---|
| **NF-PERF-01** | Policy evaluation via a co-located sidecar (OPA or Cedar on `localhost`) MUST complete within 5 ms at the 99th percentile under normal operating conditions. |
| **NF-PERF-02** | RFC 8785 canonicalization and Ed25519 signing of a `KestEntry` payload MUST complete within 1 ms on modern hardware. |
| **NF-PERF-03** | The overhead added by the Verification Hook (excluding policy evaluation and identity provider latency) MUST not exceed 2 ms at the 99th percentile. |
| **NF-PERF-04** | `PassportVerifier.verify()` for a chain of up to 100 entries MUST complete within 500 ms. |

### 3.2 Security

| ID | Requirement |
|---|---|
| **NF-SEC-01** | Private keys MUST NOT be logged, serialized to disk, or transmitted over any network channel. |
| **NF-SEC-02** | A failure to reach the IdentityProvider MUST prevent signing and raise an error that halts execution — NEVER return a stub or empty signature. |
| **NF-SEC-03** | A failure to reach the PolicyEngine MUST be treated as a denial (fail-secure) and raise an error. |
| **NF-SEC-04** | The implementation MUST NOT silently downgrade from a cryptographic signature to a plaintext assertion under any error path. |
| **NF-SEC-05** | Clock skew between nodes MUST NOT be used as a basis for lineage validation. The cryptographic hash linkage (`parent_ids`) supersedes timestamp ordering. |
| **NF-SEC-06** | Replay attack detection at the application level (e.g., nonces, idempotency keys) is explicitly out of scope for the Kest core. The Kest Passport prevents history tampering but does not prevent replaying an identical, unmodified request at the application layer. |

### 3.3 Correctness & Determinism

| ID | Requirement |
|---|---|
| **NF-CORR-01** | The RFC 8785 canonicalization of any `KestEntry` payload MUST produce byte-identical output across all conformant implementations in all languages. |
| **NF-CORR-02** | The SHA-256 hash of the same JWS compact string MUST produce the same hex-digest across all conformant implementations. |
| **NF-CORR-03** | The `DefaultTrustEvaluator` formula `(min(parent_scores) * self_score) // 100` MUST use integer arithmetic (floor division). |

### 3.4 Observability

| ID | Requirement |
|---|---|
| **NF-OBS-01** | All policy denial events MUST be logged with sufficient context (entry_id, policy names, workload_id) to support post-incident review. |
| **NF-OBS-02** | All OTel spans emitted by Kest MUST carry the standard `service.name` resource attribute. |
| **NF-OBS-03** | The `kest.verified.*` naming convention MUST be used for all Kest-specific OTel span/log names. |

### 3.5 Interoperability

| ID | Requirement |
|---|---|
| **NF-INTER-01** | The Passport serialization format MUST be a JSON array of JWS compact strings (`string[]`), with no language-specific wrappers. |
| **NF-INTER-02** | The `baggage` header format MUST conform to W3C Baggage specification, with percent-encoding for reserved characters. |
| **NF-INTER-03** | The `kest.passport` baggage value MUST be the JSON array serialized as a string (not further base64 encoded). |

### 3.6 Testability

| ID | Requirement |
|---|---|
| **NF-TEST-01** | The implementation SHOULD provide at least one `IdentityProvider` test double that produces deterministic, structurally valid (but cryptographically trivial) JWS strings without requiring a live identity plane. This enables repeatable unit test assertions. |
| **NF-TEST-02** | All policy engines MUST provide a `MockPolicyEngine` (or equivalent) that returns a configurable boolean without network calls. |
| **NF-TEST-03** | Integration tests requiring real SPIRE attestation MUST run inside the workload's PID namespace (i.e., within the container, not from the host). |

---

## 4. Data Model Specification

### 4.1 `KestEntry` Payload Schema

The canonical payload embedded in every JWS. Before signing, this object MUST be canonicalized using RFC 8785.

```json
{
  "schema_version": "0.3.0",
  "runtime": {
    "name":    "<Kest library name, e.g. 'kest-python'>",
    "version": "<Kest library semver, e.g. '0.3.1'>"
  },
  "entry_id":        "<UUID v7 — time-ordered, RFC 9562>",
  "operation":       "<string — name of decorated function or caller label>",
  "classification":  "<string — data classification, default: 'system'>",
  "trust_score":     "<integer 0–100>",
  "parent_ids":      ["<SHA-256 hex of previous JWS compact string, or '0' for root>"],
  "added_taints":    ["<string>"],
  "removed_taints":  ["<string>"],
  "taints":          ["<string — accumulated set>"],
  "labels": {
    "principal":         "<workload_id string>",
    "kest.identity":     "<JSON string: {user, agent, task}>",
    "kest.resource_attr":"<JSON string: {key: value, ...}>",
    "trace_id":          "<OTel trace ID hex string>"
  },
  "policy_context": {
    "enterprise_policies": ["<policy name>"],
    "platform_policies":   ["<policy name>"],
    "app_policies":        ["<policy name>"],
    "function_policies":   ["<policy name>"],
    "deviations": [
      {
        "policy":   "<deviated policy name>",
        "tier":     "<'enterprise' | 'platform' | 'application'>",
        "reason":   "<human-readable justification or null>",
        "approver": "<identity of approver or null>"
      }
    ]
  },
  "environment":     {},
  "otel_context":    {},
  "metadata":        null,
  "content_hash":    "<SHA-256 of function return value, or empty string>",
  "input_hash":      "<SHA-256 of function input arguments, or empty string>",
  "timestamp_ms":    "<epoch milliseconds integer>"
}
```

**Field constraints:**

| Field | Type | Required | Constraints |
|---|---|---|---|
| `schema_version` | string | YES | Semantic version of the KestEntry schema (e.g., `"0.3.0"`) |
| `runtime.name` | string | YES | Non-empty; identifies the Kest library (e.g., `"kest-python"`) |
| `runtime.version` | string | YES | Semantic version of the Kest library |
| `entry_id` | string | YES | [UUID v7](https://datatracker.ietf.org/doc/html/rfc9562#section-5.7) format ([RFC 9562](https://datatracker.ietf.org/doc/html/rfc9562)) |
| `operation` | string | YES | Non-empty |
| `classification` | string | YES | Default: `"system"` |
| `trust_score` | integer | YES | Range: 0–100 inclusive |
| `parent_ids` | array[string] | YES | `["0"]` for root; SHA-256 hex otherwise |
| `added_taints` | array[string] | YES | May be empty |
| `removed_taints` | array[string] | YES | May be empty |
| `taints` | array[string] | YES | May be empty |
| `labels` | object | YES | MUST contain `"principal"` and `"trace_id"` |
| `policy_context` | object | YES | See §9.6; MUST contain at minimum `function_policies` and `deviations` arrays |
| `policy_context.enterprise_policies` | array[string] | YES | Names of enterprise baseline policies evaluated; may be empty |
| `policy_context.platform_policies` | array[string] | YES | Names of platform-scoped policies evaluated; may be empty |
| `policy_context.app_policies` | array[string] | NO | Names of application-scoped policies evaluated; may be empty |
| `policy_context.function_policies` | array[string] | YES | Names of function-level policies evaluated; may be empty |
| `policy_context.deviations` | array[object] | YES | Declared deviations from higher-tier policies; may be empty |
| `policy_context.deviations[].policy` | string | YES (if deviation) | Name of the deviated policy |
| `policy_context.deviations[].tier` | string | YES (if deviation) | One of: `"enterprise"`, `"platform"`, `"application"` |
| `policy_context.deviations[].reason` | string | NO | Human-readable justification |
| `policy_context.deviations[].approver` | string | NO | Identity of the approver |
| `timestamp_ms` | integer | YES | Epoch ms, positive |

### 4.2 JWS Header

```json
{
  "alg": "EdDSA",
  "typ": "JWS"
}
```

- `alg`: MUST be `"EdDSA"` (Ed25519 curve). Future versions may introduce `"ES256"` but MUST document this explicitly.
- `typ`: MUST be `"JWS"`.

### 4.3 JWS Signing Input

The Ed25519 signature MUST be computed over the following byte string (per RFC 7515 §7.2):

```
ASCII(base64url(UTF8(header)) || '.' || base64url(JCS(payload)))
```

Where:
- `base64url()` is standard Base64URL encoding with no padding.
- `UTF8()` is UTF-8 encoding of the JSON string.
- `JCS(payload)` is the RFC 8785 canonical JSON serialization of the `KestEntry` object.

### 4.4 `Passport` Schema

```json
{
  "entries": ["<JWS compact string>", "..."]
}
```

When serialized for transport (OTel baggage, API responses), the `entries` array is JSON-encoded as a top-level array string:

```
"[\"header.payload.sig1\",\"header.payload.sig2\"]"
```

### 4.5 `ORIGIN_TRUST_MAP`

| `source_type` / `origin` | Default `trust_score` |
|---|---|
| `"system"` | 100 |
| `"internal"` | 100 |
| `"verified_rag"` | 90 |
| `"third_party_api"` | 60 |
| `"user_input"` | 40 |
| `"internet"` | 10 |
| `"llm"` | 0 |

Implementations MAY extend this map with additional keys. Values MUST remain in the range [0, 100].

---

## 5. Interface Specification

All interfaces are defined in a language-agnostic notation. Each conformant implementation must provide equivalent constructs.

### 5.1 `IdentityProvider`

Provides cryptographic workload identity. Implementations connect to the appropriate platform identity service (e.g., [SPIFFE/SPIRE](https://spiffe.io/), [AWS IAM](https://aws.amazon.com/iam/), [OIDC](https://openid.net/developers/how-connect-works/)).

```
interface IdentityProvider {
  // Returns the unique workload identifier for the current runtime.
  // Examples: SPIFFE URI, AWS Role ARN, OIDC sub claim.
  get_workload_id() → string

  // Signs the given byte payload using the workload's private key.
  // Returns a JWS compact serialization: "header.payload.signature"
  sign(payload: bytes) → string

  // Optional: Verifies a remote SVID and returns the workload_id it represents.
  // Raises an error if the SVID is invalid.
  verify_svid(svid: string) → string
}
```

**Normative implementations** (required for Kest compatibility):

| Name | Identity Source | Notes |
|---|---|---|
| `SPIREProvider` | [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) | Supports any transport SPIRE exposes (UDS, TCP). Connection parameters are operator-configurable. |
| `AWSWorkloadIdentity` | AWS STS + [KMS](https://aws.amazon.com/kms/) | Signs via KMS; resolves role from ambient AWS credential chain. |
| `BedrockAgentIdentity` | [Amazon Bedrock AgentCore Identity](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html) | Workload identity for AI agents hosted on AWS Bedrock AgentCore. See below. |
| `OIDCIdentity` | OIDC JWT from file or env | Token path/value configurable by operator. |

**Informative implementations** (not required for compatibility; provided as reference):

| Name | Purpose | Constraint |
|---|---|---|
| `LocalEd25519Provider` | Development convenience — in-process ephemeral key pair when no identity plane is available | MUST warn at startup; MUST NOT be used in production |
| `MockIdentityProvider` | Test double — deterministic, structurally valid JWS without real signing | For unit tests only |

#### `SPIREProvider` — Mechanism

[SPIFFE/SPIRE](https://spiffe.io/) (Secure Production Identity Framework for Everyone / SPIRE Runtime Environment) is a CNCF-graduated open-source framework for issuing, rotating, and verifying cryptographic workload identities in dynamic, heterogeneous environments — without secrets or long-lived credentials.

**How it works:**

1. **Attestation** — A SPIRE Agent runs on each node and attests the workload using platform-specific selectors (e.g., Kubernetes pod labels, OS process attributes, AWS instance identity documents). The agent co-locates with the workload and uses kernel-level evidence (PID namespace, cgroup, etc.) to verify the workload's identity — this is why integration tests must run inside the workload's container (see NF-TEST-03).

2. **SVID issuance** — Once attested, the SPIRE Server issues a **SPIFFE Verifiable Identity Document (SVID)** to the workload. SVIDs may be X.509 certificates or JWT tokens, both encoding a globally unique **SPIFFE ID** in URI form: `spiffe://<trust-domain>/<path>`. The `workload_id` returned by `get_workload_id()` SHOULD be this SPIFFE URI.

3. **Workload API** — The SPIRE Agent exposes the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) — a gRPC API accessible via a local socket (or TCP endpoint). The `SPIREProvider` connects to this API to fetch the current SVID and its associated private key for signing. SVIDs are short-lived and automatically rotated; the provider SHOULD re-fetch on rotation events.

4. **Signing** — The signing key is the SVID's private key, held by the SPIRE Agent and delivered to the workload transiently via the Workload API. It MUST NOT be persisted (F-ID-04).

> **References:** [SPIFFE Standards](https://spiffe.io/) · [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/) · [SPIFFE Workload API Spec](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)

---

#### `AWSWorkloadIdentity` — Mechanism

AWS provides workload identity through the combination of [IAM Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html) and [AWS Security Token Service (STS)](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html). In containerized or serverless environments (ECS, EKS, Lambda), credentials are injected via the instance metadata service or environment variables, without any long-lived secrets in code.

**How it works:**

1. **Ambient credential resolution** — The provider resolves the workload's IAM identity from the AWS credential chain (instance profile, EKS IRSA pod annotation, ECS task role, `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE`, etc.). No static key material is required in the deployment.

2. **Identity token** — The resolved IAM role ARN serves as the `workload_id`. For cross-account or federated scenarios, `AssumeRole` (via STS) produces a temporary session with a short TTL.

3. **Signing** — Signing is delegated to [AWS KMS](https://aws.amazon.com/kms/) using a key identified by `KEST_AWS_KMS_KEY_ID`. The provider calls `KMS:Sign` with the `RSASSA_PKCS1_V1_5_SHA_256` or `ECDSA_SHA_256` algorithm (or Ed25519 if the key type supports it). KMS never exposes the private key material — signing is performed inside the HSM boundary.

4. **Auditability** — Every KMS signing call is logged to [AWS CloudTrail](https://aws.amazon.com/cloudtrail/), providing an independent audit trail of all key usages — complementing the Kest Passport audit chain.

> **References:** [AWS IAM Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html) · [AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html) · [AWS KMS](https://aws.amazon.com/kms/) · [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)

---

#### `OIDCIdentity` — Mechanism

[OpenID Connect (OIDC)](https://openid.net/specs/openid-connect-core-1_0.html) is an identity layer on top of OAuth 2.0 that defines a standard for issuing signed JSON Web Tokens (JWTs) asserting a workload's identity. It is widely used in CI/CD pipelines (GitHub Actions, GitLab CI, CircleCI) and cloud federation scenarios (e.g., EKS Pod Identity, GCP Workload Identity Federation).

**How it works:**

1. **Token acquisition** — A JWT (ID token) is obtained from an OIDC-compliant IdP and written to a file path or environment variable (configurable via operator). In CI/CD contexts the token is usually injected by the platform; in Kubernetes it is mounted as a projected ServiceAccount token.

2. **Identity extraction** — The `workload_id` is extracted from the JWT's `sub` (subject) claim, which is globally unique within the issuer's trust domain. Implementations MAY optionally validate the token's signature and expiry using the IdP's JWKS endpoint before use.

3. **Signing** — Because OIDC tokens are issued by an external IdP and may not carry a private key for the workload itself, the `OIDCIdentity` provider MUST use a locally held or KMS-backed signing key to produce the JWS. The OIDC token serves purely as the **identity assertion**; it is not itself the signing key. Implementations SHOULD record the OIDC `iss` (issuer) and `sub` claims in the `labels` of the `KestEntry` for auditability.

4. **Federation** — OIDC is the bridge that enables workloads in one environment (e.g., a GitHub Actions runner) to assume roles in cloud providers (e.g., AWS IAM via `AssumeRoleWithWebIdentity`) without static secrets — making it the recommended identity method for ephemeral CI/CD workloads.

> **References:** [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) · [RFC 7519 – JWT](https://datatracker.ietf.org/doc/html/rfc7519) · [GitHub OIDC](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)

---

#### `BedrockAgentIdentity` — Mechanism

[Amazon Bedrock AgentCore Identity](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html) is AWS's workload identity plane purpose-built for AI agents and automated systems. It addresses the challenge of issuing, managing, and verifying non-human identities — specifically for agent workloads that may invoke AWS resources, third-party APIs, or other agents on behalf of users.

**How it works:**

1. **Workload identity registration** — Each Bedrock agent is registered in the AgentCore Identity directory with a unique Agent ID (`AWS_BEDROCK_AGENT_ID`). Unlike traditional service accounts tied to infrastructure, agent identities are environment-agnostic and can hold multiple authentication credentials simultaneously.

2. **Authentication** — AgentCore Identity verifies requests using AWS SigV4, standardized OAuth 2.0 flows, or API keys. Inbound requests to an agent runtime can be authorized via a configurable JWT authorizer that validates tokens from any OIDC-compatible identity provider.

3. **Signing** — The `BedrockAgentIdentity` provider derives signing credentials from the agent's AWS identity context. Signing is performed via [AWS KMS](https://aws.amazon.com/kms/), using an Ed25519 key (or a KMS-managed key configured by the operator). The `workload_id` returned by `get_workload_id()` SHOULD be the agent's ARN or a stable identifier derived from it.

4. **Credential federation** — AgentCore Identity acts as an outbound credential broker: it can exchange the agent's identity token for credentials to access third-party services (e.g., OAuth tokens, API keys), scoped to the specific task. Kest does not mandate use of this federation feature, but implementations SHOULD be aware of it when constructing the identity context passed to the policy engine.

> **Reference:** [Amazon Bedrock AgentCore Identity Developer Guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html)


### 5.2 `PolicyEngine`

Delegates authorization decisions to an external or in-process policy engine. See [OPA](https://www.openpolicyagent.org/docs/latest/) and [Cedar](https://www.cedarpolicy.com/) for reference policy language documentation.

```
interface PolicyEngine {
  // Evaluates whether the described action is authorized.
  // entry_id    : the UUID of the executing KestEntry
  // policy_names: list of policy identifiers to evaluate (ALL must allow)
  // context     : the structured evaluation context (see §9.2)
  // Returns true if ALL policies allow; raises an authorization error on denial.
  evaluate(entry_id: string, policy_names: sequence<string>, context: map<string, any>) → bool

  // Concurrent/async variant of evaluate().
  // Implementations SHOULD provide this where the language supports async I/O.
  // The evaluation contract and error behaviour are identical to evaluate().
  async_evaluate(entry_id: string, policy_names: sequence<string>, context: map<string, any>) → bool
}
```

**Required implementations:**

| Name | Backend | Notes |
|---|---|---|
| `OPAPolicyEngine` | [OPA](https://www.openpolicyagent.org/) REST API (`/v1/data/<policy>`) | See §9.3 for wire format |
| `CedarPolicyEngine` | [Cedar Agent](https://www.cedarpolicy.com/) REST API (`/is_authorized`) | See §9.4 for wire format |
| `CedarLocalEngine` | In-process Cedar via compiled policy objects | No network dependency |
| `AVPPolicyEngine` | [AWS Verified Permissions](https://docs.aws.amazon.com/verified-permissions/) REST API | Managed Cedar in AWS |
| `MockPolicyEngine` | Configurable boolean | For unit tests only |

### 5.3 `TrustEvaluator`

```
interface TrustEvaluator {
  // Computes the trust score for a node given its own declared score
  // and the scores of its parent nodes.
  calculate(self_score: int, parent_scores: list[int]) → int
}
```

**Default implementation (`DefaultTrustEvaluator`):**

```
calculate(self_score, parent_scores):
  if parent_scores is empty:
    return self_score
  return (min(parent_scores) * self_score) // 100
```

### 5.4 `Passport`

```
struct Passport {
  entries: list[string]  // ordered list of JWS compact strings

  // Append a new JWS to the chain.
  add_signature(jws: string) → void

  // Serialize the entries list to a JSON string.
  serialize() → string

  // Factory: construct a Passport from a serialized JSON string.
  static deserialize(data: string) → Passport
}
```

### 5.5 `PassportVerifier`

```
struct PassportVerifier {
  // Verify the cryptographic integrity and lineage of a Passport.
  // providers: map of workload_id → IdentityProvider (for public key lookup)
  // Raises an error on any verification failure.
  static verify(passport: Passport, providers: map[string, IdentityProvider]) → void
}
```

**Verification algorithm** (see §6.2 for full detail):

1. Initialize `last_hash = "0"`.
2. For each `jws` in `passport.entries`:
   a. Decode and parse the JWS payload.
   b. Assert `payload.parent_ids[0] == last_hash`.
   c. Look up the public key for `payload.labels["principal"]` via `providers`.
   d. Verify the JWS signature against the public key.
   e. Compute `last_hash = SHA-256(jws)` (the full compact JWS string, UTF-8 encoded).
3. If all steps pass, return successfully.

### 5.6 `CacheProvider`

```
interface CacheProvider {
  // Store a value under a key with an optional TTL (in seconds).
  set(key: string, value: string, ttl?: int) → void

  // Retrieve a value by key. Returns null if not found or expired.
  get(key: string) → string | null
}
```

### 5.7 `BaggageManager`

```
struct BaggageManager {
  // Serialize and store the Passport, applying Claim Check if needed.
  // Returns the baggage key-value pairs to inject into the transport header.
  store(passport: Passport, cache: CacheProvider?) → map[string, string]

  // Restore the Passport from baggage key-value pairs.
  restore(baggage: map[string, string], cache: CacheProvider?) → Passport
}
```

### 5.8 Verification Hook

The Verification Hook is the primary developer-facing integration point. It wraps a protected operation with the full Kest authorization and lineage lifecycle. How this is exposed is **language and framework specific** — see §15 for reference implementations.

**Configuration Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `policy` | string or sequence of strings | YES | Policy name(s) to evaluate |
| `engine` | PolicyEngine | NO | Per-invocation engine override |
| `identity` | IdentityProvider | NO | Per-invocation identity override |
| `trust_evaluator` | TrustEvaluator | NO | Per-invocation evaluator override |
| `source_type` / `origin` | string | NO | Origin label for root node trust bootstrap |
| `added_taints` | sequence of strings | NO | Taints to introduce at this node |
| `removed_taints` | sequence of strings | NO | Taints to clear at this node (sanitizer) |
| `trust_override` | integer | NO | Bypass evaluator; hard-set trust_score |
| `user` | string or resolver | NO | User principal |
| `agent` | string or resolver | NO | Agent identity |
| `task` | string or resolver | NO | Task or scope |
| `resource_id` | string or resolver | NO | Resource identifier |
| `resource_attr` | map or resolver | NO | Resource attributes for ABAC |

**Execution Lifecycle (normative 13-step contract):**

```
 1. Resolve identity   (per-invocation override → global config → error if absent)
 2. Resolve engine     (per-invocation override → global config → error)
 3. Extract Passport from ambient context (OTel Baggage)
 4. Resolve user / agent / task / resource_attr
    (explicit → resolver → OTel Baggage fallback)
 5. Compute trust_score:
    a. If root (Passport is empty): ORIGIN_TRUST_MAP[source_type]
    b. Else: trust_evaluator.calculate(self_score, parent_scores)
    c. If trust_override is set: use trust_override directly
 6. Compute accumulated taints from all parent entries
 7. Build KestEntry payload (unsigned)
 8. Canonicalize payload per RFC 8785; sign with identity.sign()
 9. Call engine.evaluate(entry_id, policy_names, context)
    → raise authorization error on denial; abort execution
10. Execute the protected operation
11. Append signed JWS to Passport
12. Update OTel context with the updated Passport
13. Emit OTel span/log with kest.* attributes
```

### 5.9 `AutoDetector` _(Recommended, Informative)_

> **This is not a normative requirement.** Implementations MAY provide an `AutoDetector` as a convenience helper. When present, it removes the burden of manually specifying an `IdentityProvider` in standard deployment environments.

An `AutoDetector` inspects the runtime environment and returns the most appropriate `IdentityProvider` without requiring explicit configuration from the caller. It is particularly useful in multi-cloud or hybrid deployments where the same codebase runs in different identity environments.

**Recommended probe order (highest to lowest priority):**

| Priority | Environment Signal | Selected Provider |
|---|---|---|
| 1 | `SPIFFE_ENDPOINT_SOCKET` is set and the socket is reachable | `SPIREProvider` |
| 2 | `AWS_BEDROCK_AGENT_ID` is set | `BedrockAgentIdentity` |
| 3 | `AWS_EXECUTION_ENV` or `AWS_ROLE_ARN` is set (and `KEST_AWS_KMS_KEY_ID` is present) | `AWSWorkloadIdentity` |
| 4 | `KEST_OIDC_TOKEN_PATH` is set and the file exists | `OIDCIdentity` |
| 5 | _(fallback)_ | `LocalEd25519Provider` _(development only)_ |

**Reference architecture:**

```
AutoDetector.detect() → IdentityProvider
  │
  ├─ probe SPIFFE_ENDPOINT_SOCKET  → SPIREProvider      (production: SPIRE)
  ├─ probe AWS_BEDROCK_AGENT_ID    → BedrockAgentIdentity (production: AWS AI)
  ├─ probe AWS_EXECUTION_ENV       → AWSWorkloadIdentity  (production: AWS workload)
  ├─ probe KEST_OIDC_TOKEN_PATH    → OIDCIdentity         (CI / federated)
  └─ fallback                      → LocalEd25519Provider (development)
```

If the `AutoDetector` is provided, it SHOULD be invokable as a standalone utility (e.g., a CLI command or a one-liner that prints the detected provider and workload ID). This aids in debugging misconfigured identity environments.

> **Note:** The `LocalEd25519Provider` fallback SHOULD emit a prominent warning at startup (e.g., a log line at `WARN` level) so that it is never silently used in production.

---

## 6. Protocol & Algorithm Specification

### 6.1 Canonicalization (RFC 8785 / JCS)

Before signing, the `KestEntry` JSON object MUST be serialized using the JSON Canonicalization Scheme (RFC 8785):

1. All Unicode characters in string values MUST be normalized.
2. Object keys MUST be sorted lexicographically by their Unicode code points.
3. No whitespace (spaces, newlines, tabs) MUST appear outside of string values.
4. Numbers MUST use the shortest representation that round-trips correctly.
5. The output MUST be a UTF-8 encoded byte array.

**Reference test vector:**

Input object:
```json
{"b": 2, "a": 1}
```

JCS-canonical output bytes (UTF-8):
```
{"a":1,"b":2}
```

Any implementation MUST pass this and all RFC 8785-compliant test vectors before being considered conformant.

### 6.2 Merkle Chain Verification Algorithm

```
function verify_passport(entries: list[string], providers: map[string, IdentityProvider]):
  last_hash = "0"

  for jws in entries:
    # Step 1: Parse the JWS compact serialization
    (header_b64, payload_b64, sig_b64) = split(jws, '.')
    header  = base64url_decode(header_b64)
    payload = base64url_decode(payload_b64)
    sig     = base64url_decode(sig_b64)

    # Step 2: Verify parent_ids linkage
    entry = parse_json(payload)
    assert entry["parent_ids"][0] == last_hash, "Lineage broken"

    # Step 3: Verify the JWS signature
    workload_id = entry["labels"]["principal"]
    provider    = providers[workload_id]
    signing_input = utf8(header_b64 + "." + payload_b64)
    assert ed25519_verify(public_key(provider), signing_input, sig), "Signature invalid"

    # Step 4: Advance chain
    last_hash = sha256_hex(utf8(jws))
```

### 6.3 SHA-256 Hash Computation

The `parent_ids` hash MUST be computed as:

```
SHA-256(UTF-8(jws_compact_string))
```

Encoded as a lowercase hexadecimal string (64 characters). No prefix, no padding.

### 6.4 Trust Score Propagation

```
function compute_trust_score(source_type, parent_entries, trust_override, evaluator):
  if trust_override is set:
    return clamp(trust_override, 0, 100)

  if parent_entries is empty or all parent_ids == ["0"]:
    self_score = ORIGIN_TRUST_MAP.get(source_type, 10)
    return self_score

  parent_scores = [entry.trust_score for entry in parent_entries]
  self_score    = ORIGIN_TRUST_MAP.get(source_type, 100)  # internal default
  return evaluator.calculate(self_score, parent_scores)
```

### 6.5 Taint Accumulation

```
function compute_taints(parent_entries, added_taints, removed_taints):
  accumulated = set()
  for entry in parent_entries:
    accumulated = accumulated ∪ set(entry.taints)
  accumulated = accumulated ∪ set(added_taints)
  accumulated = accumulated − set(removed_taints)
  return sorted(list(accumulated))  # deterministic ordering
```

---

## 7. Trust Model Specification

### 7.1 CARTA Model

Kest implements **Continuous Adaptive Risk and Trust Assessment (CARTA)**. Trust is not binary; it is a real-time integer [0, 100] computed from the full execution history.

### 7.2 Trust Score Semantics

| Score Range | Meaning |
|---|---|
| 100 | Fully trusted. Internal system components only. Permits all operations. |
| 80–99 | High trust. Verified internal services or RAG pipelines. |
| 50–79 | Moderate trust. Delegated agents, third-party integrations. |
| 10–49 | Low trust. User-provided data, internet entry points. |
| 1–9 | Minimal trust. Entry from untrusted systems. |
| 0 | No trust. Raw LLM output or completely untrusted sources. Blocks all sensitive operations. |

### 7.3 Trust Degradation Guarantee

The weakest-link model guarantees:
- A single low-trust ancestor permanently degrades all downstream scores.
- Trust can only be explicitly upgraded by a declared Sanitizer (via `trust_override`), which is itself signed and auditable.
- An internet entry (score=10) propagating through 100 internal hops still yields a score of 10 via the weakest-link formula.

### 7.4 Policy Threshold Guide

| Threshold | Recommended Use |
|---|---|
| `trust_score >= 100` | System-only operations: cron jobs, infrastructure tasks |
| `trust_score >= 80` | Internal RPC calls, verified data pipelines |
| `trust_score >= 50` | Delegated agent tasks, third-party integrations |
| `trust_score >= 10` | Minimum viable trust for any public route |
| `trust_score == 0` | Always block |

---

## 8. Context Propagation Specification

### 8.1 Server-Side Lineage Interceptor

Every service MUST include a **Server-Side Lineage Interceptor** that runs at the outermost layer of the request pipeline, before any application logic. Its sole responsibilities are:

1. Read the [`baggage`](https://www.w3.org/TR/baggage/) header from the incoming request.
2. Parse the `kest.passport` baggage key and deserialize it into a `Passport` object.
3. If `kest.claim_check` is present instead, retrieve the full Passport from the `CacheProvider`.
4. Attach the restored Passport to the ambient [OTel context](https://opentelemetry.io/docs/specs/otel/context/) for the duration of the request.

> **Reference implementation (Python/ASGI):** `KestMiddleware` wraps a Starlette/FastAPI application as standard ASGI middleware.

### 8.2 Server-Side Identity Interceptor

Every service that authenticates end-users MUST include a **Server-Side Identity Interceptor** that runs inside the Lineage Interceptor. Its responsibilities:

1. Extract the `Authorization: Bearer <token>` header.
2. Decode and validate the JWT (signature, expiry, issuer).
3. Write the resolved claims to OTel Baggage:
   - JWT `sub` claim → `kest.user`
   - JWT `client_id` claim → `kest.agent` _(claim name configurable)_
   - JWT `scope` claim → `kest.task` _(claim name configurable)_
   - Raw JWT string → `kest.jwt`
4. Values already present in Baggage from an upstream hop MUST be overwritten by the locally validated JWT.

> **Reference implementation (Python/ASGI):** `KestIdentityMiddleware`.

**Ordering requirement:** The Lineage Interceptor MUST execute before (outer to) the Identity Interceptor so that Passport lineage is available regardless of whether the current hop authenticates a user JWT.

### 8.3 Outbound Propagator

When making outbound HTTP calls to downstream services, the implementation MUST inject the current Passport (or Claim Check reference) into the `baggage` header of the outgoing request. This is typically achieved via an HTTP client interceptor / middleware / transport decorator.

> **Reference implementation (Python):** An `httpx` transport wrapper that reads the current OTel Baggage and injects it as a `baggage` header on every outbound request.

### 8.4 OTel Baggage Keys

| Baggage Key | Set By | Consumed By |
|---|---|---|
| `kest.passport` | Server-Side Lineage Interceptor, Verification Hook | Downstream Verification Hook, Lineage Interceptor |
| `kest.claim_check` | `BaggageManager` (when passport > 4 KB) | Lineage Interceptor |
| `kest.user` | Server-Side Identity Interceptor or explicit parameter | Verification Hook context, policy engine |
| `kest.agent` | Server-Side Identity Interceptor or explicit parameter | Verification Hook context, policy engine |
| `kest.task` | Server-Side Identity Interceptor or explicit parameter | Verification Hook context, policy engine |
| `kest.jwt` | Server-Side Identity Interceptor | Downstream verification |
| `kest.chain_tip` | Verification Hook | Policy engine context |

### 8.5 Middleware Stack Ordering

Regardless of the framework or language, the required execution order for incoming requests is:

```
Incoming request
  └─▶ Lineage Interceptor   (outer)  — restores Passport from baggage
        └─▶ Identity Interceptor (inner)  — validates JWT, writes identity to baggage
              └─▶ Verification Hook        — evaluates policy, signs entry
                    └─▶ Protected operation
```

This ordering ensures that JWT-validated identity always takes precedence over upstream-propagated baggage identity.

> **Note:** In frameworks where middleware ordering is reversed (e.g., Python ASGI adds middleware in LIFO order), the Lineage Interceptor MUST be registered last and the Identity Interceptor first.

### 8.3 Claim Check Pattern

```
store_passport(passport, cache, threshold=4096):
  serialized = passport.serialize()   // JSON string
  if len(serialized) <= threshold:
    return {"kest.passport": serialized}
  else:
    claim_id = generate_uuid_v4()
    cache.set(claim_id, serialized, ttl=300)  // 5 min TTL
    return {"kest.claim_check": claim_id}

restore_passport(baggage, cache):
  if "kest.passport" in baggage:
    return Passport.deserialize(baggage["kest.passport"])
  if "kest.claim_check" in baggage:
    serialized = cache.get(baggage["kest.claim_check"])
    if serialized is null:
      raise error("Claim check not found — passport TTL expired")
    return Passport.deserialize(serialized)
  return Passport(entries=[])  // empty/root passport
```

---

## 9. Policy Engine Specification

### 9.1 Policy Evaluation Contract

All policy engines MUST implement the following contract:

- **Input**: `(entry_id, policy_names, context)` where `context` is a flat string-keyed dictionary.
- **Output**: `true` (allow) or `false` (deny).
- **Error handling**: Any network error, timeout, or malformed response MUST be treated as `false` (deny), and a descriptive error MUST be raised to the caller.
- **Multi-policy evaluation**: The engine's `evaluate()` implementation MUST call each named policy independently and return `true` only if ALL policies return `true`.

### 9.2 Evaluation Context Schema

The following JSON object is passed as `context` to every policy evaluation. The structure is flat (serialized to a string-keyed map for Cedar compatibility):

```json
{
  "subject": {
    "workload":    "<workload_id>",
    "user":        "<user string or null>",
    "agent":       "<agent string or null>",
    "task":        "<task/scope string or null>",
    "trust_score": "<integer 0–100>",
    "taints":      ["<string>"]
  },
  "object": {
    "id":         "<resource_id or null>",
    "attributes": {}
  },
  "environment": {
    "is_root":              "<bool>",
    "source_type":          "<string>",
    "parent_hash":          "<SHA-256 hex of last JWS or '0'>",
    "policy_names":         ["<string>"],
    "policy_tier":          "<'enterprise' | 'platform' | 'application' | 'function'>",
    "active_deviations":    ["<deviated policy name>"]
  },
  "identity":    "<workload_id>",
  "trust_score": "<integer — top-level for backwards compatibility>"
}
```

For Cedar engines, this MUST be flattened to a single-level map using dot-notation or Cedar-specific extension semantics (e.g., `context["subject.user"]`).

### 9.3 OPA Integration

**Endpoint**: `POST http://<host>:<port>/v1/data/<policy_path>`

**Request body**:
```json
{"input": <context object>}
```

**Expected response**:
```json
{"result": {"allow": true}}
```

The `decision_path` (default: `result.allow`) MUST be configurable. Any non-200 response, connection error, or `allow != true` MUST result in denial.

### 9.4 Cedar Integration

**Endpoint**: `POST http://<host>:<port>/is_authorized`

**Request body** (Cedar Agent wire format):
```json
{
  "principal": "<workload_id>",
  "action":    "<policy-name>",
  "resource":  "<resource_id or '*'>",
  "context":   {<flattened context>}
}
```

**Expected response**:
```json
{"decision": "Allow"}
```

Any response where `decision != "Allow"` MUST result in denial.

### 9.5 Logical AND Multi-Policy Evaluation

```
function multi_policy_evaluate(entry_id, policy_names, context, engine):
  for policy in policy_names:
    result = engine.evaluate(entry_id, [policy], context)
    if result == false:
      raise AuthorizationError("Policy '" + policy + "' denied execution")
  return true
```

### 9.6 Policy Tier Architecture

Kest defines a **four-tier policy hierarchy**. Tiers are evaluated in strict descending order. A denial at any tier halts evaluation and blocks execution.

```
┌─────────────────────────────────────────────────────────┐
│  Tier 1: Enterprise Baseline                            │
│  Configured globally. Applied to ALL invocations.       │
│  Not overridable from application code.                 │
├─────────────────────────────────────────────────────────┤
│  Tier 2: Platform                                       │
│  Scoped to a logical platform or service group.         │
│  Configured at deployment/runtime level.                │
├─────────────────────────────────────────────────────────┤
│  Tier 3: Application  (optional)                        │
│  Scoped to a specific application.                      │
│  Configured in app-level Kest configuration.            │
├─────────────────────────────────────────────────────────┤
│  Tier 4: Function-level                                 │
│  The `policy=` parameter on the Verification Hook.      │
│  Supplements — does not replace — higher-tier policies. │
└─────────────────────────────────────────────────────────┘
```

**Policy evaluation pseudocode:**

```
function tiered_policy_evaluate(entry_id, config, hook_policies, context, engine):
  all_results = {]

  // Tier 1 — Enterprise Baseline (minus active deviations)
  for policy in config.enterprise_policies:
    if policy not in context.environment.active_deviations:
      evaluate_or_raise(entry_id, policy, context, engine)

  // Tier 2 — Platform
  for policy in config.platform_policies:
    if policy not in context.environment.active_deviations:
      evaluate_or_raise(entry_id, policy, context, engine)

  // Tier 3 — Application (optional)
  for policy in config.app_policies:
    if policy not in context.environment.active_deviations:
      evaluate_or_raise(entry_id, policy, context, engine)

  // Tier 4 — Function-level
  for policy in hook_policies:
    evaluate_or_raise(entry_id, policy, context, engine)

  return true
```

**Configuration schema** (runtime/deployment level):

```json
{
  "kest": {
    "enterprise_policies": ["baseline-auth", "data-classification"],
    "platform_policies":   ["payments-pci", "payments-audit"],
    "app_policies":        ["checkout-fraud-check"],
    "deviations": [
      {
        "scope":    "process_refund",
        "policy":   "payments-pci",
        "tier":     "platform",
        "reason":   "Refund flow operates on already-cleared transactions",
        "approver": "security-team@example.com"
      }
    ]
  }
}
```

**Key invariants:**

| Invariant | Description |
|---|---|
| Deviations are configuration, not code | Developers MUST NOT be able to declare deviations in application code. Deviations are operator/security-team approved and stored in deployment configuration. |
| Deviations are signed | Because `policy_context.deviations` is part of the `KestEntry` payload, the presence and content of every deviation is cryptographically auditable. |
| Deviations do not bypass recording | An invocation with active deviations MUST still produce a complete, signed `KestEntry` and MUST be appended to the Passport. |
| Empty deviation list is normal | Most invocations will have `deviations: []`. The field MUST always be present so audit tools can distinguish "no deviations" from "field absent — possibly tampered". |

---

## 10. Telemetry & Audit Specification

### 10.1 OTel Span / Log Record

After each Verification Hook execution, the following attributes MUST be present on the emitted [OTel](https://opentelemetry.io/docs/specs/) record:

| Attribute Key | Type | Value |
|---|---|---|
| `kest.signature` | string | Full JWS compact string of the current entry |
| `kest.parent_hash` | string | SHA-256 hex of previous JWS, or `"0"` |
| `kest.passport` | string | JSON-serialized Passport (all entries) |
| `kest.entry_id` | string | UUID v7 of the current entry |
| `kest.workload_id` | string | workload_id from IdentityProvider |
| `kest.trust_score` | int | Trust score of the current entry |
| `kest.operation` | string | Operation name |

### 10.2 Instrumentation Scope

All Kest telemetry MUST use:

- **Scope name**: `kest.core`
- **Span/record name pattern**: `kest.verified.<operation_name>`

### 10.3 Exporters

The `KestTelemetry.setup()` helper MUST support at minimum:

| `exporter_type` | Description |
|---|---|
| `"otlp"` | Exports via OTLP gRPC (default port 4317) or HTTP (4318) |
| `"file"` | Writes JSON-formatted spans to a local file |
| `"sqlite"` | Writes spans to a SQLite database for local auditing |

### 10.4 Audit Verification Workflow

External auditors can verify the audit trail without access to the original services:

```
1. Collect OTel spans containing kest.signature attributes for a trace.
2. Order spans by kest.chain_tip / parent_hash linkage.
3. Reconstruct the Passport: entries = [span.kest.signature for span in ordered_spans]
4. Call PassportVerifier.verify(passport, providers=spire_trust_bundle)
5. If verification passes, the audit trail is cryptographically proven unaltered.
```

---

## 11. Edge Case Handling

### 11.1 Policy Sidecar Unreachable

- **Condition**: TCP connection refused, HTTP timeout, or non-200 response from the policy sidecar.
- **Required behaviour**: Immediately treat as denial. Raise an authorization error that halts the protected operation. Do NOT retry automatically — retry policy is the operator's responsibility at the infrastructure level.
- **Configurable**: The engine `timeout` parameter controls how long to wait before treating the sidecar as unreachable. Default: 1.0 seconds.

### 11.2 Identity Provider Unavailable

- **Condition**: Identity socket not found, cloud KMS API error, token file missing.
- **Required behaviour**: Raise an error during initialization or during `sign()`. The Verification Hook MUST propagate this error upward, preventing execution of the protected operation.
- **No fallback signing**: The implementation MUST NOT fall back to an unsigned audit entry.

### 11.3 Oversized Passport (Claim Check)

- **Condition**: Serialized Passport exceeds 4096 bytes (configurable).
- **Required behaviour**: Engage the Claim Check pattern (§8.3). Store full Passport in `CacheProvider`. Propagate only `kest.claim_check=<uuid>`. If no `CacheProvider` is configured, raise a configuration error.

### 11.4 Claim Check Not Found

- **Condition**: Downstream middleware receives `kest.claim_check` but the UUID is not in the configured cache (expired TTL or cache restart).
- **Required behaviour**: Raise an exception. Do NOT proceed with an empty passport — this would break the chain.

### 11.5 Clock Skew

- **The `timestamp_ms` field in KestEntry MUST NOT be used for validating execution order.**
- Order is determined exclusively by the cryptographic `parent_ids` hash linkage.
- Timestamps are informational only (for human inspection and approximate forensic timing).

### 11.6 Empty Policy List

- **Condition**: Verification Hook configured with an empty policy list.
- **Required behaviour**: Reject at configuration time (raise an error), not at execution time.

### 11.7 Concurrent Execution (Async / Parallel)

- The Kest context (Passport, baggage) MUST be scoped to the execution context of the current async task or thread. Concurrent tasks MUST NOT share a mutable Passport state.
- Each branching concurrent task creates an independent sub-chain rooted at the last shared entry.

---

## 12. Compliance Mappings

### 12.1 [NIST SP 800-207](https://doi.org/10.6028/NIST.SP.800-207) (Zero Trust Architecture)

| NIST Tenet | Kest Mechanism |
|---|---|
| Tenet 2: Secure all communication regardless of location | [SPIRE](https://spiffe.io/) X509-SVIDs sign all execution payloads; network assumed hostile |
| Tenet 3: Per-session resource access grants | Verification Hook evaluates policies per invocation, per request |
| Tenet 4: Dynamic policy via attributes | [OPA](https://www.openpolicyagent.org/) / [Cedar](https://www.cedarpolicy.com/) ABAC on `trust_score`, `taints`, `user`, `agent` |
| Tenet 6: Strict enforcement before access | Policy sidecar evaluated BEFORE protected operation executes |

### 12.2 SOC 2 Type II

| Control | Kest Mechanism |
|---|---|
| CC6.1 (Logical access security) | Granular ABAC policies; execution blocked without policy authorization |
| CC7.2 (Anomaly monitoring) | Non-fungible OTel audit trail; Merkle-linked entries resist tampering |

### 12.3 PCI-DSS v4.0

| Requirement | Kest Mechanism |
|---|---|
| Req. 7 (Need-to-know access control) | Chinese Wall policies (Brewer-Nash) track cross-domain lineage |
| Req. 10 (Log and monitor all access) | Merkle-linked JWS audit trail signed by short-lived SPIRE SVIDs; tamper-evident by construction |

---

## 13. Implementation Guidance

This section provides sufficient detail for an independent team to implement a conformant Kest library in any language (Go, Java, TypeScript, Rust, etc.).

### 13.1 Minimum Viable Implementation Checklist

A minimum viable Kest implementation MUST provide:

- [ ] `IdentityProvider` interface (at minimum: one production-grade implementation, e.g., `SPIREProvider` or `AWSWorkloadIdentity`)
- [ ] RFC 8785 JSON canonicalization
- [ ] [EdDSA (Ed25519)](https://datatracker.ietf.org/doc/html/rfc8037) signing — [JWS compact](https://datatracker.ietf.org/doc/html/rfc7515) format
- [ ] SHA-256 hashing
- [ ] `KestEntry` schema construction and validation
- [ ] `Passport` with `serialize()`, `deserialize()`, `add_signature()`
- [ ] `PassportVerifier` with full Merkle + JWS verification
- [ ] `PolicyEngine` interface with at least `MockPolicyEngine`
- [ ] **Verification Hook** implementing the normative 13-step lifecycle (§5.8)
- [ ] `DefaultTrustEvaluator` with weakest-link formula
- [ ] [OTel Baggage](https://opentelemetry.io/docs/specs/otel/baggage/api/) context read/write for `kest.passport`, `kest.user`, `kest.agent`, `kest.task`
- [ ] `BaggageManager` with Claim Check support

A full-featured implementation additionally provides:

- [ ] `SPIREProvider` ([SPIFFE Workload API](https://spiffe.io/)), `AWSWorkloadIdentity`, `BedrockAgentIdentity`, `OIDCIdentity`
- [ ] `OPAPolicyEngine` ([OPA](https://www.openpolicyagent.org/)), `CedarPolicyEngine` ([Cedar](https://www.cedarpolicy.com/)), `CedarLocalEngine`, `AVPPolicyEngine` ([AVP](https://docs.aws.amazon.com/verified-permissions/))
- [ ] **Server-Side Lineage Interceptor** and **Server-Side Identity Interceptor** integrated with the target HTTP framework
- [ ] **Outbound Propagator** integrated with the target HTTP client library
- [ ] Telemetry bootstrap helper
- [ ] Lineage visualiser CLI tool
- [ ] `WeightedTrustEvaluator` example

### 13.2 Critical Implementation Notes

1. **[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) is non-negotiable.** This is the single most critical requirement for polyglot interoperability. If two language implementations produce different canonical byte arrays for the same `KestEntry`, their Passports are incompatible. Use a well-tested JCS library (e.g., `serde_jcs` in Rust, `canonicalize` in Go, `@erdtman/canonicalize` in TypeScript).

2. **SHA-256 of the full JWS compact string.** The `parent_ids[0]` is the SHA-256 of the complete compact JWS string including all three dot-separated segments: `"header.payload.signature"`.

3. **Integer arithmetic for trust scores.** Use floor division (e.g., `//` in Python, `/` on integer types in Go/Java/Rust). Floating-point arithmetic MUST NOT be used in trust score computation.

4. **OTel context is the source of truth for Passport propagation.** Do not thread Passport state through function arguments or process-level globals. Use the [OTel Context API](https://opentelemetry.io/docs/specs/otel/context/) as the ambient store.

5. **Policy evaluation before execution.** The protected operation MUST NOT execute if policy returns false.

6. **`removed_taints` requires explicit declaration.** A node cannot silently drop taints from its ancestors. The signed payload makes sanitization publicly auditable.

7. **Root nodes use `parent_ids: ["0"]`.** The string `"0"` (not integer zero, not null, not empty string) is the canonical sentinel for a chain root.

8. **Task-local context.** The OTel context (and therefore the Passport) MUST be propagated using the language's idiomatic async/concurrent context mechanism (e.g., Python `contextvars`, Go `context.Context`, Java `ScopedValue`). Never use process-level globals.

### 13.3 Test Cases Every Implementation Must Pass

These are not examples — they are normative test cases:

**TC-01: Root entry hash**
> Given a single-entry Passport with `parent_ids: ["0"]`, `PassportVerifier.verify()` MUST succeed without checking the "0" as a hash.

**TC-02: Merkle chain break detection**
> Given a 3-entry Passport where the second entry's payload is modified after signing, `PassportVerifier.verify()` MUST raise an error on the third entry's `parent_ids` mismatch.

**TC-03: JWS signature tampering detection**
> Given a 2-entry Passport where the first entry's signature bytes are altered, `PassportVerifier.verify()` MUST raise a cryptographic verification error.

**TC-04: Trust score weakest-link**
> Given a root entry with `trust_score=10` (internet) followed by a node with `source_type="internal"` (self_score=100), the second entry's `trust_score` MUST equal `(10 * 100) // 100 = 10`.

**TC-05: Trust override bypasses evaluator**
> Given a node with `trust_override=100` and parent `trust_score=10`, the node's `trust_score` MUST be 100.

**TC-06: Taint accumulation**
> Given parent taints `["a", "b"]`, `added_taints=["c"]`, `removed_taints=["b"]`, the result `taints` MUST be `["a", "c"]` (sorted).

**TC-07: Authorization error halts execution**
> Given a `MockPolicyEngine` configured to return `false`, the protected operation MUST NOT execute, and an authorization error MUST be raised.

**TC-08: Multi-policy logical AND**
> Given policies `["allow_all", "deny_all"]` where `allow_all → true` and `deny_all → false`, the protected operation MUST NOT execute.

**TC-09: Sidecar timeout is denial**
> Given an `OPAPolicyEngine` pointing to a non-existent address, `evaluate()` MUST raise an error (not return true).

**TC-10: RFC 8785 determinism**
> The JSON object `{"z": 3, "a": 1, "m": 2}` MUST canonicalize to the byte string `{"a":1,"m":2,"z":3}` in every conformant implementation.

**TC-11: Claim Check round-trip**
> Given a Passport that exceeds the size threshold and a configured `CacheProvider`, `BaggageManager.store()` MUST return `{"kest.claim_check": <uuid>}` and `BaggageManager.restore({"kest.claim_check": <uuid>})` MUST return the original Passport.

**TC-12: Context accessor fallback**
> When no `user` is passed to the Verification Hook and `kest.user` is set in OTel Baggage, `get_current_user()` MUST return the baggage value within the protected operation's execution scope.

---

## 14. Normative Standards References

The following documents are normative. Conformant implementations MUST adhere to them.

| Standard | Description | URL |
|---|---|---|
| RFC 7515 | JSON Web Signature (JWS) | https://datatracker.ietf.org/doc/html/rfc7515 |
| RFC 8037 | Ed25519 / EdDSA in JOSE | https://datatracker.ietf.org/doc/html/rfc8037 |
| RFC 8785 | JSON Canonicalization Scheme (JCS) | https://www.rfc-editor.org/rfc/rfc8785 |
| RFC 9562 | UUID v7 — Time-Ordered Universally Unique Identifiers | https://datatracker.ietf.org/doc/html/rfc9562 |
| W3C Trace Context | Distributed tracing propagation | https://www.w3.org/TR/trace-context/ |
| W3C Baggage | HTTP context propagation | https://www.w3.org/TR/baggage/ |
| SPIFFE Standards | Workload identity specification | https://spiffe.io/ |
| SPIFFE Workload API | gRPC API for SVID retrieval | https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md |
| OpenTelemetry | Observability specification | https://opentelemetry.io/docs/specs/ |
| NIST SP 800-207 | Zero Trust Architecture | https://doi.org/10.6028/NIST.SP.800-207 |

The following documents are informative references for policy engine integrations:

| System | Description | URL |
|---|---|---|
| Open Policy Agent | Rego-based policy engine | https://www.openpolicyagent.org/docs/latest/ |
| Cedar Policy Language | AWS Cedar authorization language | https://www.cedarpolicy.com/ |
| AWS Verified Permissions | Managed Cedar service | https://docs.aws.amazon.com/verified-permissions/ |
| AWS KMS | Signing key management | https://aws.amazon.com/kms/ |

---

## 15. Reference Implementations

This section documents how the normative specifications in this document are realized in the **Python reference implementation**. These details are informative, not normative. Other language implementations MAY follow different idioms while conforming to the same contracts.

### 15.1 Python / PyO3 Binding

| Spec Concept | Python Implementation |
|---|---|
| Verification Hook | `@kest_verified` function decorator (using `functools.wraps`) |
| Server-Side Lineage Interceptor | `KestMiddleware` — a Starlette-compatible ASGI middleware class |
| Server-Side Identity Interceptor | `KestIdentityMiddleware` — ASGI middleware; validates Bearer JWT, writes to OTel Baggage |
| Outbound Propagator | `KestTransport` — an `httpx` transport wrapper that injects `baggage` headers |
| Telemetry Bootstrap | `KestTelemetry.setup()` — configures the OTel Python SDK |
| Lineage Visualiser _(recommended)_ | `kest-viz` CLI — reads SQLite/JSON OTel exports and renders a Merkle DAG (output format: implementer's choice) |
| RFC 8785 Canonicalization | Rust `serde_jcs` via PyO3 bindings in `kest-core-rs` |
| Async context propagation | Python `contextvars.ContextVar` via the OTel Python SDK context API |

### 15.2 Idiom Mapping for Other Languages

| Language | Verification Hook idiom | Interceptor idiom | Context propagation |
|---|---|---|---|
| Go | Exported wrapper function / middleware handler | `net/http` middleware | `context.Context` |
| Java | Annotation + AspectJ or CDI interceptor | Servlet filter / Spring interceptor | `ThreadLocal` / `ScopedValue` |
| TypeScript / Node | Higher-order function wrapper | Express/Fastify middleware | `AsyncLocalStorage` |
| Rust | Closure wrapper / proc-macro attribute | Tower `Layer` | `tokio::task_local!` |

---

*This document is the authoritative specification for Kest v0.3.0. An independent team or agent equipped with this specification, the normative standards listed in §14, and a working knowledge of [OpenTelemetry](https://opentelemetry.io/) MUST be able to produce a fully conformant Kest implementation in any language without consulting the Python reference implementation.*
