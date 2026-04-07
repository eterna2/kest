# Kest v0.3.0 Requirements & Specifications

## 1. Overview and Core Philosophy

Kest provides a cryptographic distributed auditing and lineage-tracking mechanism for polyglot microservice architectures. The core requirement is that an execution context within any service must retain cryptographic proof of its authorization and data lineage across service boundaries.

In `v0.3.0`, the core engine is decoupled from strict SPIFFE integration, introduces a high-performance Rust core (via PyO3 for Python), integrates natively with OpenTelemetry (OTel), and delegates authorization logical assertions to dynamic execution engine Sidecars (OPA, Cedar, AVP).

## 2. Core Abstractions

### 2.1 Identity Providers (`IdentityProvider` protocol)

A workload must establish its identity securely and sign payloads.

Protocol Requirements
: `get_workload_id() -> str`: Returns the unique string identifying the workload (e.g., `spiffe://...`, `arn:aws:iam::...`).
: `sign(payload: bytes) -> str`: Cryptographically signs the payload (often wrapped as a JWS).

Implementations
: `SPIREProvider`: Uses `spiffe-python` for short-lived X509-SVIDs.
: `AWSWorkloadIdentity`: Identifies via STS, signs with KMS or local Ed25519.
: `AgentcoreIdentity`: Simulates JWT identity fetching.
: `OIDCIdentity`: Generic provider using basic OIDC flows.
: `StaticIdentity`: Fallback local keys.

### 2.2 Policy Engines (`PolicyEngine` protocol)

Kest core does not compile or parse Rego/Cedar. It relies on fail-secure HTTP delegation.

Protocol Requirements
: `evaluate(entry_id: str, policy_names: List[str], context: Dict[str, Any]) -> bool`

Implementations
: `OPASidecarEngine`: Polls `localhost:8181/v1/data/kest/{policy}`.
: `CedarSidecarEngine`: Polls `localhost:8180/is_authorized`.
: `AmazonVerifiedPermissionsEngine`: Formats REST request payloads for AWS AVP.

### 2.3 Passport and Lineage
A Kest Passport is a JSON structure containing sequential executed entries (`entries: List[str]`, where each entry is a JWS signature).

- Each signature payload strictly adheres to **RFC 8785** (JCS - JSON Canonicalization Scheme) to ensure deterministic hashing across polyglot components.
- Lineage linkage operates via a `parent_entry_ids` field in the payload that securely links child actions to their cryptographic parent hashes forming a **Merkle DAG**.

## 3. Polyglot Architecture & Rust Core (`kest-core-rs`)
Because deterministic canonicalization and hashing are language-sensitive, `v0.3.0` standardizes the critical path in a pure Rust library.

- Python wraps this Rust library using `PyO3`.
- Rust enforces the ABI, memory-safe cryptographic bindings, and RFC 8785 parsing.

## 4. Telemetry and Observability
Kest no longer builds custom transport protocols for audit aggregation.

- Kest objects (`Passports`, `Signatures`, `parent_lineage`) are propagated and injected as native `OpenTelemetry` span attributes (e.g., `kest.passport`, `kest.lineage_root`).
- Helpers like `KestTelemetry` provide effortless bootstrapping for OTLP, Local JSON file, or SQLite exporters.

## 5. Security & Delegation Assurances

- **Fail-Secure Defaults**: Any failure to reach a PolicyEngine, IdentityProvider, or any malformed canonical JSON results in immediate `False` evaluation / exceptions preventing execution.
- **Zero-Trust**: The framework assumes the network is compromised. Trust is verified strictly through cryptographic signature verification of the `parent_entry_ids`.

## 6. Implementation Re-Creation Constraints
An independent team armed with this spec should be able to implement Kest in Go, Java, or Node.js by:

1. Re-implementing the IdentityProvider bridging interface.
2. Generating RFC 8785 JSON of their execution scopes.
3. Signing it using Ed25519 (JWS).
4. Emitting the JWS array (`entries`) via OTel trace attributes `kest.passport`.
