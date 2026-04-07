# API Specification

The Kest API Specification defines the technical contracts and data models that govern the framework's behavior. Kest follows an **Interface-First** philosophy, ensuring that its core cryptographic and policy logic remains stable across language bindings and execution environments.

This reference provides detailed documentation for the primary modules, controllers, and data types used by the `kest-core` library.

---

## 🏗️ Core Modules

The Kest toolkit is architected as a series of decoupled modules, each responsible for a specific pillar of the Zero Trust framework.

### 🍱 1. Universal Data Models
The foundational structures used to represent and verify execution history and trust state.
- **[Models & Models](models.md)**: Specifications for **Passports** (Merkle DAGs), **Evidence**, and **Taints**.
- **Lineage Verification**: Deep-dive into the `PassportVerifier` and JWS signature standards.

### 🔑 2. Identity Providers
The sources of truth for workload attestation and cryptographic signing.
- **[Identity Controllers](identity.md)**: Support for **SPIFFE/SPIRE** (SVIDs), AWS IAM/KMS, and OIDC tokens.
- **Auto-Detection**: How the `AutoDetector` chooses the optimal provider for your runtime environment.

### 🛡️ 3. Policy Engines
Unified evaluation interfaces that bridge the gap between different policy languages.
- **[Enforcement Engines](engine.md)**: API reference for **Rego (OPA)** and **Cedar** local/remote evaluators.
- **Engine Parity**: Understanding the unified `evaluate()` and `async_evaluate()` interface.

### 🚦 4. Developer Surface
The primary interfaces developers use to integrate Kest into their applications.
- **[Decorators & Hooks](decorators.md)**: Detailed specification for `@kest_verified` and execution hooks.
- **Context Propagation**: Technical details of the **OTel Baggage** and **Claim-Check** propagation patterns.

---

## 📐 Design Philosophy

When interacting with the Kest API, keep the following technical standards in mind:

1.  **Immutability**: Data structures representing lineages (Passports) are immutable. Every change results in a new, signed node.
2.  **Language Agnostic**: While the primary bindings are in Python, the underlying contracts are designed to be implemented in any language supported by the Rust core (`kest-core-rs`).
3.  **Open Standard Alignment**: Kest strictly adheres to W3C Trace Context, OpenTelemetry, and SPIFFE standards for maximum interoperability.

---
*For high-level guides and tutorials, see the [Developer Guide](../developer/README.md). For ready-to-use security models, explore the [Policy Library](../policy/README.md).*)
