# Introduction

**Kest** (Key + Trust) is a toolkit for **cryptographically verifiable execution lineage** in distributed systems. It ensures that every action in a microservice chain is authenticated via workload identity, authorized via policy-as-code, and immutably recorded in a tamper-evident Merkle chain.

## The Problem: Perimeter Security is Not Enough

Modern distributed systems rely on firewalls, API gateways, and static secrets. Once compromised:

- **Lateral movement** — A stolen API key works anywhere in the network
- **Log tampering** — Compromised nodes can alter or drop audit records
- **Identity spoofing** — Tokens can be replayed or forged without detection
- **No provenance** — You can't prove *how* a request arrived, only *who* sent it

## Three Pillars of Kest

| Pillar | What It Does | Key Standards |
|---|---|---|
| **Workload Identity** | Eliminate the Secret Zero problem with platform attestation | SPIFFE/SPIRE, X.509 SVIDs |
| **Cryptographic Lineage** | Tamper-evident Merkle chain of signed audit entries | JWS (RFC 7515), JCS (RFC 8785) |
| **Continuous Verification** | Full-lineage policy evaluation at every hop | OPA/Cedar, CARTA trust model |

## Navigate the Documentation

### 📐 [Design Principles](/blog)
The eight immutable principles (P1–P8) that govern every design decision — from "Identity is the Perimeter" to "Fail-Secure by Default."

### 📖 [Journal](/blog)
Deep-dive articles on core concepts: the Secret Zero problem, Merkle DAG lineage, non-fungible audit, the 4-tier policy hierarchy, and edge case handling.

### 🔧 [Developer Guide](/developers/guide/getting_started)
Step-by-step: installation, `configure()`, `@kest_verified`, trust model, identity providers, middleware, and the full 13-step verification lifecycle.

### 🧪 [Testing & Kest Lab](/developers/guide/kest_lab)
Unit testing with mocks, 17 integration tests, Docker Compose lab with SPIRE, OPA, Cedar, and Keycloak.

### 📋 [Specification](/blog/design/kest_spec_v0.3.0)
The full normative v0.3.0 specification — data models, interfaces, algorithms, edge cases, and conformance tests.

### 📚 [API Reference](/developers/api)
Language-agnostic interface specifications for PolicyEngine, IdentityProvider, TrustEvaluator, and all core models.

## Quick Start

```python
from kest.core import configure, MockPolicyEngine, kest_verified

# Configure once at startup
configure(engine=MockPolicyEngine(allow=True))

# Protect any function
@kest_verified(policy="kest/allow_trusted", source_type="internal")
def process_data(payload: dict):
    return {"status": "processed"}

# Call normally — Kest handles identity, signing, policy, and audit
result = process_data({"key": "value"})
```
