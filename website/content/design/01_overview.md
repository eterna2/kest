# Architecture Overview: Why Kest?

Modern distributed systems are secured at the perimeter — firewalls, API gateways, and static API keys form the first and often the only line of defense. Once an attacker breaches this perimeter or compromises a single key, they move laterally through the network with impunity. Logs can be altered, dropped, or spoofed. Post-breach forensics becomes guesswork.

Kest exists because perimeter security is not enough.

## The Gap in Current Zero Trust

Zero Trust architectures (NIST SP 800-207) mandate "never trust, always verify." But most implementations stop at the authentication step — *is this caller who they claim to be?* They rarely ask the deeper question: *what is the full history of this request, and can I cryptographically prove it hasn't been tampered with?*

Consider a 3-hop microservice call:

```
User → API Gateway → Payment Service → Database Service
```

Traditional approaches verify identity at each hop independently. But if the Payment Service is compromised, it can:
1. Forge its identity in logs
2. Claim the request came from a different origin
3. Drop inconvenient audit records
4. Replay old, legitimate requests to the Database Service

These attacks are invisible to conventional logging because logs are **fungible** — mutable text files forwarded to a centralized system.

## The Kest Approach

Kest combines three pillars into a single, cohesive toolkit:

### 1. Workload Identity (SPIFFE/SPIRE)

Services do not use static API keys. They receive short-lived, automatically rotated X.509 certificates from SPIRE, where the infrastructure itself attests the workload's identity through kernel-level evidence. No shared secrets ever touch the wire.

*Spec Reference: §5.1 IdentityProvider, Principle P1*

### 2. Cryptographic Lineage (Merkle DAG)

Every execution hop produces a **KestEntry** — a JSON Web Signature (JWS) whose payload is canonicalized per RFC 8785 and whose `parent_ids` field hashes the preceding JWS. This creates a tamper-evident Merkle chain called the **Passport**. If any prior entry is altered, every subsequent hash breaks.

![Merkle chain linking three execution hops via SHA-256 parent hashes](/images/merkle-chain.png)

*Spec Reference: §4.1 KestEntry, §4.4 Passport, Principle P3*

### 3. Continuous Verification (OPA/Cedar)

At every hop, a co-located policy sidecar evaluates the *entire* cryptographic lineage — not just the immediate caller. This enables Continuous Adaptive Risk and Trust Assessment (CARTA): trust is a dynamic integer (0–100) that degrades through untrusted hops and can only be restored by explicitly declared, cryptographically signed sanitizers.

*Spec Reference: §9 Policy Engine, §7 Trust Model, Principle P2*

## What You Get

| Capability | Traditional | Kest |
|---|---|---|
| **Identity** | Static API keys | Ephemeral SPIRE SVIDs |
| **Audit** | Mutable JSON logs | Merkle-linked JWS signatures |
| **Authorization** | Per-hop RBAC | Full-lineage ABAC (OPA/Cedar) |
| **Trust** | Binary (auth/unauth) | Continuous integer 0–100 |
| **Tamper detection** | None | Cryptographic hash chain |
| **Cross-language** | Framework-specific | Spec-driven, language-agnostic |

## Target Audiences

-   **Security & Crypto Engineers** — dive into the [Design Principles](principles) and [Specification](kest_spec_v0.3.0) to understand our cryptographic guarantees.
-   **Platform & Infra Engineers** — explore the [Developer Guide](/developers/guide/getting_started) to deploy SPIRE, configure OPA/Cedar, and manage OTel collectors.
-   **Application Developers** — check out the [Getting Started](/developers/guide/getting_started) guide to see how simple it is to secure your functions with `@kest_verified`.

---

*The full normative specification is available in the [Kest v0.3.0 Spec](kest_spec_v0.3.0).*
