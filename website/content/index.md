# Introduction

Kest (Key + Trust) is a distributed Zero Trust architecture designed to solve the **Secret Zero** problem and enforce high-fidelity execution lineage across polyglot microservices.

## The Problem

Modern distributed systems rely on perimeter security, API gateways, and static API keys. Once an attacker breaches the perimeter or compromises a key (the "Secret Zero" problem), they can laterally move through the network with impunity. Traditional logging solutions are fungible; logs can be altered, dropped, or spoofed by compromised nodes, rendering compliance and post-breach analysis difficult.

## The Kest Solution

Kest combines **Workload Identity (SPIFFE)**, **Policy as Code (OPA/Cedar)**, and **Cryptographic Lineage (Merkle DAGs)** into a cohesive toolkit.

1.  **Identity, Not Keys**: Services do not use static API keys. They use short-lived, dynamically rotated X509-SVIDs provided by SPIRE.
2.  **Cryptographic Lineage**: Every execution hop is cryptographically signed using RFC 8785 JSON Canonicalization and linked to its parent's signature hash. This creates a tamper-evident Merkle DAG of the request's journey.
3.  **Continuous Verification**: At every hop, Policy Engines (OPA/Cedar sidecars) evaluate the *entire cryptographic lineage*, not just the immediate caller, enabling true Continuous Adaptive Risk and Trust Assessment (CARTA).
4.  **Non-Fungible Audit Trails**: The verified lineage is exported as OpenTelemetry spans, creating an immutable, cryptographically verifiable audit log.

## Target Audiences

-   **Security & Crypto Engineers**: Dive into the [Architecture & Design](design/secret_zero.md) to understand how we mitigate replay attacks, clock skew, and ensure non-fungible logging.
-   **Platform & Infra Engineers**: Explore the [Platform & Infrastructure](infra/spire.md) section to learn how to deploy SPIRE, configure OPA/Cedar sidecars, and manage OTel collectors.
-   **Application Developers**: Check out the [Developer Guide](developer/getting_started.md) to see how simple it is to secure your functions using the `@kest_verified` decorator and our automatic HTTP transport middleware.
