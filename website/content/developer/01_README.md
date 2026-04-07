# Developer Guide

Welcome to the Kest Developer Guide. This section provides step-by-step tutorials, architectural deep-dives, and integration patterns for building high-fidelity Zero Trust systems.

Kest is designed to be **Secure by Architecture**. By following these guides, you will move beyond peripheral security (firewalls and API keys) toward **Continuous Verification** and **Verifiable Execution Lineage**.

---

## 🛤️ The Path to Mastery

Whether you are securing a single microservice or orchestrating a distributed intelligence swarm, we recommend following this progression:

### 🐣 1. Fundamentals
Get up and running with the Kest core and understand the mental model behind the framework.
- **[Getting Started](getting_started.md)**: Your first 10 minutes with Kest—installation, configuration, and basic protection.
- **[The Trust Model](trust_model.md)**: Deep-dive into Identity-First security, SPIFFE attestation, and Merkle DAG chains.

### 🛠️ 2. Integration Patterns
Learn how to weave Kest into your existing application stacks with minimal friction.
- **[Decorators & Trust Scores](decorators.md)**: Using `@kest_verified` to enforce policies and manage complex execution taints.
- **[Identity & Resource Context](identity_context.md)**: Passing `user`, `agent`, `task`, and `resource_attr` for fine-grained, identity-aware ABAC enforcement.
- **[Middleware & Context Propagation](middleware.md)**: Automatically passing the Merkle lineage and JWT identity across FastAPI, HTTPX, and background workers.

### 🔬 3. Observability & Assurance
Verify that your system is behaving as expected and maintain a non-fungible audit trail.
- **[Lineage Visualization](visualization.md)**: Generating Mermaid.js Merkle DAGs from your execution history.
- **[Testing & Verification](testing.md)**: Best practices for TDD in Zero Trust environments.
- **[Kest Lab (E2E Simulation)](kest_lab.md)**: Using our distributed Docker lab to simulate real-world attacks and multi-hop trace leakage.

---

## 🧠 The Kest Way: Design Principles

As you navigate these guides, keep the following core principles in mind:

1.  **Identity is the Perimeter**: Every action requires a cryptographically verified workload identity (SVID).
2.  **No Blind Trust**: Use the `kest_verified` trust scores to dynamically adjust behavior based on a request's lineage.
3.  **Audit is Data**: Your execution history is as valuable as your business data. Treat it as a first-class, tamper-evident citizen.

---
*For low-level implementation details, see the [API Reference](../reference/README.md). For ready-to-use security models, explore the [Policy Library](../policies/README.md).*
