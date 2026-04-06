---
title: Models
description: Core data structures for execution lineage and trust.
sidebarTitle: passport.json
sidebarCode: |
  {
    "entries": [
      {
        "jws": "header.payload.sig",
        "parents": ["0"],
        "node_id": "root"
      }
    ]
  }
---

The `kest.core.models` module defines the core data structures used by Kest to represent execution lineage and trust.

The `kest.core.models` module defines the core data structures used by Kest to represent execution lineage and trust.

---

### `Passport`

Represents a verifiable execution graph (lineage). A `Passport` is a collection of JWS-formatted audit entries that form a **Merkle DAG** (Directed Acyclic Graph). Each entry points to its parents via their cryptographic hashes.

#### Methods
- **`add_signature(signature)`**: Appends a new JWS signature (audit entry) to the passport.
- **`serialize() -> str`**: Serializes the passport entries to a JSON string.
- **`deserialize(data) -> Passport`**: Creates a Passport instance from a serialized JSON string.

---

### `PassportVerifier`

Utility to verify the integrity and authenticity of a Passport chain. The verifier checks both the cryptographic signatures and the Merkle links between entries.

---

### `TrustEvaluator` (CARTA)

Abstract base class for Continuous Adaptive Risk and Trust Assessment. TrustEvaluators define how trust scores are propagated and attenuated through the execution graph.

#### `DefaultTrustEvaluator`
Uses a "weakest link" model: the current trust is the minimum of parent trust scores multiplied by the current workload's score.

---

### `BaggageManager`

Handles the hybrid propagation of lineage data in **OpenTelemetry (OTel) Baggage**.

#### Hybrid Pattern
- **Inline Propagation**: For small passports, data is stored directly in the baggage headers.
- **Claim-Check Pattern**: For larger lineages, the manager stores the data in an external cache and propagates only a `claim_id` to avoid exceeding HTTP header limits.

---

### `SOURCE_TRUST_MAP`

Standard trust scores for root nodes based on their origin:
- `system`: 1.0
- `verified_rag`: 0.9
- `third_party_api`: 0.6
- `user_input`: 0.4
- `llm`: 0.0
