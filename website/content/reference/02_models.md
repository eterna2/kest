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

Handles the hybrid propagation of lineage data in **OpenTelemetry (OTel) Baggage** using a three-tier strategy:

| Tier | Baggage Key | Condition |
|---|---|---|
| 1 — Inline | `kest.passport` | Passport ≤ 4 KB uncompressed |
| 2 — Compressed Inline | `kest.passport_z` | zlib-compressed size ≤ 4 KB |
| 3 — Claim Check | `kest.claim_check` | Exceeds both thresholds |

This handles chains from 1 to 50+ hops without exceeding HTTP header limits. A 10-hop chain (~5 KB raw) compresses to ~1.5 KB and propagates inline as `kest.passport_z`, avoiding the cache lookup entirely.

Consumers **MUST** handle all three tiers. Producers **MAY** skip Tier 2 and fall directly to Tier 3.

---

### `ORIGIN_TRUST_MAP` / `SOURCE_TRUST_MAP`

Standard trust scores for root nodes based on their origin. Scores are **integers (0–100)** as of v0.3.0.

| Origin | Score |
|---|---|
| `system` / `internal` | `100` |
| `verified_rag` | `90` |
| `third_party_api` | `60` |
| `user_input` | `40` |
| `internet` | `10` |
| `llm` | `0` |

`SOURCE_TRUST_MAP` is retained as a backward-compatibility alias for `ORIGIN_TRUST_MAP`.

### `Passport` Properties

| Property | Type | Description |
|---|---|---|
| `entries` | `List[str]` | Ordered list of JWS signatures (the Merkle chain) |
| `trust_scores` | `List[int]` | Trust score of each entry (cached, O(1) after first read) |
| `accumulated_taints` | `set` | Union of all taints across all entries (cached) |

> **Performance note:** `accumulated_taints` and `trust_scores` are read from a parsed-entries cache. The cache is invalidated on every `add_signature()` call. See [GitHub #12](https://github.com/eterna2/kest/issues/12) for planned O(1) incremental accumulation.
