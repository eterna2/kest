# KestEntry: The Non-Fungible Audit Schema

Every `KestEntry` is a self-contained, cryptographically signed audit record. Unlike traditional log lines — which are mutable text that can be silently altered — Kest entries are **non-fungible**: tamper-evident, non-repudiable, and permanently linked to their predecessors.

This article walks through the KestEntry schema field by field, explaining why each field exists and what compliance guarantee it provides.

## The KestEntry Schema (Spec §4.1)

```json
{
  "schema_version": "0.3.0",
  "runtime": {
    "name": "kest-python",
    "version": "0.3.0"
  },
  "entry_id":       "019746a2-3c4f-7da1-8b5f-2a1c3d4e5f67",
  "operation":      "process_payment",
  "classification": "system",
  "trust_score":    40,
  "parent_ids":     ["a1b2c3d4e5f6..."],
  "added_taints":   ["user_input"],
  "removed_taints": [],
  "taints":         ["user_input"],
  "labels": {
    "principal":          "spiffe://kest.internal/workload/payment-svc",
    "kest.identity":      "{\"user\":\"alice\",\"agent\":\"web-app\",\"task\":\"checkout\"}",
    "kest.resource_attr": "{\"amount\":150,\"currency\":\"USD\"}",
    "trace_id":           "4bf92f3577b34da6a3ce929d0e0e4736"
  },
  "policy_context": {
    "enterprise_policies": ["baseline-auth"],
    "platform_policies":   ["payments-pci"],
    "app_policies":        [],
    "function_policies":   ["kest/allow_trusted"],
    "deviations": []
  },
  "environment":  {},
  "otel_context":  {},
  "metadata":      null,
  "content_hash":  "e3b0c44298fc1c14...",
  "input_hash":    "7f83b1657ff1fc53...",
  "timestamp_ms":  1712150400000
}
```

## Field-by-Field Reference

### Versioning & Runtime

| Field | Purpose | Compliance Value |
|---|---|---|
| `schema_version` | Schema version of this entry format (F-AE-05) | Enables forward-compatible parsing by audit tools as the spec evolves |
| `runtime.name` | Which Kest library produced this entry (F-AE-06) | Cross-language diagnostics — identifies if an interop bug is language-specific |
| `runtime.version` | Semantic version of the library | Matches entries to known library releases for vulnerability tracing |

### Identity & Ordering

| Field | Purpose | Compliance Value |
|---|---|---|
| `entry_id` | UUID v7 — time-ordered, globally unique (F-AE-04) | Natural chronological ordering without secondary sorting. RFC 9562 guarantees uniqueness |
| `operation` | Name of the protected function (F-AE-07) | Maps audit entries to specific business operations for access reviews |
| `timestamp_ms` | Epoch milliseconds at entry creation (F-AE-12) | Approximate forensic timing. **Not** used for ordering — cryptographic hash chain supersedes (Spec §11.5) |

### Cryptographic Linkage

| Field | Purpose | Compliance Value |
|---|---|---|
| `parent_ids` | SHA-256 hash of the preceding JWS string, or `["0"]` for root (F-AE-08) | Creates the Merkle chain — tamper-evident ordering |
| `content_hash` | SHA-256 of the function's return value | Proves what the function produced |
| `input_hash` | SHA-256 of the function's input arguments | Proves what the function received |

### Trust & Taints

| Field | Purpose | Compliance Value |
|---|---|---|
| `trust_score` | Integer 0–100 (F-AE-09) | Quantified risk level — feeds into CARTA-based policy decisions |
| `added_taints` | New taint labels at this node (F-TT-02) | Traces where risk was introduced |
| `removed_taints` | Taints cleared at this node (F-TT-03) | Auditable sanitization — proves a node declared itself as a sanitizer |
| `taints` | Cumulative taint set: `(parent ∪ added) − removed` (F-AE-10) | Full risk profile visible to policy engines and auditors |

### Labels

| Field | Purpose | Compliance Value |
|---|---|---|
| `labels.principal` | The `workload_id` from the IdentityProvider (F-AE-11) | Who signed this entry — non-repudiable identity |
| `labels.trace_id` | OTel trace ID (F-AE-11) | Correlates audit entries with distributed traces |
| `labels.kest.identity` | JSON: `{user, agent, task}` (F-IC-04) | Fine-grained identity context for ABAC policies |
| `labels.kest.resource_attr` | JSON: resource attributes (F-IC-04) | ABAC resource attributes (e.g., document ID, sensitivity level) |

### Policy Context

| Field | Purpose | Compliance Value |
|---|---|---|
| `policy_context.enterprise_policies` | Enterprise baseline policies evaluated (F-AE-13) | Proves enterprise-level compliance was enforced |
| `policy_context.platform_policies` | Platform-scoped policies evaluated | Proves platform governance was applied |
| `policy_context.function_policies` | Function-level policies evaluated | Proves the specific access control was checked |
| `policy_context.deviations` | Active policy deviations at this invocation (F-PE-12) | Cryptographic proof of any compliance exemptions |

The `deviations` array is **always present** — an empty array `[]` means "no deviations were active." If the field is absent entirely, it indicates potential tampering (the signed payload is incomplete).

## Why Non-Fungible?

Traditional logs:
```
2024-03-15 10:23:45 INFO payment processed for user alice amount=150
```

This log line can be:
- ✗ Modified after the fact (change "alice" to "bob")
- ✗ Deleted silently
- ✗ Fabricated by a compromised service
- ✗ Reordered to hide a sequence of events

A KestEntry cannot be any of these things because:
- ✓ It is **signed** by the workload's private key (JWS/EdDSA)
- ✓ It is **hash-linked** to its predecessor (SHA-256 parent_ids)
- ✓ Its payload is **canonicalized** (RFC 8785) for deterministic verification
- ✓ Modification of any entry **breaks** every subsequent hash in the chain

## Compliance Mappings

| Standard | KestEntry Mechanism |
|---|---|
| **NIST SP 800-207** Tenet 6 | Policy evaluated before execution; decision recorded in `policy_context` |
| **SOC 2** CC7.2 | Tamper-evident audit trail via Merkle-linked JWS |
| **PCI-DSS v4.0** Req. 10 | Cryptographically signed, non-fungible access logs |
| **GDPR** Art. 30 | `kest.identity` and `kest.resource_attr` provide processing activity records |

---

*For how entries are chained into a Passport, see [Lineage Over Assertion](merkle_dag). For the full schema constraints, see [Spec §4.1](kest_spec_v0.3.0).*
