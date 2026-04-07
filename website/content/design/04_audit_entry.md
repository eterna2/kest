# Audit Entry Specification

This document defines the schema and cryptographic properties of a Kest audit entry. Developers can use this specification to build custom verifiers or integrate Kest's non-fungible audit trail into external security platforms.

## The Passport Entry (JWS)

Each hop in an execution lineage produces a **JSON Web Signature (JWS)**. A JWS consists of three base64url-encoded parts separated by periods: `header.payload.signature`.

### 1. The Header

```json
{
  "alg": "EdDSA",
  "typ": "JWS"
}
```

- **alg**: Cryptographic algorithm. Currently `EdDSA` (Ed25519) via the Rust PyO3 core.
- **typ**: Always `JWS` for Kest audit entries.

### 2. The Payload (KestEntry)

The payload contains the execution metadata. Before signing, this JSON object is canonicalized using **RFC 8785 (JCS)** via `serde_jcs` in the Rust core, ensuring byte-identical serialization regardless of runtime or language.

```json
{
  "entry_id": "e5bb092f-6f0f-4e12-9f3e-c3cadf64e194",
  "operation": "func_sanitizer",
  "classification": "system",
  "trust_score": 100,
  "parent_ids": ["31a2f90fb8aeda526638948834a5fd599cf0a6fa7119817d48c2efadeec3dc5b"],
  "added_taints": [],
  "removed_taints": ["malicious_input"],
  "taints": ["untrusted_source"],
  "labels": {
    "principal": "spiffe://kest.internal/workload/hop2",
    "kest.identity": "{\"user\": \"alice-uuid\", \"agent\": \"kest-agent\"}",
    "trace_id": "cafb9a789e16bd9cdcb0a70c3fdaf60e"
  },
  "environment": {},
  "otel_context": {},
  "metadata": null,
  "content_hash": "",
  "input_hash": "",
  "timestamp_ms": 1775494770269
}
```

| Field | Type | Description |
|---|---|---|
| `entry_id` | `string` | UUID v4 unique to this execution event. |
| `operation` | `string` | Name of the decorated Python function. |
| `classification` | `string` | Data classification (`"system"` by default). |
| `trust_score` | `int` | Integer trust score (0–100) at time of execution. |
| `parent_ids` | `array[string]` | SHA-256 hash(es) of parent JWS entries. Root nodes use `["0"]`. |
| `added_taints` | `array[string]` | New risk taints introduced at this node. |
| `removed_taints` | `array[string]` | Taints explicitly removed at this node (sanitizers). |
| `taints` | `array[string]` | Accumulated taints from all ancestors plus `added_taints` minus `removed_taints`. |
| `labels` | `dict` | Arbitrary key-value metadata (principal, trace ID, identity, etc.). |
| `timestamp_ms` | `int` | Epoch milliseconds of the execution. |

### 3. The Signature

The Ed25519 signature is computed over:

```
ASCII(base64url(UTF8(header)) || '.' || base64url(JCS(payload)))
```

Where `JCS(payload)` is the RFC 8785 canonical JSON of the payload object. This is computed in Rust via `serde_jcs` and signed via `ed25519-dalek`.

## Merkle-Link Verification

To verify a Passport chain `[JWS₁, JWS₂, …, JWSₙ]`:

1. **Start** with `last_hash = "0"`.
2. **Decode** the payload of `JWSᵢ`.
3. **Assert** `JWSᵢ.payload.parent_ids[0] == last_hash`.
4. **Verify** the Ed25519 signature of `JWSᵢ` against the public key of its signer.
5. **Compute** `last_hash = SHA-256(JWSᵢ)` (the full compact JWS string).
6. **Repeat** for `JWSᵢ₊₁`.

If any step fails, the lineage is invalid (tampered or replayed).

```python
from kest.core.models import Passport, PassportVerifier

passport = Passport.deserialize(baggage_json_string)
PassportVerifier.verify(passport, providers={
    "spiffe://kest.internal/workload/hop1": hop1_identity_provider,
})
```

## Taint Audit Trail

Because `added_taints`, `removed_taints`, and `taints` are all in the **signed** payload, the following properties are cryptographically guaranteed:

- **Taint attribution**: Any verifier can determine exactly which node introduced a taint.
- **Sanitizer accountability**: A `removed_taints` field proves a specific node claimed to clean that taint. Disputes are resolved by re-running the verifier against the signed chain.
- **Non-repudiation**: Neither the service that added a taint nor the one that removed it can deny their action without invalidating their signature.
