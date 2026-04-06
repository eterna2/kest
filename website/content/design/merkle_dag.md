# Cryptographic Lineage (Merkle DAG)

Kest replaces traditional, fungible log tracking with a cryptographically secure, non-repudiable audit trail known as the **Passport**.

## The Passport Structure

A Passport is an ordered collection of JSON Web Signatures (JWS). Every time a function protected by `@kest_verified` is executed, a new entry is generated, signed, and appended to the Passport.

### 1. Canonicalization (RFC 8785)

To prevent signature invalidation due to minor JSON formatting differences (e.g., whitespace, key ordering), Kest strictly adheres to **RFC 8785 JSON Canonicalization Scheme (JCS)**.

Before signing, the raw payload is serialized to a deterministic string representation. This guarantees that verifiers across polyglot microservices (e.g., Python, Rust, Go) produce the exact same byte array for the payload hash.

### 2. Merkle-Linked Hashes

To ensure the execution sequence cannot be tampered with (e.g., a malicious node reordering or dropping an earlier hop), each execution entry stores the SHA-256 hash of the *previous* signature.

```json
{
  "entry_id": "uuid-1234",
  "node_id": "process_payment",
  "workload_id": "spiffe://kest.internal/payment-service",
  "parent_entry_ids": ["hash-of-previous-jws"],
  "trust_score": 1.0,
  "timestamp_ms": 1712345678900
}
```

This structure creates a **Directed Acyclic Graph (DAG)** of the request's journey. Any modification to a previous entry invalidates its signature, thereby invalidating its hash, which immediately breaks the cryptographic link for all subsequent entries in the chain.

## Verification Guarantees

When a downstream node or a post-execution auditor parses the OTel spans to reconstruct the Passport, it verifies two distinct properties:

1.  **Identity Verification**: The JWS signature is cryptographically sound and was produced by the private key belonging to the `workload_id` claimed in the payload. The public key is verified against the SPIRE Trust Domain.
2.  **Lineage Integrity**: The `parent_entry_ids` hash perfectly matches the computed SHA-256 hash of the preceding JWS signature.

If either check fails, the execution lineage is considered compromised, and the `PassportVerifier` throws a cryptographic exception.
