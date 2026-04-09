# Cryptographic Audit Trails

In conventional architectures, application logs are typically forwarded to a centralized logging server (e.g., Elasticsearch, Splunk) as flat text or JSON objects. This model is fundamentally flawed from a security and compliance perspective.

If an attacker compromises a single application node, they can alter the node's local logs before forwarding, inject forged logs into the central system, or selectively drop logs covering their tracks. Because the logs are *fungible* (interchangeable and easily altered), auditors have no cryptographic guarantee that the logs accurately reflect reality.

## The Immutable Record

Kest guarantees **non-fungibility** through the Merkle-linked execution lineage (the Passport) and JSON Web Signatures (JWS).

1.  **Workload Identity**: Kest nodes fetch short-lived X509 certificates and private keys from the local SPIRE agent.
2.  **Cryptographic Signatures**: When an application executes a `@kest_verified` function, Kest produces an entry containing the policy decision, the node ID, the parent node's signature hash, and a timestamp. Kest signs this payload with the node's private key.
3.  **Hash Linking**: Because every execution entry hashes the preceding entry's signature, changing any part of an entry breaks the hash for every subsequent entry in the chain.

## Verification Guarantees

Instead of trusting the logging agent, auditors extract the `kest.signature` attributes from the OpenTelemetry span logs and run the `PassportVerifier`.

```python
from kest.core import Passport, PassportVerifier

# Spans are collected directly from the OpenTelemetry datastore
# and provided to the Verifier.

passport = Passport(entries=[sig1, sig2, sig3])

# The `providers` argument represents the trusted public keys
# associated with the SPIFFE IDs. In a production environment,
# the Verifier fetches these directly from the SPIRE Trust Bundle.
PassportVerifier.verify(passport, providers=spire_trust_bundle)
```

The verifier confirms that:
*   The JWS is mathematically valid and signed by the private key belonging to the stated `spiffe_id`.
*   The `kest.parent_hash` inside the payload exactly matches the `SHA-256` hash of the preceding JWS.

## Proof of Execution

The non-fungible audit trail guarantees that the execution occurred exactly as recorded. A compromised node cannot forge a request from an upstream node because it does not possess the upstream node's private key. The cryptographic proof of execution simplifies post-breach forensics and ensures indisputable regulatory compliance.
