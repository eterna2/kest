# Handling Edge Cases

A distributed Zero Trust architecture introduces new complexities. Kest handles these edge cases systematically to maintain both security and reliability.

## Network Partitions (Fail-Secure)

If a network partition occurs between the application node and the policy sidecar (e.g., OPA or Cedar):
- Kest defaults to a strict **Fail-Secure** posture.
- A `httpx.RequestError` or any non-200 HTTP response from the sidecar immediately evaluates to `False` (Deny).
- The `PermissionError` is raised in the application, halting execution.

To mitigate transient network glitches, you can configure the timeout policy on the sidecar engine:

```python
engine = OPASidecarEngine(url="http://localhost:8181", timeout=0.5)
```

## Clock Skew

Distributed nodes inherently experience clock skew.
Kest entries track the `timestamp_ms` when the execution occurred.
During post-execution Merkle verification, the `PassportVerifier` ignores strict monotonic timestamp validation in favor of the cryptographic hash linkage (`parent_entry_ids`). The cryptographic proof of order supersedes NTP synchronization guarantees.

## Replay Attacks

Because traditional fungible logs are susceptible to replay attacks, Kest relies on the Merkle DAG structure:

1. An attacker intercepting a valid request and attempting to replay it against a downstream node will present an identical `kest.lineage_root`.
2. However, the downstream node will sign a *new* entry linked to that root.
3. If an attacker alters the payload to appear unique, the existing `kest.signature` breaks, triggering an instant verification failure in `PassportVerifier`.
4. While the `kest.passport` ensures the *lineage* is non-repudiable, replay attack mitigation on the application endpoint itself (e.g., nonces, idempotency keys) remains the responsibility of the underlying HTTP framework.

## Baggage Size Limits (Claim Check)

OpenTelemetry Baggage headers and general HTTP headers have size limitations (typically 4KB-8KB). A long execution chain can easily bloat the base64-encoded `kest.passport`.

Kest implements a **Hybrid Lineage Strategy**:
- **Direct Mode:** If the serialized `kest.passport` is under 4KB, it is passed directly in the HTTP headers.
- **Claim Check Mode:** If the size exceeds the limit, Kest automatically triggers the `BaggageManager`. It uploads the full Passport to a shared, high-performance datastore via a `CacheProvider` (e.g., Redis).
- The HTTP header is then compressed to a tiny UUID: `kest.claim_check=uuid-1234`.
- The downstream Kest node transparently retrieves the full passport from the shared cache before evaluating policy.

```python
from kest.core import SimpleCache, configure

# Initialize Kest with a Cache Provider for Claim Check support
configure(engine=my_engine, identity=my_id, cache=SimpleCache())
```
