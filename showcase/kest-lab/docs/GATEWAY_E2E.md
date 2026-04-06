# Scope-Delegated Gateway: Full Zero Trust Delegation Flow

<!--
AUTO-GENERATED COMPANION CONTENT
This README is the canonical source of truth for the `gateway_e2e` scenario.
The website page at `website/content/examples/gateway_e2e.md` is derived from this file.
When the implementation changes, update this README first, then regenerate the website page.
Sync command: cp showcase/kest-lab/docs/GATEWAY_E2E.md website/content/examples/gateway_e2e.md (and update frontmatter)
-->

This document explains the **Scope-Delegated Gateway** scenario: a complete, runnable Zero Trust delegation chain where a human user delegates to an autonomous agent, the agent presents credentials to a gateway that enforces scope-based policies, the gateway mints a narrow-scope task token, and every step is woven into a cryptographically verifiable Merkle DAG audit trail.

---

## The Problem: Why Delegation Is Hard to Get Right

When an AI agent acts on behalf of a user, three failure modes are common in practice:

1. **Over-privilege**: The agent receives the user's full token and uses it everywhere. If the agent is compromised, the attacker inherits all of the user's rights — forever.
2. **Invisible provenance**: The system records what the agent *did*, but not *who authorised it*. An audit log shows `agent-service called /transfer`, not `alice delegated to agent-service to call /transfer`.
3. **Forged scope creep**: The agent exchanges a user token for a narrower OBO token, but a compromised gateway re-mints tokens with broader scopes than were originally granted.

Kest addresses all three with cryptographic lineage. Every delegation hop is signed, chained to its parent, and enforced by policy *before* execution.

---

## The Full Flow

```
┌──────────┐  1. user token         ┌─────────────┐
│  Alice   │ ───────────────────── ▶│  kest-agent │
│ (human)  │                        │  /delegate  │
└──────────┘                        └──────┬──────┘
                                           │ 2. RFC 8693 OBO exchange
                                           │    sub=kest-agent, act.sub=alice
                                           │    scopes: read:data write:data
                                           ▼
                                    ┌──────────────┐
                                    │ kest-gateway │
                                    │ /authorise   │
                                    │  ① verify OBO│
                                    │  ② scope check│
                                    │  ③ sign audit │
                                    │  ④ mint task  │
                                    │    token      │
                                    └──────┬───────┘
                                           │ 5. task token (scope: task:process-data only)
                                           ▼
                                    ┌──────────────┐
                                    │ kest-gateway │
                                    │ /execute-task│
                                    │  ① task scope│
                                    │     check    │
                                    │  ② sign audit│
                                    └──────┬───────┘
                                           │ 6. calls → hop1 → hop2 → hop3
                                           ▼
                                    ┌────────────────────┐
                                    │ hop1 → hop2 → hop3 │
                                    │ (each signs audit) │
                                    └────────────────────┘
```

**Audit trail**: 6 signed `KestEntry` records chained into a Merkle DAG:

| # | Service | Policy Enforced | Identity |
|---|---|---|---|
| 1 | kest-agent | `delegation_policy` | alice (via OBO `act`) + kest-agent |
| 2 | kest-gateway | `gateway_policy` (scope check) | alice + kest-agent |
| 3 | kest-gateway | `task_policy` (task token) | kest-gateway (narrow scope) |
| 4 | hop1 | `workload_user_policy` | kest-gateway |
| 5 | hop2 | `workload_user_policy` | kest-gateway |
| 6 | hop3 | `workload_user_policy` | kest-gateway |

---

## Token Lifecycle

### 1 — User Token (issued by Keycloak, ROPC grant)

```json
{
  "sub": "alice-uuid",
  "preferred_username": "alice",
  "realm_access": { "roles": ["kest-reader"] },
  "scope": "openid profile roles read:data write:data",
  "aud": ["kest-agent"]
}
```

Alice's token carries her full delegated scopes. It is presented **only to kest-agent** — never sent directly to any downstream service.

### 2 — OBO Token (issued by Keycloak, RFC 8693 exchange)

```json
{
  "sub": "kest-agent",
  "act": { "sub": "alice-uuid" },
  "preferred_username": "kest-agent",
  "scope": "openid profile roles read:data write:data",
  "aud": ["kest-gateway"]
}
```

The OBO token carries Alice's original scopes but the **acting principal is kest-agent**. `KestIdentityMiddleware` on kest-gateway extracts:
- `kest.user = alice` (from `act.sub` → `preferred_username` lookup)
- `kest.agent = kest-agent` (from `sub`)
- `kest.task = read:data write:data` (from `scope`)

### 3 — Task Token (minted by kest-gateway's own Ed25519 key)

```json
{
  "sub": "kest-gateway",
  "task": "process-data",
  "scope": "task:process-data",
  "delegated_user": "alice",
  "delegated_agent": "kest-agent",
  "iat": 1712345678,
  "exp": 1712349278
}
```

The task token is **not a Keycloak token**. It is a compact JWT signed by kest-gateway's own `LocalEd25519Provider`. It carries only the single scope needed for the specific task. Hop1 validates it via the baggage kest.task claim set by kest-gateway before forwarding.

---

## Approach Analysis: Token Minting Strategies

Three approaches exist for how kest-gateway can produce a task token. Each has distinct security trade-offs.

---

### Approach A — Gateway Self-Signs (Ed25519, this implementation)

kest-gateway mints the task token using its own `LocalEd25519Provider`. The token is short-lived and carries only the single narrow scope.

**Pros:**
- No dependency on Keycloak for task token issuance. No network round-trip at authorisation time.
- Token contents are fully controlled by the gateway's business logic.
- Kest's `@kest_verified` decorator signs the authorisation decision into the Merkle DAG — the audit trail proves the gateway evaluated the policy before minting.
- Short-lived (TTL configurable, e.g. 5 minutes) minimises blast radius if stolen.

**Cons / Threat Model:**
- **If kest-gateway is compromised**, the attacker can mint arbitrary task tokens. The Kest audit trail will still record a signed entry attributing the action to kest-gateway — so compromise is detectable, but it is not preventable at the token layer.
- **Mitigation**: Pin kest-gateway's signing key to a SPIRE SVID. SPIRE rotates the key automatically; if kest-gateway loses its SVID (e.g. pod restart without re-attestation), it cannot issue tokens.
- Downstream services (hop1/2/3) cannot verify the task token's signature against a known JWKS without being told kest-gateway's public key. In this implementation, scope is verified via baggage (`kest.task`), not raw JWT signature, so the hop services rely on kest-gateway embedding the scope in baggage — they trust kest-gateway as a signed audit entry in the chain.
- A compromised kest-gateway can re-use the Ed25519 key until the key is rotated or audited.

**Recommended safeguards for production:**
1. Run kest-gateway with a SPIRE-attested identity. Use `SPIREProvider` (not `LocalEd25519Provider`) so the key material is attestation-backed.
2. Set a short SVID TTL (e.g. 1 hour). SPIRE will refuse to issue an SVID if the workload cannot be re-attested.
3. Add an OTel alert on audit entries where kest-gateway appears as the signer but no corresponding agent/user delegation entry is present in the same trace — that would indicate an out-of-band token mint.

---

### Approach B — Keycloak Downscoping (Token Exchange with `scope` restriction)

kest-gateway calls Keycloak's token exchange endpoint again, requesting a new token with a restricted scope:

```http
POST /realms/kest-lab/protocol/openid-connect/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<OBO token>
requested_token_type=urn:ietf:params:oauth:token-type:access_token
scope=task:process-data
```

**Pros:**
- Task tokens are Keycloak-issued. Downstream services can verify them against the JWKS endpoint, independently of kest-gateway.
- Keycloak's audit log records every exchange, providing a second audit trail outside Kest.
- A compromised kest-gateway can only mint tokens for scopes Keycloak's policies permit. Keycloak acts as an independent enforcer.

**Cons:**
- Requires Keycloak to be available at authorisation time. If Keycloak is down, task execution fails entirely.
- Adds ~50–200ms latency per authorisation for the Keycloak round-trip.
- Keycloak must be configured with the `task:process-data` scope as a valid exchangeable scope — this couples the gateway's business logic to the IdP's configuration.
- `scope` restriction in Keycloak token exchange is supported but has known quirks (Keycloak 24+). Not all Keycloak versions honour `scope` in downscoped exchanges.

---

### Approach C — Kest Claim-Check / JWT Lineage Only (no separate task token)

Instead of minting a token, kest-gateway simply signs a `KestEntry` with `kest.task=process-data` in the baggage and forwards the OBO token directly to hop1.

**Pros:**
- Simplest. No extra token issuance.
- The audit entry IS the authorisation record. Everything is in the Merkle DAG.
- Zero risk of a forged token — there is no task token to forge.

**Cons:**
- Hop1 receives the user's (agent's) OBO token directly. If hop1 is compromised, the attacker has the OBO token.
- Scope enforcement relies entirely on the Kest policy context (`kest.task` baggage). A compromised intermediate service could modify baggage.
- Does not satisfy regulatory requirements that may mandate a separate verifiable credential per task.

---

### Comparison Matrix

| Property | A: Gateway Self-Signs | B: Keycloak Downscope | C: Claim-Check Only |
|---|:---:|:---:|:---:|
| Zero Keycloak dependency | ✅ | ❌ | ✅ |
| Token independently verifiable | ⚠️ (gateway key) | ✅ (JWKS) | ❌ |
| Blast radius if gateway compromised | High (can mint anything) | Medium (Keycloak limits scope) | Low (no token, just baggage) |
| Latency | Low | Medium (+Keycloak RTT) | Lowest |
| Audit trail completeness | ✅ Kest DAG | ✅ Kest DAG + KC audit | ✅ Kest DAG |
| SPIRE key backing possible | ✅ | N/A | N/A |
| Implementation complexity | Low | Medium | Lowest |

**This showcase uses Approach A** because it most clearly demonstrates kest's signing model. For production systems with regulatory requirements, **Approach B** provides the strongest independent verifiability. For high-throughput internal services where latency matters, **Approach C** (claim-check only) is appropriate when the Kest audit trail is treated as the primary compliance artefact.

---

## Security Considerations

### What happens if kest-gateway is compromised?

Under **Approach A**:

1. The attacker has the gateway's `LocalEd25519Provider` private key and can mint task tokens for any scope.
2. **Detection**: Every task token used in a Kest-protected call produces a signed `KestEntry`. A batch analysis of the Merkle DAG can flag entries where kest-gateway appears as the signing workload but no corresponding parent delegation entry (from a user → agent) is present in the same passport chain.
3. **Containment**: Rotate the gateway's signing key (restart with a new `LocalEd25519Provider`, or revoke the SPIRE SVID if using `SPIREProvider`). All tokens signed by the old key become unverifiable by downstream services that validate the Kest signature chain.
4. **Prevention**: Run gateway in a SPIRE-attested environment. SPIRE's node attestation ensures the gateway pod cannot obtain an SVID unless it passes its registration entry checks (e.g. Docker label, Kubernetes SA). A compromised pod that crashes and restarts will fail re-attestation if its attributes have changed.

### Scope creep: can the agent escalate?

The OBO token's scope is bounded by Alice's original token (`read:data write:data`). Keycloak's token exchange cannot produce a token with scopes broader than the subject token's scopes. kest-gateway's `gateway_policy` further enforces that the incoming OBO token must carry the *required* scope before any task token is minted.

If Alice's token does not include `write:data`, the gateway policy denies the request at step ④, and no task token is minted. The denial is recorded as a signed `KestEntry` with `allowed=false` in the OTel span.

---

## Running the Scenario

```bash
# Start the full lab stack
moon run kest-lab:up

# Run only the gateway E2E tests (inside the lab)
moon run kest-core-python:test-live -k test_gateway

# Run all keycloak + gateway tests
moon run kest-core-python:test-live -k "keycloak or gateway"

# Tear down
moon run kest-lab:down
```

### Expected output (abbreviated)

```
showcase/kest-lab/tests/test_gateway_e2e.py::test_full_delegation_chain_alice PASSED
showcase/kest-lab/tests/test_gateway_e2e.py::test_gateway_denies_insufficient_scope PASSED
showcase/kest-lab/tests/test_gateway_e2e.py::test_task_token_cannot_access_authorise PASSED
showcase/kest-lab/tests/test_gateway_e2e.py::test_audit_trail_integrity PASSED
```

---

## Files

| File | Role |
|---|---|
| `gateway.py` | kest-gateway FastAPI service |
| `agent.py` | kest-agent (patched to support `/delegate-to-gateway`) |
| `cedar/policies/gateway_policy.cedar` | Scope enforcement on kest-gateway `/authorise` |
| `cedar/policies/task_policy.cedar` | Narrow-scope enforcement for task token execution |
| `keycloak/realm-export.json` | Keycloak realm with `read:data`, `write:data` scopes, `kest-gateway` client |
| `tests/test_gateway_e2e.py` | Full E2E test suite |
| `docs/GATEWAY_E2E.md` | This document |
