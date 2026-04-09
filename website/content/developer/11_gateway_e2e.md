---
title: "Scope-Delegated Gateway: Full Zero Trust Delegation"
description: "A step-by-step walkthrough of the most complete Zero Trust delegation flow Kest supports: human → agent → gateway → task, with token contents, policy context, and signed audit entries shown at every hop."
---


# Scope-Delegated Gateway: Full Zero Trust Delegation

This walkthrough demonstrates the most complete delegation flow Kest supports:

1. A **human user (Alice)** authenticates via Keycloak and delegates to an AI agent.
2. The **agent** performs an RFC 8693 On-Behalf-Of (OBO) exchange and presents the token to a gateway.
3. The **gateway** enforces scope policy, mints a narrow-scope task token, and calls downstream services.
4. Every hop produces a **signed `KestEntry`** chained into a tamper-evident **Merkle DAG**.

At the end of this page you will see the actual token payloads, policy context dictionaries, and signed audit entries at each step.

> **Try it yourself**: Ships in the kest-lab showcase. Run `moon run kest-lab:up` then `moon run kest-lab:test-live -k test_gateway`.

---

## Architecture Overview

![Gateway E2E delegation flow — Alice → Agent → Gateway → downstream hops](/examples/gateway_flow_diagram.png)


**Six signed `KestEntry` records** are chained into one Merkle DAG:

| # | Service | Operation | Policy Enforced | Signer Identity |
|---|---|---|---|---|
| 1 | kest-agent | `/delegate-to-gateway` | `delegation_policy` | alice + kest-agent |
| 2 | kest-gateway | `/authorise` | `gateway_policy` (scope check) | kest-agent + alice |
| 3 | kest-gateway | `/execute-task` | `task_policy` (narrow scope) | kest-gateway |
| 4 | hop1 | `GET /` | `workload_user_policy` | kest-gateway |
| 5 | hop2 | `GET /hop2` | `workload_user_policy` | kest-gateway |
| 6 | hop3 | `GET /hop3` | `workload_user_policy` | kest-gateway |

---

## Step 1 — Alice Authenticates (Keycloak ROPC)

Alice uses a Resource Owner Password Credentials (ROPC) grant to obtain a Keycloak token, requesting the optional data scopes she needs to delegate:

```http
POST /realms/kest-lab/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=kest-cli&username=alice&password=alice
&scope=openid+profile+roles+read:data+write:data
```

**Resulting JWT payload (Alice's token):**

```json
{
  "sub": "a1b2c3d4-0001-0001-0001-000000000001",
  "preferred_username": "alice",
  "realm_access": { "roles": ["kest-reader"] },
  "scope": "openid profile roles read:data write:data",
  "aud": ["account"],
  "exp": 1775491200
}
```

> **Security note**: Alice's token is presented **only to kest-agent** and never forwarded directly to downstream services.

---

## Step 2 — OBO Exchange & Agent Delegation (Audit #1)

kest-agent receives Alice's token and exchanges it for an On-Behalf-Of (OBO) token via Keycloak's token exchange endpoint (RFC 8693). The new token's `sub` becomes `kest-agent` while Alice's identity is preserved in the `act` claim.

**OBO Token payload:**

```json
{
  "sub": "kest-agent",
  "act": { "sub": "a1b2c3d4-0001-0001-0001-000000000001" },
  "scope": "openid profile roles read:data write:data",
  "aud": ["kest-gateway"],
  "exp": 1775491200
}
```

**kest-agent's `@kest_verified` produces Audit Entry #1:**

```python
@kest_verified(
    policy="delegation_policy",
    origin="internet",          # trust bootstrapped at 10
)
async def _delegate_logic():
    ...
```

**Context passed to `delegation_policy` (Cedar):**

```python
{
    "principal": "spiffe://kest.internal/workload/kest-agent",
    "trust_score": 10,          # ORIGIN_TRUST_MAP["internet"] = 10
    "is_root": True,            # first hop in the chain
    "chain_tip": "0",
    "principal_user": "a1b2c3d4-0001-0001-0001-000000000001",
    "principal_agent": "kest-agent",
    "principal_scope": "openid profile roles read:data write:data",
}
```

**Signed KestEntry #1 payload (decoded from JWS):**

```json
{
  "entry_id": "11111111-aaaa-bbbb-cccc-000000000001",
  "operation": "_delegate_logic",
  "classification": "system",
  "trust_score": 10,
  "parent_ids": ["0"],
  "added_taints": [],
  "removed_taints": [],
  "taints": [],
  "labels": {
    "principal": "spiffe://kest.internal/workload/kest-agent",
    "kest.identity": "{\"user\": \"a1b2c3d4-...\", \"agent\": \"kest-agent\"}",
    "trace_id": "d449a53efe8b1cd431d84db00f8dc43a"
  },
  "timestamp_ms": 1775494707000
}
```

The SHA-256 of this JWS becomes `chain_tip` and is injected into outgoing OTel baggage headers as `kest.chain_tip`.

---

## Step 3 — Gateway /authorise (Audit #2)

kest-agent forwards the OBO token to `kest-gateway POST /authorise`. The `KestIdentityMiddleware` on the gateway parses the JWT and injects four OTel baggage keys:

| OTel Baggage Key | Value | Source |
|---|---|---|
| `kest.principal_user` | `a1b2c3d4-...` (alice's UUID) | `act.sub` from OBO token |
| `kest.principal_agent` | `kest-agent` | `azp` / `sub` from OBO token |
| `kest.principal_scope` | `openid profile roles read:data write:data` | `scope` from OBO token |
| `kest.chain_tip` | SHA-256 of entry #1 | Propagated baggage from kest-agent |

The `@kest_verified` decorator on `_authorise_logic` now runs:

```python
@kest_verified(
    policy="gateway_policy",
    origin="internal",          # trust_score = 100
)
async def _authorise_logic():
    ...
```

**Context passed to `gateway_policy` (CedarLocalEngine):**

```python
{
    "principal": "spiffe://kest.internal/workload/kest-gateway",
    "trust_score": 100,         # ORIGIN_TRUST_MAP["internal"] = 100
    "is_root": False,
    "chain_tip": "31a2f9...",   # SHA-256 of entry #1
    "principal_user": "a1b2c3d4-0001-0001-0001-000000000001",
    "principal_agent": "kest-agent",
    "principal_scope": "openid profile roles read:data write:data",
}
```

**`gateway_policy.cedar` evaluation:**

```cedar
permit(principal, action, resource) when {
    context["trust_score"] >= 10 &&               // 100 >= 10 ✓
    context has "principal_user" &&
    context["principal_user"] != "" &&             // alice UUID ✓
    context has "principal_agent" &&
    context["principal_agent"] != "" &&            // "kest-agent" ✓
    context has "principal_scope" &&
    context["principal_scope"] like "*read:data*"  // scope contains "read:data" ✓
};
// → Allow
```

**Signed KestEntry #2 payload:**

```json
{
  "entry_id": "22222222-aaaa-bbbb-cccc-000000000002",
  "operation": "_authorise_logic",
  "classification": "system",
  "trust_score": 100,
  "parent_ids": ["31a2f90fb8aeda526638948834a5fd5..."],
  "added_taints": [],
  "removed_taints": [],
  "taints": [],
  "labels": {
    "principal": "spiffe://kest.internal/workload/kest-gateway",
    "kest.identity": "{\"user\": \"a1b2c3d4-...\", \"agent\": \"kest-agent\"}",
    "trace_id": "d449a53efe8b1cd431d84db00f8dc43a"
  },
  "timestamp_ms": 1775494708000
}
```

---

## Step 4 — Task Token Minted

![Token delegation and scope narrowing — Alice's full scopes narrow through OBO exchange and gateway policy to a single task:process-data scope](/examples/scope_narrowing.png)

After policy passes, the gateway mints a narrow-scope task token using its own `LocalEd25519Provider` (or `SPIREProvider` in production). This token carries **only** the scope required for the specific task — not Alice's full delegated scopes.

**Task token JWT payload:**

```json
{
  "iss": "kest-gateway/kest-gateway",
  "sub": "kest-gateway",
  "iat": 1775494708,
  "exp": 1775495008,
  "scope": "task:process-data",
  "task": "process-data",
  "delegated_user": "a1b2c3d4-0001-0001-0001-000000000001",
  "delegated_agent": "kest-agent"
}
```

> **Scope narrowing**: Alice's token had `read:data write:data`. The task token carries only `task:process-data`. The agent cannot re-use this token to obtain a second delegation (Flow F in the test suite enforces this as a 403).

---

## Step 5 — Gateway /execute-task (Audit #3)

kest-agent posts the task token back to `kest-gateway POST /execute-task`. The gateway decodes the task token and injects its scope into baggage before invoking the `@kest_verified` decorator:

```python
ctx = otel_baggage.set_baggage("kest.principal_scope", "task:process-data")
ctx = otel_baggage.set_baggage("kest.principal_user", delegated_user)
ctx = otel_baggage.set_baggage("kest.principal_agent", delegated_agent)
```

**Context passed to `task_policy` (CedarLocalEngine):**

```python
{
    "principal": "spiffe://kest.internal/workload/kest-gateway",
    "trust_score": 100,         # ORIGIN_TRUST_MAP["internal"] = 100
    "is_root": False,
    "chain_tip": "c82664...",   # SHA-256 of entry #2
    "principal_user": "a1b2c3d4-0001-0001-0001-000000000001",
    "principal_agent": "kest-agent",
    "principal_scope": "task:process-data",
}
```

**`task_policy.cedar` evaluation:**

```cedar
permit(principal, action, resource) when {
    context["trust_score"] >= 50 &&                              // 100 >= 50 ✓
    context has "principal_scope" &&
    context["principal_scope"] == "task:process-data"            // exact match ✓
};
// → Allow
```

**Signed KestEntry #3 payload:**

```json
{
  "entry_id": "33333333-aaaa-bbbb-cccc-000000000003",
  "operation": "_execute_task_logic",
  "classification": "system",
  "trust_score": 100,
  "parent_ids": ["c82664a3cf66be1310319801ff96e64c..."],
  "added_taints": [],
  "removed_taints": [],
  "taints": [],
  "labels": {
    "principal": "spiffe://kest.internal/workload/kest-gateway",
    "kest.identity": "{\"user\": \"a1b2c3d4-...\", \"agent\": \"kest-agent\"}",
    "trace_id": "d449a53efe8b1cd431d84db00f8dc43a"
  },
  "timestamp_ms": 1775494709000
}
```

The gateway now calls `hop1` with the OTel baggage propagated (including `kest.chain_tip` and `kest.passport`).

---

## Step 6 — hop1 → hop2 → hop3 (Audits #4–#6)

Each hop service runs `KestMiddleware` (which extracts the incoming Passport from baggage) and a `@kest_verified`-decorated handler. The `workload_user_policy` at each hop verifies the trust score and that the scope is still `task:process-data`.

**OTel baggage propagated between hops:**

```
baggage: kest.chain_tip=<sha256 of prev entry>,
         kest.passport=["<jws1>","<jws2>","<jws3>"],
         kest.principal_scope=task:process-data,
         kest.principal_user=a1b2c3d4-...,
         kest.principal_agent=kest-agent
```

**Context passed to `workload_user_policy` at hop1:**

```python
{
    "principal": "spiffe://kest.internal/workload/hop1",
    "trust_score": 100,         # inherited from parent (100 * 100 / 100 = 100)
    "is_root": False,
    "chain_tip": "<sha256 of entry #3>",
    "principal_user": "a1b2c3d4-0001-0001-0001-000000000001",
    "principal_agent": "kest-agent",
    "principal_scope": "task:process-data",
}
```

**Signed KestEntry #4 payload (hop1):**

```json
{
  "entry_id": "44444444-aaaa-bbbb-cccc-000000000004",
  "operation": "get_data",
  "classification": "system",
  "trust_score": 100,
  "parent_ids": ["<sha256 of entry #3>"],
  "added_taints": [],
  "removed_taints": [],
  "taints": [],
  "labels": {
    "principal": "spiffe://kest.internal/workload/hop1",
    "kest.identity": "{\"user\": \"a1b2c3d4-...\", \"agent\": \"kest-agent\"}",
    "trace_id": "d449a53efe8b1cd431d84db00f8dc43a"
  },
  "timestamp_ms": 1775494710000
}
```

hop2 and hop3 produce identical structure, each extending the chain via their `parent_ids`.

---

## The Final Passport

After the full flow, the `kest.passport` baggage header carries all 6 JWS entries as a JSON array. Each entry's `parent_ids[0]` is the SHA-256 of the preceding signature — forming a cryptographically linked Merkle chain.

![Merkle chain — 6 signed KestEntry records chained via SHA-256, trust scores from 10 to 100](/examples/merkle_chain_diagram.png)

To verify this chain programmatically:

```python
from kest.core.models import Passport, PassportVerifier

passport = Passport.deserialize(baggage_passport_json)
PassportVerifier.verify(passport, providers={
    "spiffe://kest.internal/workload/kest-agent": agent_identity,
    "spiffe://kest.internal/workload/kest-gateway": gateway_identity,
    "spiffe://kest.internal/workload/hop1": hop1_identity,
    # ...
})
```

---

## Trust Score Propagation

Note that `trust_score` in entry #1 is `10` (bootstrapped from `ORIGIN_TRUST_MAP["internet"]`). Entry #2 onward uses `ORIGIN_TRUST_MAP["internal"] = 100` because the gateway re-bootstraps trust at the internal boundary.

The `DefaultTrustEvaluator` applies: `score = (min(parent_scores) * self_score) // 100`.

For entries #2–#6 (all `internal` origin, self_score=100, parent from a non-root hop=100):

```
min(100) * 100 // 100 = 100
```

This is why the task execution chain sees a full trust score of `100`, even though the delegation entry started at `10`.

---

## What Happens When Policy Fails?

### Flow E — Insufficient scope (403)

If Alice's token lacks `read:data`, `gateway_policy` denies the request:

```python
# KestIdentityMiddleware extracts: principal_scope = "openid profile roles"
{
    "principal_scope": "openid profile roles",  # no "read:data"
    ...
}
# gateway_policy: context["principal_scope"] like "*read:data*" → false
# @kest_verified raises PermissionError
# → gateway exception_handler returns HTTP 403
```

### Flow F — Task token cannot re-delegate (403)

A task token presented back to `/authorise` is denied because:

```python
# principal_scope = "task:process-data" (does not contain "read:data")
# gateway_policy forbids this → 403
```

This enforces the one-way scope narrowing: task tokens cannot escalate back to delegation tokens.

---

## Cedar Policies

### `gateway_policy.cedar`

```cedar
// gateway_policy.cedar
// Evaluated by CedarLocalEngine on kest-gateway /authorise.
// Permits delegation if: user present, agent present, scope contains read:data, trust >= 10.

permit(principal, action, resource) when {
    context["trust_score"] >= 10 &&
    context has "principal_user" &&
    context["principal_user"] != "" &&
    context has "principal_agent" &&
    context["principal_agent"] != "" &&
    context has "principal_scope" &&
    context["principal_scope"] like "*read:data*"
};
```

### `task_policy.cedar`

```cedar
// task_policy.cedar
// Evaluated by CedarLocalEngine on kest-gateway /execute-task.
// Permits execution only with the exact narrow task scope and internal trust level.

permit(principal, action, resource) when {
    context["trust_score"] >= 50 &&
    context has "principal_scope" &&
    context["principal_scope"] == "task:process-data"
};
```

---

## Security Analysis: What If kest-gateway Is Compromised?

Under the self-signing approach (Approach A):

1. **Detection**: Every task token use produces a signed `KestEntry`. A Merkle DAG analysis can flag entries where kest-gateway appears as signer without a valid `user→agent` parent delegation in the same Passport.
2. **Containment**: Rotate the gateway's signing key. If using `SPIREProvider`, revoke the SVID — all tokens signed by the old key become cryptographically unverifiable.
3. **Prevention**: Back kest-gateway with SPIRE. A compromised pod that restarts fails re-attestation if its attributes change.

---

## Source Files

| File | Description |
|---|---|
| [`gateway.py`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/gateway.py) | kest-gateway FastAPI service |
| [`agent.py`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/agent.py) | kest-agent (includes `/delegate-to-gateway`) |
| [`cedar/policies/gateway_policy.cedar`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/cedar/policies/gateway_policy.cedar) | Scope enforcement policy |
| [`cedar/policies/task_policy.cedar`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/cedar/policies/task_policy.cedar) | Task token enforcement policy |
| [`cedar/policies/delegation_policy.cedar`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/cedar/policies/delegation_policy.cedar) | Agent delegation policy |
| [`cedar/policies/workload_user_policy.cedar`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/cedar/policies/workload_user_policy.cedar) | Hop-to-hop service policy |
| [`tests/test_gateway_e2e.py`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/tests/test_gateway_e2e.py) | Full E2E test suite (4 flows) |
