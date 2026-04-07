---
title: "Kest Lab: Zero Trust Integration Playground"
description: "A complete step-by-step walkthrough of the kest-lab showcase: spinning up real SPIRE identities, Keycloak, Cedar policies, and OTel tracing, then running the full delegation chain and live integration tests."
---

# Kest Lab: Zero Trust Integration Playground

`kest-lab` is a self-contained Docker environment that runs the **complete Kest stack** — SPIRE workload identity, Keycloak OAuth, Cedar policies, OpenTelemetry auditing, and a five-service delegation chain — locally on your machine.

This guide walks you through every step from a cold start to verified audit trails, with exact commands, real JSON payloads, and annotated code snippets.

---

## Prerequisites

| Tool | Minimum Version | Install |
|---|---|---|
| Docker + Compose | 24+ | https://docs.docker.com/get-docker/ |
| `moon` | 1.x | bundled via `proto` |
| `proto` | latest | `curl -fsSL https://moonrepo.dev/install/proto.sh \| bash` |

Verify before proceeding:

```bash
docker compose version  # Docker Compose version v2.x.x
moon --version          # moon v1.x.x
```

---

## Architecture Overview

The lab spins up the following services. All communicate inside a Docker bridge network:

| Service | Port | Role |
|---|---|---|
| `spire-server` | 8081 | SPIFFE trust domain, issues SVIDs to agents |
| `spire-agent` | — | Local workload attestor (PID/UID based) |
| `keycloak` | 8080 | Human identity provider; handles ROPC + token exchange |
| `opa` | 8181 | Open Policy Agent (Rego) policy server |
| `cedar-agent` | 8180 | Cedar JSON-based policy server |
| `otel-collector` | 4317/4318 | Audit log + trace sink |
| `hop1` | 8000 | First workload (FastAPI + `@kest_verified`) |
| `hop2` | — | Second workload; called by hop1 |
| `hop3` | — | Third workload; called by hop2 |
| `kest-agent` | 8001 | OBO delegation agent; calls hop1 and kest-gateway |
| `kest-gateway` | 8002 | Scope-enforcement gateway; mints narrow task tokens |

The full `gateway_e2e` delegation chain is:

```
Alice → kest-agent /delegate-to-gateway
     → OBO exchange (sub=kest-agent, act.sub=alice)
     → kest-gateway /authorise  (gateway_policy: scope check → audit #2)
     → kest-gateway /execute-task (task_policy: narrow scope → audit #3)
     → hop1 /  (workload_user_policy → audit #4)
     → hop2 /hop2  (workload_user_policy → audit #5)
     → hop3 /hop3  (workload_user_policy → audit #6)
```

---

## Step 1 — Clone and Prepare

```bash
git clone https://github.com/eterna2/kest.git
cd kest

# Install all toolchain versions declared in .prototools
proto install
```

---

## Step 2 — Start the Lab

A single `moon` task handles the full startup sequence:

```bash
moon run kest-lab:up
```

**What this does internally:**

1. `kest-lab:bootstrap` — starts `spire-server` in detached mode, runs `bootstrap.sh` which:
   - Generates a SPIRE join token
   - Registers workload entries in the SPIRE server for each service
   - Starts the `spire-agent` with the join token
2. `kest-core-python:check` — verifies the core library passes lint/type-check before mounting it into containers
3. `docker compose up -d` — brings up all remaining services in parallel

**Expected output (abbreviated):**

```
[kest-lab:up] ✔ Generating join token...
[kest-lab:up] ✔ Registering spiffe://kest.internal/workload/hop1
[kest-lab:up] ✔ Registering spiffe://kest.internal/workload/hop2
[kest-lab:up] ✔ Registering spiffe://kest.internal/workload/hop3
[kest-lab:up] ✔ Registering spiffe://kest.internal/workload/kest-agent
[kest-lab:up] ✔ Registering spiffe://kest.internal/workload/kest-gateway
[+] Running 11/11
 ✔ Container kest-lab-spire-server-1     Running
 ✔ Container kest-lab-spire-agent-1      Running
 ✔ Container kest-lab-keycloak-1         Running
 ✔ Container kest-lab-otel-collector-1   Running
 ✔ Container kest-lab-opa-1              Running
 ✔ Container kest-lab-cedar-agent-1      Running
 ✔ Container kest-lab-hop1-1             Running
 ✔ Container kest-lab-hop2-1             Running
 ✔ Container kest-lab-hop3-1             Running
 ✔ Container kest-lab-kest-agent-1       Running
 ✔ Container kest-lab-kest-gateway-1     Running
```

Allow ~30 seconds for Keycloak to finish its initial import of the `kest-lab` realm.

---

## Step 3 — Verify SPIRE Health

Check that the SPIRE agent is connected and issuing SVIDs:

```bash
moon run kest-lab:spire-healthcheck
```

Expected output:

```
Agent is healthy.
```

If you see a connection error, wait another 10–15 seconds for `spire-agent` to complete its join-token attestation, then retry.

To inspect the actual X.509 SVID bundle being served to workloads:

```bash
moon run kest-lab:fetch-bundle
```

This installs `curl` inside `hop1` and fetches the bundle from the SPIRE Workload API socket at `/var/run/spire/agent/public/api.sock`. You'll see a JSON response with the trust bundle containing the root CA certificate for `spiffe://kest.internal`.

---

## Step 4 — Understanding the Services

### Identity Provider Setup (`gateway.py`)

Each workload detects whether the SPIRE socket is available and falls back to a local Ed25519 key for development:

```python
# gateway.py (lines 63–69)
SPIRE_SOCKET = "unix:///var/run/spire/agent/public/api.sock"
if os.path.exists(SPIRE_SOCKET):
    identity_provider = SPIREProvider(socket_path=SPIRE_SOCKET)
else:
    identity_provider = LocalEd25519Provider()
```

In the lab, SPIRE is running and the socket is mounted into every container — so `SPIREProvider` is active and all audit signatures use SPIRE-issued Ed25519 key material.

### Cedar Policy Loading (`gateway.py`)

The gateway loads all `.cedar` files from `/app/cedar/policies/` at startup:

```python
# gateway.py (lines 79–96)
def _load_cedar_policies(policy_dir: str = "/app/cedar/policies") -> dict:
    policies = {}
    if os.path.isdir(policy_dir):
        for fname in os.listdir(policy_dir):
            if fname.endswith(".cedar"):
                policy_id = fname[:-6]
                with open(os.path.join(policy_dir, fname)) as f:
                    policies[policy_id] = f.read()
    if not policies:
        policies["deny_all"] = "forbid(principal, action, resource);"
    return policies

cedar_policies = _load_cedar_policies()
policy_engine = CedarLocalEngine(policies=cedar_policies, entities=[])
configure(engine=policy_engine, identity=identity_provider)
```

The loaded policies are:

```
[Kest.Gateway] Loaded Cedar policies: ['gateway_policy', 'task_policy',
               'delegation_policy', 'workload_user_policy']
```

### Middleware Stack & Order

FastAPI middleware runs **LIFO** (last added = first executed). The gateway adds middleware in this order:

```python
# gateway.py (lines 117–122)
# Added first → runs second (inner)
app.add_middleware(
    KestIdentityMiddleware,
    jwks_uri=JWKS_URI,
    user_claim="preferred_username",
)
# Added last → runs first (outer)
app.add_middleware(KestMiddleware)
```

**Execution order per request:**

1. `KestMiddleware` (outer) — extracts W3C `baggage` header into OTel context; populates `kest.chain_tip`, `kest.passport`
2. `KestIdentityMiddleware` (inner) — verifies the `Authorization: Bearer <token>` JWT against Keycloak JWKS; writes `kest.principal_user`, `kest.principal_agent`, `kest.principal_scope` into OTel baggage

This ordering ensures that an OBO token's identity always overwrites whatever came in via baggage headers.

---

## Step 5 — Manual Flow Walkthrough

You can exercise the delegation chain manually from your host machine (all services expose ports).

### 5.1 Obtain Alice's Token (ROPC)

```bash
curl -s -X POST http://localhost:8080/realms/kest-lab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=kest-cli" \
  -d "username=alice" \
  -d "password=alice" \
  -d "scope=openid profile roles read:data write:data" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
```

**Alice's token payload (decoded):**

```json
{
  "sub": "a1b2c3d4-0001-0001-0001-000000000001",
  "preferred_username": "alice",
  "realm_access": { "roles": ["kest-reader"] },
  "scope": "openid profile roles read:data write:data",
  "aud": ["account"],
  "iss": "http://keycloak:8080/realms/kest-lab"
}
```

> **Note:** `kest-cli` omits `preferred_username` from the JWT payload, so all identity comparisons inside the lab use the `sub` UUID, not the string `"alice"`.

### 5.2 Trigger the Full Delegation Chain

```bash
ALICE_TOKEN=$(curl -s -X POST http://localhost:8080/realms/kest-lab/protocol/openid-connect/token \
  -d "grant_type=password&client_id=kest-cli&username=alice&password=alice&scope=openid profile roles read:data write:data" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:8001/delegate-to-gateway \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  | python3 -m json.tool
```

**Expected response (trimmed):**

```json
{
  "status": "delegated_via_gateway",
  "agent": "kest-agent",
  "user": "a1b2c3d4-0001-0001-0001-000000000001",
  "authorise_response": {
    "status": "authorised",
    "gateway": "kest-gateway",
    "delegated_user": "a1b2c3d4-0001-0001-0001-000000000001",
    "delegated_agent": "kest-agent",
    "granted_scope": "task:process-data",
    "task_token": "<compact-jwt>"
  },
  "execute_response": {
    "status": "executed",
    "gateway": "kest-gateway",
    "task": "process-data",
    "delegated_user": "a1b2c3d4-0001-0001-0001-000000000001",
    "delegated_agent": "kest-agent",
    "hop_result": {
      "hop1": "ok",
      "hop2": { "hop2": "ok", "hop3": "ok" }
    }
  }
}
```

**What happened inside `kest-agent /delegate-to-gateway`:** (see `agent.py` lines 192–294)

1. Receives `alice_token` in the `Authorization` header
2. Calls Keycloak token exchange (RFC 8693) to swap it for an OBO token:

```python
# agent.py (lines 97–127)
async def exchange_token_obo(subject_token: str) -> str:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            TOKEN_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "client_id": KEYCLOAK_CLIENT_ID,       # "kest-agent"
                "client_secret": KEYCLOAK_CLIENT_SECRET,
            },
        )
        return response.json()["access_token"]
```

**OBO token payload:**

```json
{
  "sub": "kest-agent",
  "act": { "sub": "a1b2c3d4-0001-0001-0001-000000000001" },
  "scope": "openid profile roles read:data write:data",
  "aud": ["kest-gateway"]
}
```

3. `@kest_verified(policy="delegation_policy", origin="internal")` evaluates before forwarding:

```cedar
// delegation_policy.cedar
permit(principal, action, resource) when {
    context["trust_score"] >= 10 &&
    context has "principal_user" &&
    context["principal_user"] != "" &&
    context has "principal_agent" &&
    context["principal_agent"] != ""
};
// → Allow (trust_score=100 internal, user=alice UUID, agent=kest-agent)
```

4. Forwards the OBO token to `kest-gateway /authorise`, then the returned task token to `/execute-task`.

### 5.3 Decode the Task Token

```bash
TASK_TOKEN="<paste task_token from step 5.2>"
echo "$TASK_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**Task token payload:**

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

Key observations:
- `scope` is **only** `task:process-data` — Alice's `read:data write:data` scopes are gone
- `iss` is the gateway itself (Approach A self-signing)
- `delegated_user` + `delegated_agent` preserve the original chain identity

---

## Step 6 — Cedar Policy Deep Dive

### `gateway_policy.cedar` — Enforced on `/authorise`

```cedar
// Located: showcase/kest-lab/cedar/policies/gateway_policy.cedar

permit(principal, action, resource) when {
    context["trust_score"] >= 10 &&              // OBO from internet entry → score=10 ✓
    context has "principal_user" &&
    context["principal_user"] != "" &&           // alice's UUID present ✓
    context has "principal_agent" &&
    context["principal_agent"] != "" &&          // "kest-agent" present ✓
    context has "principal_scope" &&
    context["principal_scope"] like "*read:data*" // scope contains read:data ✓
};
```

**Context dictionary passed to this policy** (from `CedarLocalEngine._flatten`):

```python
{
    "principal": "spiffe://kest.internal/workload/kest-gateway",
    "trust_score": 100,         # ORIGIN_TRUST_MAP["internal"] = 100
    "is_root": False,
    "chain_tip": "31a2f9...",   # SHA-256 of audit entry #1
    "principal_user": "a1b2c3d4-0001-0001-0001-000000000001",
    "principal_agent": "kest-agent",
    "principal_scope": "openid profile roles read:data write:data",
}
```

### `task_policy.cedar` — Enforced on `/execute-task`

```cedar
// Located: showcase/kest-lab/cedar/policies/task_policy.cedar

permit(principal, action, resource) when {
    context["trust_score"] >= 50 &&                            // internal = 100 ✓
    context has "principal_scope" &&
    context["principal_scope"] == "task:process-data"          // exact match ✓
};
```

The gateway injects the task token's scope into baggage **before** the `@kest_verified` call:

```python
# gateway.py (lines 299–313)
token_claims = _decode_task_token(task_token)
task_scope = token_claims.get("scope", "")     # "task:process-data"
delegated_user = token_claims.get("delegated_user", "")
delegated_agent = token_claims.get("delegated_agent", "")

ctx = otel_context.get_current()
ctx = otel_baggage.set_baggage("kest.principal_scope", task_scope, context=ctx)
ctx = otel_baggage.set_baggage("kest.principal_user", delegated_user, context=ctx)
ctx = otel_baggage.set_baggage("kest.principal_agent", delegated_agent, context=ctx)
token = otel_context.attach(ctx)
```

### `workload_user_policy.cedar` — Enforced at each hop

```cedar
// Located: showcase/kest-lab/cedar/policies/workload_user_policy.cedar

permit(principal, action, resource) when {
    context["trust_score"] >= 10 &&
    context has "principal_user" &&
    context["principal_user"] != ""
};
```

The OTel baggage carrying `kest.principal_user`, `kest.principal_scope`, and `kest.chain_tip` propagates automatically from `kest-gateway → hop1 → hop2 → hop3` via the `baggage` header injected by `_execute_task_logic`:

```python
# gateway.py (lines 339–344)
all_baggage = baggage.get_all()
baggage_header = ",".join(f"{k}={v}" for k, v in all_baggage.items())
headers: dict[str, str] = {}
if baggage_header:
    headers["baggage"] = baggage_header
```

---

## Step 7 — Run Live Integration Tests

The integration tests run **inside the `hop1` container** to satisfy SPIRE's PID namespace attestation requirements. SPIRE's Unix workload attestor uses `SO_PEERCRED` to verify that the connecting process belongs to the registered workload — this only works when tests run inside the same PID namespace as the workload.

```bash
moon run kest-core-python:test-live
```

This executes:

```bash
docker compose exec hop1 sh -c '
  until /app/.venv/bin/python -m pytest --version 2>/dev/null; do
    echo "Waiting for hop1 to be ready..." && sleep 2
  done &&
  /app/.venv/bin/python -m pytest /app/tests/'
```

To run only the gateway E2E tests:

```bash
docker compose exec hop1 /app/.venv/bin/python -m pytest /app/tests/test_gateway_e2e.py -v
```

### Test Suite: `test_gateway_e2e.py`

The file covers four test flows. All use helpers from `conftest.py`:

```python
# conftest.py — Keycloak ROPC helper
async def get_keycloak_token(
    username: str,
    password: str,
    client_id: str = "kest-cli",
    scope: str = "openid profile roles email",
) -> str:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"http://keycloak:8080/realms/kest-lab/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": client_id,
                "username": username,
                "password": password,
                "scope": scope,
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

# conftest.py — RFC 8693 OBO exchange helper
async def exchange_token_obo(subject_token: str) -> str:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            ...,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_token,
                "client_id": "kest-agent",
                "client_secret": "kest-agent-secret",
            },
        )
        return resp.json()["access_token"]
```

### Flow D — Happy Path (`test_full_delegation_chain_alice`)

**Input:**
- Alice's token with `scope=openid profile roles read:data write:data`
- `POST http://kest-agent:8001/delegate-to-gateway`

**Assertions:**
- `response.status == "delegated_via_gateway"`
- `authorise_response.granted_scope == "task:process-data"`
- Task token `scope == "task:process-data"` (does **not** contain `read:data`)
- Task token carries `delegated_user == alice_uuid`
- Audit trail has ≥ 6 entries within 20 seconds
- At least one audit entry has `user=alice_uuid` + `agent=kest-agent`

```python
@pytest.mark.live
@pytest.mark.asyncio
async def test_full_delegation_chain_alice(wait_for_audit):
    alice_token = await get_alice_token_with_data_scopes()
    claims = decode_jwt_payload(alice_token)
    user_id = claims.get("sub")  # UUID — kest-cli drops preferred_username

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{AGENT_URL}/delegate-to-gateway",
            headers={"Authorization": f"Bearer {alice_token}"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "delegated_via_gateway"

    task_token = data["authorise_response"]["task_token"]
    task_claims = decode_jwt_payload(task_token)
    assert task_claims["scope"] == "task:process-data"
    assert "read:data" not in task_claims["scope"]

    audit = wait_for_audit(timeout=20, expected_count=6)
    assert any_audit_matches(all_audit_payloads(audit), user=user_id, agent="kest-agent")
```

### Flow E — Insufficient Scope (`test_gateway_denies_insufficient_scope`)

**Input:**
- Alice's token **without** `read:data` (default scopes only: `openid profile roles email`)
- Performs OBO exchange directly, then `POST http://kest-gateway:8002/authorise`

**Expected output:**

```
HTTP 403 Forbidden
{"detail": "Permission denied by policy 'gateway_policy': ..."}
```

`gateway_policy` denies because `context["principal_scope"] like "*read:data*"` is false.

```python
async def test_gateway_denies_insufficient_scope():
    alice_token_no_data = await get_keycloak_token("alice", "alice")
    obo_token = await exchange_token_obo(alice_token_no_data)

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{GATEWAY_URL}/authorise",
            headers={"Authorization": f"Bearer {obo_token}"},
        )

    assert response.status_code == 403
```

### Flow F — Task Token Cannot Re-Authorise (`test_task_token_cannot_access_authorise_endpoint`)

**Input:**
- Full authorise flow to obtain a `task_token` with `scope=task:process-data`
- Present that task token back to `POST /authorise`

**Expected output:**

```
HTTP 403 Forbidden
```

`gateway_policy` requires `context["principal_scope"] like "*read:data*"`. `task:process-data` does not satisfy this, enforcing **one-way scope narrowing** — task tokens cannot escalate back into delegation tokens.

### Flow G — Audit Trail Integrity (`test_audit_trail_integrity`)

This is the **reference compliance test**. It verifies the Merkle chain properties of the audit trail:

```python
async def test_audit_trail_integrity(wait_for_audit):
    alice_token = await get_alice_token_with_data_scopes()
    # Trigger full chain...
    audit = wait_for_audit(timeout=25, expected_count=6)
    payloads = all_audit_payloads(audit)

    # 1. Alice's UUID in all entries
    assert any_audit_matches(payloads, user=user_id)

    # 2. OBO delegation entry (alice + kest-agent)
    assert any_audit_matches(payloads, user=user_id, agent="kest-agent")

    # 3. Merkle chain linkage: entries after the first have non-"0" parent_ids
    prev_hashes = [p.get("parent_ids") for p in payloads]
    chained_entries = [h for h in prev_hashes
                       if h is not None and len(h) > 0 and h[0] != "0"]
    assert len(chained_entries) >= 3  # execute-task + 3 hops

    # 4. Chain length
    assert len(payloads) >= 6
```

**What a decoded audit entry looks like:**

```json
{
  "entry_id": "33333333-aaaa-bbbb-cccc-000000000003",
  "operation": "_execute_task_logic",
  "classification": "system",
  "trust_score": 100,
  "parent_ids": ["c82664a3cf66be1310319801ff96e64c..."],
  "added_taints": [],
  "taints": [],
  "labels": {
    "principal": "spiffe://kest.internal/workload/kest-gateway",
    "kest.identity": "{\"user\": \"a1b2c3d4-...\", \"agent\": \"kest-agent\"}",
    "trace_id": "d449a53efe8b1cd431d84db00f8dc43a"
  },
  "timestamp_ms": 1775494709000
}
```

Each entry's `parent_ids[0]` is the SHA-256 hash of the **previous entry's JWS signature** — forming the tamper-evident Merkle chain.

**Expected test output:**

```
tests/test_gateway_e2e.py::test_full_delegation_chain_alice PASSED
tests/test_gateway_e2e.py::test_gateway_denies_insufficient_scope PASSED
tests/test_gateway_e2e.py::test_task_token_cannot_access_authorise_endpoint PASSED
tests/test_gateway_e2e.py::test_audit_trail_integrity PASSED

========================= 4 passed in 18.32s ==========================
```

---

## Step 8 — Inspect the Audit Trail

### View OTel Spans

```bash
moon run kest-lab:logs-otel
```

This streams the OTel Collector's stdout, where you'll see span JSON from each service. Kest audit entries are exported as OTel `log` records with `kest.passport` as an attribute.

### Read the Raw Audit File

During test execution, `conftest.py` writes signed audit entries to `lab_audit.json` inside the `hop1` container's working directory (`/app/lab_audit.json`). To inspect it:

```bash
docker compose exec hop1 cat /app/lab_audit.json | python3 -m json.tool | head -80
```

The file is an array of JWS compact serializations. Each can be decoded with:

```python
import base64, json

def decode_jws(jws: str) -> dict:
    parts = jws.split(".")
    pad = "=" * ((4 - len(parts[1]) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(parts[1] + pad))
```

### Verify the Chain Programmatically

From Python inside a container or locally once the chain is exported:

```python
from kest.core.models import Passport, PassportVerifier

# Deserialize from the JWS array
passport = Passport.deserialize(baggage_passport_json)

PassportVerifier.verify(passport, providers={
    "spiffe://kest.internal/workload/kest-agent":   agent_identity,
    "spiffe://kest.internal/workload/kest-gateway": gateway_identity,
    "spiffe://kest.internal/workload/hop1":         hop1_identity,
    "spiffe://kest.internal/workload/hop2":         hop2_identity,
    "spiffe://kest.internal/workload/hop3":         hop3_identity,
})
```

---

## Step 9 — Tear Down

```bash
moon run kest-lab:down
```

This runs `docker compose down --remove-orphans`, stopping and removing all containers. Named volumes (`spire-server-data`, `spire-agent-data`, `kest-lab-venv`) are preserved between runs unless you pass `-v`:

```bash
cd showcase/kest-lab && docker compose down --remove-orphans -v
```

---

## Troubleshooting

### `spire-agent` fails to start (join token expired)

Join tokens in SPIRE expire after 600 seconds. If you wait too long between `bootstrap` and `up`, the agent will fail attestation. Fix:

```bash
moon run kest-lab:down
moon run kest-lab:up
```

The bootstrap script generates a fresh token on every `up`.

### Keycloak not ready yet (token exchange returns 503)

Keycloak takes 20–40 seconds to import the realm on a cold start. The integration tests poll with retries, but manual `curl` calls may fail. Wait for:

```bash
curl -sf http://localhost:8080/realms/kest-lab || echo "not ready"
```

### Tests fail with `No audit entries found`

The `wait_for_audit` fixture polls `lab_audit.json` every 500 ms for up to the specified `timeout`. If the gateway chain times out, check gateway logs:

```bash
docker compose logs kest-gateway --tail=50
```

### SPIRE socket not found inside container

Verify the `spire/agent/public/` directory exists and the `spire-agent` has completed attestation:

```bash
ls showcase/kest-lab/spire/agent/public/api.sock
moon run kest-lab:spire-healthcheck
```

---

## Reference: Moon Tasks

| Task | Command | Description |
|---|---|---|
| Start full stack | `moon run kest-lab:up` | Bootstrap + compose up |
| Stop all services | `moon run kest-lab:down` | Compose down |
| Check SPIRE health | `moon run kest-lab:spire-healthcheck` | Agent health status |
| Fetch SVID bundle | `moon run kest-lab:fetch-bundle` | Inspect X.509 SVID trust bundle |
| Run live tests | `moon run kest-core-python:test-live` | Full integration test suite in hop1 |
| Stream OTel logs | `moon run kest-lab:logs-otel` | Live audit trail from OTel Collector |

---

## Source Files

| File | Description |
|---|---|
| [`showcase/kest-lab/docker-compose.yml`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/docker-compose.yml) | Full service definitions |
| [`showcase/kest-lab/bootstrap.sh`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/bootstrap.sh) | SPIRE join token + workload registration |
| [`showcase/kest-lab/gateway.py`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/gateway.py) | Gateway: scope enforcement + task token minting |
| [`showcase/kest-lab/agent.py`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/agent.py) | Agent: OBO exchange + gateway delegation |
| [`showcase/kest-lab/app.py`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/app.py) | Hop workload: `@kest_verified` decorated handler |
| [`showcase/kest-lab/cedar/policies/`](https://github.com/eterna2/kest/tree/main/showcase/kest-lab/cedar/policies) | All Cedar `.cedar` policy files |
| [`showcase/kest-lab/tests/test_gateway_e2e.py`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/tests/test_gateway_e2e.py) | Gateway E2E integration tests (Flows D–G) |
| [`showcase/kest-lab/tests/conftest.py`](https://github.com/eterna2/kest/blob/main/showcase/kest-lab/tests/conftest.py) | Shared fixtures and Keycloak/OBO helpers |
