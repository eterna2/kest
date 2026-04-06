---
title: Identity & Resource Context
description: Pass user, agent, task, and resource attributes to @kest_verified for fine-grained, identity-aware policy enforcement.
---

# Identity & Resource Context

Kest's `@kest_verified` decorator supports **fine-grained, identity-aware authorization**. Beyond workload identity (SPIFFE), you can explicitly declare:

- **Who** is calling (the `user` — the original human or system principal)
- **Via what** (the `agent` — the service or bot acting on the user's behalf)
- **For what** (the `task` / scope)
- **On what** (the `resource_id` and `resource_attr` — the resource being accessed)

These attributes are passed to your policy engine and signed into the cryptographic audit trail, giving you **per-request, attribute-based access control (ABAC)** with a non-fungible evidence chain.

---

## The Three-Layer Identity Model

```
┌───────────────────────────────────┐
│  subject.workload                 │  ← SPIFFE/SVID workload identity (always present)
│  subject.user     "alice@corp"    │  ← Human or system principal (optional, from JWT or explicit)
│  subject.agent    "data-bot-1"   │  ← Delegated agent identity (optional)
│  subject.task     "read:docs"     │  ← Scope / task identifier (optional)
├───────────────────────────────────┤
│  object.id        "doc-abc123"    │  ← Resource being accessed
│  object.attributes { class: "C" } │  ← Attributes for ABAC evaluation
├───────────────────────────────────┤
│  environment.trust_score  95      │  ← Propagated CARTA score (integer 0-100)
│  environment.taints       [...]   │  ← Accumulated taint labels
└───────────────────────────────────┘
```

All of the above is available to your OPA Rego or Cedar policy as the `context` argument to `evaluate()`.

---

## 1. Explicit Static Values

Pass values directly when they are known at decoration time:

```python
from kest.core import kest_verified

@kest_verified(
    policy="financial/transfer",
    user="alice@corp.com",
    task="initiate:transfer",
    resource_id="account-001",
    resource_attr={"currency": "USD", "tier": "premium"},
)
async def transfer_funds(amount: float, recipient: str):
    """Transfers funds. Policy sees the full identity + resource context."""
    ...
```

---

## 2. Dynamic Callable Resolution

For values that depend on the function's arguments, pass a **callable** that receives `call_args: dict` (a mapping of argument names to their values):

```python
@kest_verified(
    policy="data/read",
    user=lambda args: args["request"].user.email,
    agent=lambda args: args["request"].headers.get("x-agent-id"),
    resource_id=lambda args: f"doc:{args['doc_id']}",
    resource_attr=lambda args: {"team": args["request"].user.team},
)
async def read_document(doc_id: str, request):
    """Policy sees the actual user and document details at call time."""
    ...
```

---

## 3. Automatic JWT Propagation via Middleware

For HTTP services, the simplest pattern is to **let the middleware extract identity from a JWT** and propagate it as OTel Baggage. The decorator then **falls back to baggage** if no explicit `user/agent/task` is provided.

### Step 1: Add `KestIdentityMiddleware`

```python
from fastapi import FastAPI
from kest.core.ext import KestIdentityMiddleware, KestMiddleware

app = FastAPI()

# Extracts kest.user / kest.agent / kest.task from the Bearer JWT
app.add_middleware(KestIdentityMiddleware)

# Also propagate Kest lineage across hops
app.add_middleware(KestMiddleware)
```

The middleware automatically extracts:
| JWT Claim | Baggage Key | Description |
|---|---|---|
| `sub` | `kest.user` | The user subject |
| `client_id` | `kest.agent` | The OAuth2 client ID |
| `scope` | `kest.task` | The token scopes |

It also stores the raw JWT as `kest.jwt` in baggage for downstream verification.

### Step 2: No changes to your decorated functions needed

```python
@kest_verified(policy="data/read")  # No explicit user/agent needed
async def read_document(doc_id: str):
    # user, agent, task automatically read from kest.* baggage
    ...
```

---

## 4. Manual JWT Extraction (non-ASGI)

For non-ASGI environments (background workers, Celery tasks), use `extract_claims_to_baggage()` directly:

```python
import opentelemetry.context as otel_context
from opentelemetry import baggage
from kest.core.ext import extract_claims_to_baggage

def process_job(job_data: dict):
    # Extract claims from the job's JWT payload
    claims = extract_claims_to_baggage(
        jwt_token=job_data["user_jwt"],
        user_claim="sub",        # default
        agent_claim="client_id", # default
        task_claim="scope",      # default
    )
    # Attach to current OTel context
    ctx = otel_context.get_current()
    for k, v in claims.items():
        ctx = baggage.set_baggage(k, v, context=ctx)
    token = otel_context.attach(ctx)
    try:
        do_verified_work()  # @kest_verified will pick up kest.user etc.
    finally:
        otel_context.detach(token)
```

You can also customize the claim and baggage key names:

```python
claims = extract_claims_to_baggage(
    jwt_token=my_token,
    user_claim="email",       # use email instead of sub
    user_key="kest.user",     # default baggage key
    agent_key="kest.agent",   # default baggage key
)
```

---

## 5. Reading Identity Context Inside Functions

Once identity is in baggage, helper functions let you read it from anywhere in the call stack:

```python
from kest.core.context import (
    get_current_user,
    get_current_agent,
    get_current_task,
    get_current_jwt,
    get_current_passport,
)

@kest_verified(policy="audit/log")
def log_action(action: str):
    user = get_current_user()   # "alice@corp.com"
    agent = get_current_agent() # "data-bot-1" or None
    task = get_current_task()   # "read:documents" or None
    jwt = get_current_jwt()     # Raw JWT token if set by middleware
    ...
```

---

## 6. What the Policy Sees (Structured Engine Context)

When any `@kest_verified` function executes, the following JSON structure is sent to your OPA or Cedar engine:

```json
{
  "subject": {
    "workload": "spiffe://kest.internal/payment-service",
    "user": "alice@corp.com",
    "agent": "data-bot-1",
    "task": "initiate:transfer",
    "trust_score": 95,
    "taints": ["internet_ingress"]
  },
  "object": {
    "id": "account-001",
    "attributes": {
      "currency": "USD",
      "tier": "premium"
    }
  },
  "environment": {
    "is_root": false,
    "source_type": "internal",
    "parent_hash": "c5cc68f7f52f...",
    "policy_names": ["financial/transfer"]
  },
  "identity": "spiffe://kest.internal/payment-service",
  "trust_score": 95
}
```

> **Note:** `identity` and `trust_score` are also available as top-level keys for backwards compatibility with older policies.

---

## 7. Audit Trail: What Gets Signed

The `user`, `agent`, `task`, and `resource_attr` values are JSON-serialized and embedded in the **signed `KestEntry` labels**, making them part of the cryptographic lineage:

| Label Key | Content |
|---|---|
| `kest.identity` | `{"user": "alice@corp.com", "agent": "bot-1", "task": "transfer"}` |
| `kest.resource_attr` | `{"currency": "USD", "tier": "premium"}` |
| `kest.signature` | Full JWS over the KestEntry (tamper-evident) |

To retrieve these values later, parse the JWS payload from your audit log.

---

## See Also

- [Context Propagation (Middleware)](middleware.md) — How identity flows across service boundaries
- [CARTA Trust Model](trust_model.md) — How trust scores propagate
- [Cedar Policies](../policies/cedar.md) — Writing `subject.user`-aware Cedar policies
- [API Reference: `kest.core.context`](../reference/context.md) — Context helper functions
