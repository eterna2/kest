---
title: Context Helpers
description: Read the current Kest execution context from anywhere in your call stack.
sidebarTitle: context.py
sidebarCode: |
  from kest.core.context import (
      get_current_user,
      get_current_agent,
      get_current_task,
      get_current_jwt,
      get_current_passport,
  )

  user = get_current_user()   # "alice@corp.com"
  passport = get_current_passport()  # Encoded Merkle passport
---

The `kest.core.context` module provides helper functions for reading the current Kest execution context from within any function in the call stack, without explicitly threading state through function arguments.

All values are read from the **OpenTelemetry Baggage** attached to the current context.

---

### `get_current_user() -> Optional[str]`

Returns the user subject (`kest.user` baggage key) for the current request. Set by `KestIdentityMiddleware` from the JWT `sub` claim, or by explicitly passing `user=` to `@kest_verified`.

```python
from kest.core.context import get_current_user

def audit_action(action: str):
    user = get_current_user()
    print(f"[AUDIT] {user} performed {action}")
```

> Returns `None` if no user is set in the current context.

---

### `get_current_agent() -> Optional[str]`

Returns the agent service identity (`kest.agent` baggage key). Typically set from the JWT `client_id` claim via `KestIdentityMiddleware`.

```python
from kest.core.context import get_current_agent

agent = get_current_agent()  # e.g., "data-pipeline-bot"
```

> Returns `None` if no agent is set.

---

### `get_current_task() -> Optional[str]`

Returns the task or scope identifier (`kest.task` baggage key). Typically set from the JWT `scope` claim.

```python
from kest.core.context import get_current_task

task = get_current_task()  # e.g., "read:documents write:reports"
```

> Returns `None` if no task is set.

---

### `get_current_jwt() -> Optional[str]`

Returns the raw JWT token (`kest.jwt` baggage key). This is the full Bearer token stored by `KestIdentityMiddleware` for downstream verification. Treat with appropriate care — this is a sensitive credential.

```python
from kest.core.context import get_current_jwt

jwt = get_current_jwt()
if jwt:
    # Verify with your chosen JWT library (PyJWT, python-jose, etc.)
    ...
```

> Returns `None` if no JWT is in context.

---

### `get_current_passport() -> Optional[str]`

Returns the serialised Kest Passport (`kest.passport` baggage key). The Passport is the packed Merkle chain of JWS signatures accumulated across all hops.

```python
from kest.core.context import get_current_passport

passport_b64 = get_current_passport()
# Use PassportVerifier to validate
from kest.core.models import PassportVerifier
verifier = PassportVerifier()
is_valid = verifier.verify(passport_b64, expected_root="...")
```

---

## Usage Pattern: Structured Logging

A common pattern is to enrich your log entries with the current user and agent without passing them through every function:

```python
import logging
from kest.core.context import get_current_user, get_current_agent

log = logging.getLogger(__name__)

def get_kest_log_extra() -> dict:
    return {
        "kest.user": get_current_user(),
        "kest.agent": get_current_agent(),
    }

@kest_verified(policy="data/transform")
def transform_record(record: dict) -> dict:
    log.info("Transforming record", extra=get_kest_log_extra())
    ...
```

---

## Relationship to Baggage

Under the hood, all helpers call `baggage.get_baggage(key)` using the current OpenTelemetry context:

| Helper | Baggage Key | Set by |
|---|---|---|
| `get_current_user()` | `kest.user` | `KestIdentityMiddleware` (JWT `sub` claim) |
| `get_current_agent()` | `kest.agent` | `KestIdentityMiddleware` (JWT `client_id` claim) |
| `get_current_task()` | `kest.task` | `KestIdentityMiddleware` (JWT `scope` claim) |
| `get_current_jwt()` | `kest.jwt` | `KestIdentityMiddleware` |
| `get_current_passport()` | `kest.passport` | `@kest_verified` decorator |
| — | `kest.passport_z` | `@kest_verified` (compressed inline, Tier 2) |
| — | `kest.claim_check` | `@kest_verified` (Claim Check UUID, Tier 3) |
| — | `kest.chain_tip` | `@kest_verified` (SHA-256 of last entry) |

> **Hardening note (2026-04-11):** Baggage keys were renamed for spec compliance. Old key names (`kest.principal_user`, `kest.workload_agent`, `kest.scope`) are no longer written. Rebuild all services together when upgrading.

---

## See Also

- [Identity & Resource Context](../developer/identity_context.md) — Full guide on passing user/agent/task to the decorator
- [Middleware & Context Propagation](../developer/middleware.md) — How identity moves across service hops
- [Identity Providers](identity.md) — Workload identity (SPIFFE, AWS, etc.)
