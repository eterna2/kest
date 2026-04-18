---
title: Context Helpers
description: Read the current Kest execution context from anywhere in your call stack.
sidebarTitle: context.py
sidebarCode: |
  from kest.core.framework.context import (
      get_current_jwt,
      get_current_passport,
  )

  passport = get_current_passport()  # Encoded Merkle passport
---

The `kest.core.framework.context` module provides helper functions for reading the current Kest execution context from within any function in the call stack, without explicitly threading state through function arguments.

All values are read from the **OpenTelemetry Baggage** attached to the current context.

---

### `get_current_jwt() -> Optional[str]`

Returns the raw JWT token (`kest.jwt` baggage key). This is the full Bearer token stored by `KestIdentityMiddleware` for downstream verification. Treat with appropriate care — this is a sensitive credential.

```python
from kest.core.framework.context import get_current_jwt

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
from kest.core.framework.context import get_current_passport

passport_b64 = get_current_passport()
# Use PassportVerifier to validate
from kest.core import PassportVerifier
verifier = PassportVerifier()
is_valid = verifier.verify(passport_b64, expected_root="...")
```

---

## Accessing Other Baggage

Under the hood, helpers call `baggage.get_baggage(key)` using the current OpenTelemetry context. You can retrieve other context variables manually:

```python
from opentelemetry import baggage

user = baggage.get_baggage("kest.user")
agent = baggage.get_baggage("kest.agent")
task = baggage.get_baggage("kest.task")
```

| Baggage Key | Set by |
|---|---|
| `kest.user` | `KestIdentityMiddleware` (JWT `sub` claim) |
| `kest.agent` | `KestIdentityMiddleware` (JWT `client_id` claim) |
| `kest.task` | `KestIdentityMiddleware` (JWT `scope` claim) |
| `kest.jwt` | `KestIdentityMiddleware` |
| `kest.passport` | `@kest_verified` decorator |
| `kest.passport_z` | `@kest_verified` (compressed inline, Tier 2) |
| `kest.claim_check` | `@kest_verified` (Claim Check UUID, Tier 3) |
| `kest.chain_tip` | `@kest_verified` (SHA-256 of last entry) |

> **Hardening note (2026-04-11):** Baggage keys were renamed for spec compliance. Old key names (`kest.principal_user`, `kest.workload_agent`, `kest.scope`) are no longer written. Rebuild all services together when upgrading.

---

## See Also

- [Identity & Resource Context](../developer/06_identity_context.md) — Full guide on passing context to the decorator
- [Middleware & Context Propagation](../developer/04_middleware.md) — How identity moves across service hops
- [Identity Providers](03_identity.md) — Workload identity (SPIFFE, AWS, etc.)
