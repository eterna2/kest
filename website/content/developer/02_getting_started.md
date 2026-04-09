# Getting Started with Kest

This guide walks you through securing your first Python function with Kest — from installation to a fully working policy-enforced, cryptographically signed execution.

## 1. Installation

Install the Kest Python package:

```bash
pip install kest
```

Or with [uv](https://docs.astral.sh/uv/) (recommended):

```bash
uv add kest
```

This installs the Python package along with its Rust core (`kest-core-rs`) for high-performance RFC 8785 canonicalization and Ed25519 signing.

### Verify the Installation

```python
from kest.core import version
print(version())  # → "0.3.0"
```

## 2. Configuration

Kest uses a global `configure()` function to set up the execution environment. This should be called **once at application startup** — typically in your `main()`, FastAPI `lifespan`, or equivalent:

```python
from kest.core import configure, MockPolicyEngine

configure(
    engine=MockPolicyEngine(allow=True),
    # identity is auto-detected by default
)
```

### `configure()` Parameters

| Parameter | Type | Purpose |
|---|---|---|
| `engine` | `PolicyEngine` | **Required.** The policy engine for authorization checks |
| `identity` | `IdentityProvider` | An explicit identity provider. If omitted, Kest auto-detects |
| `cache` | `CacheProvider` | Optional. For Claim Check pattern (large Passports) |
| `enterprise_policies` | `list[str]` | Optional. Enterprise baseline policy names |
| `deviations` | `list[dict]` | Optional. Policy deviations (authorized exemptions) |
| `clear` | `bool` | If `True`, resets all global config to `None` |

### Development vs Production

```python
# Development / Unit testing
configure(
    engine=MockPolicyEngine(allow=True),
    # Auto-detects LocalEd25519Provider
)

# Production
from kest.core import OPAPolicyEngine, SPIREProvider
configure(
    engine=OPAPolicyEngine(host="localhost", port=8181),
    identity=SPIREProvider(
        socket_path="/run/spire/sockets/agent.sock"
    ),
    enterprise_policies=["baseline-auth", "data-classification"],
)
```

## 3. Your First Protected Function

The `@kest_verified` decorator wraps any function with the full Kest verification lifecycle:

```python
from kest.core import kest_verified

@kest_verified(
    policy="kest/allow_trusted",
    source_type="internal"
)
def process_payment(order_id: str, amount: float) -> dict:
    """Process a payment — now cryptographically verified."""
    return {
        "order_id": order_id,
        "amount": amount,
        "status": "completed"
    }
```

### What Happens When You Call It

When you call `process_payment("ORD-123", 99.95)`, the decorator executes a 13-step lifecycle before your function body runs:

1. **Extract context** — reads existing Passport from OTel baggage
2. **Evaluate trust** — computes trust score based on source type and parent lineage
3. **Collect taints** — computes cumulative taint set
4. **Hash inputs** — SHA-256 of the function arguments
5. **Build KestEntry** — populate all fields
6. **Evaluate enterprise policies** → OPA/Cedar
7. **Evaluate platform policies** → OPA/Cedar
8. **Evaluate application policies** → OPA/Cedar
9. **Evaluate function policies** → OPA/Cedar
10. **Sign entry** — canonicalize (RFC 8785) → JWS (EdDSA)
11. **Append to Passport** — update Merkle chain
12. **Execute function** — your code runs
13. **Hash output** — SHA-256 of return value; emit OTel span

If any policy denies (steps 6–9) or any signing/identity error occurs (step 10), the function body **never executes**.

### Calling the Function

```python
# Call it like any normal function
result = process_payment("ORD-123", 99.95)
print(result)
# → {"order_id": "ORD-123", "amount": 99.95, "status": "completed"}
```

The Passport is automatically maintained in the OTel context. If you make another `@kest_verified` call from within this function, the Merkle chain extends automatically.

## 4. Inspecting the Passport

Access the current execution context from anywhere:

```python
from kest.core.context import get_current_passport

passport = get_current_passport()

# Number of entries in the chain
print(f"Chain length: {len(passport.entries)}")

# The last JWS entry (raw compact serialization)
print(f"Latest: {passport.entries[-1][:80]}...")
```

## 5. Running with a Real Policy Engine

Replace `MockPolicyEngine` with a real OPA sidecar:

```bash
# Start OPA with a simple policy
docker run -d -p 8181:8181 \
  -v ./policies:/policies \
  openpolicyagent/opa:latest run \
  --server /policies
```

Create `policies/kest/allow_trusted.rego`:

```rego
package kest.allow_trusted

default allow = false

allow {
    input.trust_score >= 40
}
```

Update your configuration:

```python
from kest.core import configure, OPAPolicyEngine

configure(
    engine=OPAPolicyEngine(host="localhost", port=8181),
)
```

Now `@kest_verified(policy="kest/allow_trusted")` will make real HTTP calls to OPA.

## 6. Next Steps

- **[Trust Model](trust_model)** — learn how trust scores degrade and how to control them
- **[Identity & Context](identity_context)** — configure SPIRE, AWS, or OIDC identity
- **[Decorators Reference](decorators)** — every parameter of `@kest_verified`
- **[Testing](testing)** — testing strategies and the kest-lab environment

---

*For the complete API specification, see [Spec §5](../blog/design/kest_spec_v0.3.0).*
