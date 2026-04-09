# Four-Tier ABAC Policy Architecture

Kest implements a **four-tier policy hierarchy** where every execution must pass through multiple layers of authorization before the protected operation runs. Policies are evaluated as code — not manually reviewed access control lists — using Open Policy Agent (OPA) or Cedar as sidecar engines.

## The Four-Tier Hierarchy

![Policy tier hierarchy showing Enterprise, Platform, Application, and Function levels with deny/allow flow](/images/policy-tiers.png)

Policies are evaluated in strict descending order. A denial at **any** tier halts evaluation and blocks execution (Spec §9.6):

| Tier | Scope | Who Controls It | Example |
|---|---|---|---|
| **1. Enterprise Baseline** | All invocations globally | Security team (deployment config) | `baseline-auth`, `data-classification` |
| **2. Platform** | A logical service group | Platform team (deployment config) | `payments-pci`, `hipaa-phi-access` |
| **3. Application** | A single application | App team (app-level config) | `checkout-fraud-check` |
| **4. Function-level** | One decorated function | Developer (code) | `kest/allow_trusted` |

### Key Invariant: Supplements, Not Replaces

Function-level policies **supplement** — they never replace — higher-tier policies. A developer cannot bypass an enterprise baseline policy by specifying their own function-level policy. This is enforced architecturally:

```python
@kest_verified(policy="kest/allow_trusted")  # Tier 4 only
def process_order(order_id: str):
    # Enterprise + Platform policies are ALSO evaluated
    # before this function executes
    ...
```

## OPA Integration (Rego)

The `OPAPolicyEngine` calls a co-located OPA sidecar at `localhost:8181`:

```python
from kest.core import configure, OPAPolicyEngine

configure(
    engine=OPAPolicyEngine(host="localhost", port=8181),
    enterprise_policies=["baseline-auth", "data-classification"],
)
```

### Rego Policy Example

```rego
package kest.allow_trusted

default allow = false

allow {
    input.trust_score >= 50
    not input.subject.taints[_] == "contains_pii"
}
```

The policy receives the full evaluation context (Spec §9.2):

```json
{
  "subject": {
    "workload": "spiffe://kest.internal/workload/payment-svc",
    "user": "alice",
    "trust_score": 40,
    "taints": ["user_input"]
  },
  "object": {
    "id": "order-12345",
    "attributes": {"amount": 150}
  },
  "environment": {
    "is_root": false,
    "source_type": "user_input",
    "parent_hash": "a1b2c3d4..."
  }
}
```

## Cedar Integration

The `CedarPolicyEngine` calls a Cedar Agent sidecar at `localhost:8180`:

```python
from kest.core import configure, CedarPolicyEngine

configure(
    engine=CedarPolicyEngine(host="localhost", port=8180),
)
```

### Cedar Policy Example

```cedar
permit(
    principal,
    action == Action::"process_payment",
    resource
) when {
    context.trust_score >= 50 &&
    !context.taints.contains("unverified_input")
};
```

## Policy Deviations

Sometimes, a specific function needs to be exempt from a higher-tier policy — for example, a refund flow that doesn't need PCI checks because it operates on already-cleared transactions. Kest supports this through **policy deviations** (Spec §2.4, F-PE-11):

```python
configure(
    enterprise_policies=["baseline-auth"],
    deviations=[{
        "scope": "process_refund",
        "policy": "payments-pci",
        "tier": "platform",
        "reason": "Refund flow operates on already-cleared transactions",
        "approver": "security-team@example.com"
    }]
)
```

### Critical Safeguards

1. **Deviations are configuration, not code** — developers cannot self-approve exemptions. Deviations must be declared in deployment configuration.

2. **Deviations are signed** — every deviation is recorded in the `policy_context.deviations` field of the signed KestEntry. This makes them cryptographically auditable.

3. **Deviations don't bypass recording** — a deviated invocation still produces a complete, signed entry in the Passport.

4. **Empty is normal** — most invocations have `deviations: []`. The field is always present so audit tools can distinguish "no deviations" from "field absent — possibly tampered."

## Evaluation Context

The structured context passed to every policy evaluation (Spec §9.2):

```json
{
  "subject": {
    "workload":    "spiffe://...",
    "user":        "alice",
    "agent":       "web-app",
    "task":        "checkout",
    "trust_score": 40,
    "taints":      ["user_input"]
  },
  "object": {
    "id":         "order-12345",
    "attributes": {"amount": 150, "currency": "USD"}
  },
  "environment": {
    "is_root":           false,
    "source_type":       "user_input",
    "parent_hash":       "a1b2c3d4...",
    "policy_names":      ["kest/allow_trusted"],
    "policy_tier":       "function",
    "active_deviations": []
  }
}
```

This rich context enables **Attribute-Based Access Control (ABAC)** — policies can make decisions based on who is calling, what they're accessing, the trust level of the request, and what risk tags (taints) are present.

## Logical AND Evaluation

When multiple policies are specified within a tier, **all** must independently return `true` (Spec §2.4, F-PE-03):

```python
@kest_verified(policy=["allow_trusted", "check_budget"])
def approve_purchase(amount: float):
    # Both policies must allow — if either denies, execution is blocked
    ...
```

---

*For the full policy engine interface, see [Spec §5.2](kest_spec_v0.3.0). For pre-built policies, visit the [Policy Library](/developers/policy/overview).*
