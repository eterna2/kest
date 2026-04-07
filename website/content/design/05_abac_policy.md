# ABAC Policy Enforcement

While Role-Based Access Control (RBAC) relies heavily on static, pre-defined user roles, modern microservices require context-aware policies. Kest implements **Attribute-Based Access Control (ABAC)** powered by Open Policy Agent (OPA) or Amazon Cedar.

## The Sidecar Pattern

Kest utilizes the sidecar pattern to enforce policies asynchronously:

1. Every container pod (Kubernetes) or task runs the Kest application alongside an instance of the OPA server or Cedar Agent.
2. When the application invokes a `@kest_verified` function, it issues a local, sub-millisecond HTTP request to the sidecar.

This architecture ensures that policy data is cached closely to the execution node, preventing the traditional performance bottleneck of centralized authorization endpoints.

## Multi-Policy Aggregation

Kest allows you to aggregate multiple policies on a single function execution using a simple list pattern:

```python
@kest_verified(policy=["check_rbac", "check_lineage"])
def process_data(data):
    pass
```

### The Logical AND Rule

Kest strictly applies **Logical AND** to multi-policy evaluations:
- The execution is only allowed if *every* specified policy returns `allow == true`.
- If a single policy evaluates to `false` or encounters a timeout, the execution is denied.
- A global `Deny` or `Forbid` rule within a policy cannot be overridden by an explicit `Allow` rule elsewhere in the evaluation chain.

## Lineage-Aware Policies (The Chinese Wall)

ABAC traditionally uses user attributes (e.g., department, device status). Kest introduces the concept of **Lineage-Aware ABAC**. The policy engine is fed the entire OTel Baggage state, containing the cryptographic execution history (`kest.lineage_root`) and the calculated `kest.trust_score`.

You can construct advanced security requirements based on the history of execution.

**Example: A Chinese Wall Policy (Rego)**
```rego
package kest.finance_policy

default allow = false

# Allow if the execution has not passed through the 'public_api' workload
allow if {
    not input.workload_id == "spiffe://internal/public_api"
    input.trust_score >= 80
}
```

By ensuring that policies have full access to the Merkle-verified execution path, organizations can enforce strict isolation guarantees in highly interconnected networks.
