---
title: Decorators
description: High-level Python decorators for securing application execution.
sidebarTitle: decorators.py
sidebarCode: |
  # Usage Pattern
  @kest_verified(
      policy="finance/limit",
      source_type="user_input"
  )
  def process(tx_data):
      return transfer(tx_data)
---

The `kest.core` module provides the primary interface for developers to secure their application logic using Kest.

The `kest.core` module provides the primary interface for developers to secure their application logic using Kest.

---

### `@kest_verified`

Enforces authorization and records cryptographic lineage for a function. This decorator performs a **Passport Check** at the start of the function.

#### Workflow
1. Verifies the existing lineage (Passport) from context.
2. Evaluates the configured policies (OPA, Cedar, etc.).
3. Calculates a trust score (CARTA) based on parents.
4. Appends a new signed audit entry to the Passport.
5. Propagates the updated Passport via OTel baggage.

#### Arguments
- `policy`: Signature of the policy to enforce. Can be a single string or a list.
- `engine`: Override for the global `PolicyEngine`.
- `identity`: Override for the global `IdentityProvider`.
- `trust_evaluator`: Logic for propagating trust scores.
- `source_type`: Descriptive name for the data source if this is a root node.
- `added_taints`: New taints to apply to the lineage at this node.
- `removed_taints`: Taints to remove (de-taint) at this node.

#### Example
```python
@kest_verified(policy="financial/transaction-limit")
def transfer_funds(amount: float):
    ...
```

---

### Configuration Getters

- **`get_active_engine() -> Optional[PolicyEngine]`**:
  Retrieves the globally configured PolicyEngine.
- **`get_active_identity() -> Optional[IdentityProvider]`**:
  Retrieves the globally configured IdentityProvider.
- **`get_active_cache() -> Optional[PolicyCache]`**:
  Retrieves the globally configured PolicyCache.
