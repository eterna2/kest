# CARTA Trust Model

Kest implements **Continuous Adaptive Risk and Trust Assessment (CARTA)**. Trust is not a static binary state ("authenticated" vs "unauthenticated"); it is fluid and evaluated dynamically based on the execution lineage.

## Trust Scores (0–100)

Every execution hop produces a JWS-signed `KestEntry`. Part of the signed payload includes a `trust_score` as an **integer between 0 (Untrusted) and 100 (Fully Trusted)**. This makes the score directly comparable to percentage-based policy thresholds in OPA and Cedar.

### Origin Trust Map

When a function is the **root** of a chain (i.e., `is_root=True`), its initial trust score is bootstrapped from `ORIGIN_TRUST_MAP` using the `origin` parameter:

| `origin=` | `trust_score` | Description |
|---|---|---|
| `"system"` | **100** | Trusted internal system component or cron job |
| `"internal"` | **100** | Internal API gateway or service-to-service call |
| `"verified_rag"` | **90** | Data from a verified RAG pipeline |
| `"third_party_api"` | **60** | External integrations (Stripe, GitHub, etc.) |
| `"user_input"` | **40** | Data provided by a human user directly |
| `"internet"` | **10** | Traffic from the untrusted public internet |
| `"llm"` | **0** | Raw, unverified LLM output |

```python
# Public API: bootstrapped at trust_score=10
@kest_verified(policy="api_gateway", origin="internet")
async def handle_public_request():
    ...

# Internal service: bootstrapped at trust_score=100
@kest_verified(policy="task_policy", origin="internal")
async def execute_task():
    ...
```

## Trust Propagation

By default, Kest applies a **weakest-link** propagation model across the DAG:

```
score = (min(parent_scores) * self_score) // 100
```

This means:
- A single low-trust ancestor degrades all downstream scores.
- Trust **never improves** without an explicit override.
- An internet entry (score=10) propagating through an internal node (score=100) yields: `(10 * 100) // 100 = 10`.

```python
from kest.core.models import DefaultTrustEvaluator

evaluator = DefaultTrustEvaluator()
# evaluator.calculate(self_score=100, parent_scores=[10, 100])
# → (10 * 100) // 100 = 10
```

## Policy Integration

The `trust_score` integer is passed directly to the policy engine context. Policies compare it against integer thresholds:

### Rego Example

```rego
package kest.allow

import future.keywords

default allow := false

allow if {
    input.trust_score >= 80
    input.is_root == false
}
```

### Cedar Example

```cedar
permit(principal, action, resource) when {
    context["trust_score"] >= 50 &&
    context has "principal_scope" &&
    context["principal_scope"] == "task:process-data"
};
```

## Implementing Custom Evaluators

For systems with advanced risk models, inject a custom `TrustEvaluator`:

```python
from typing import List
from kest.core import TrustEvaluator, kest_verified

class WeightedTrustEvaluator(TrustEvaluator):
    def calculate(self, self_score: int, parent_scores: List[int]) -> int:
        """Weighted average of parent scores biased toward history."""
        if not parent_scores:
            return self_score
        avg_parent = sum(parent_scores) // len(parent_scores)
        return (avg_parent * 70 + self_score * 30) // 100

@kest_verified(policy="advanced_check", trust_evaluator=WeightedTrustEvaluator())
def my_function():
    ...
```

## Lineage Taints

Taints represent specific risks or data provenance labels (e.g., `"contains_pii"`, `"unverified_llm_output"`). Unlike the numeric trust score, taints are strings that **accumulate** across the DAG.

- **`added_taints`**: New risks introduced at this node.
- **`removed_taints`**: Taints this node has verified and cleaned (requires explicit override).
- **`taints`**: The full set of accumulated taints at this point in the chain.

All three are recorded in the signed `KestEntry` payload and passed to the policy engine for enforcement.

### Sanitizers — Taint Removal & Trust Override

To explicitly increase trust or declare data clean, configure a node as a **Sanitizer**:

```python
@kest_verified(
    policy="sanitizer_policy",
    trust_override=100,                    # bypass evaluator; force score to 100
    removed_taints=["unverified_input"],   # declare these taints cleared
)
async def input_scanner(data):
    # After this node, trust_score=100 and "unverified_input" is gone from taints.
    ...
```

The `removed_taints` are recorded in the signed payload so the removal itself is cryptographically auditable — any verifier can confirm *which* node claimed to sanitize which taints.
