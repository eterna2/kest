# Continuous Adaptive Risk and Trust Assessment (CARTA)

Kest implements the CARTA model by propagating and attenuating trust scores throughout the execution graph.

## Trust Scores (0–100)

A trust score is an **integer between 0 (untrusted) and 100 (fully trusted)**. Using integers makes thresholds immediately legible in policies without floating-point comparison issues.

| Origin | Score | Description |
|---|---|---|
| `"system"` | **100** | Internal system components, cron jobs |
| `"internal"` | **100** | API gateway, verified internal services |
| `"verified_rag"` | **90** | Verified RAG pipeline sources |
| `"third_party_api"` | **60** | Trusted external APIs (Stripe, GitHub) |
| `"user_input"` | **40** | Direct human user input |
| `"internet"` | **10** | Untrusted public web sources |
| `"llm"` | **0** | Raw LLM output |

## Trust Evaluators

Trust propagation is handled by a `TrustEvaluator`. The default uses a **weakest-link** model:

```python
from kest.core import DefaultTrustEvaluator

evaluator = DefaultTrustEvaluator()
# trust = (min(parent_scores) * self_score) // 100
```

## Policy Integration

Policies receive `trust_score` as an integer. For high-value operations, set a high minimum threshold. For public entry points, set a lower threshold.

### Rego Example

```rego
package kest.allow

import future.keywords

default allow := false

allow if {
    input.trust_score >= 80
    input.workload_id == "trusted-service"
}
```

### Cedar Example

```cedar
permit(
    principal,
    action == Action::"TransferFunds",
    resource
) when {
    context["trust_score"] >= 80
};
```

## Common Thresholds

| Threshold | Meaning |
|---|---|
| `>= 100` | Fully trusted; internal system only |
| `>= 50` | Internal workload or verified delegation |
| `>= 10` | Minimum viable trust (internet entry with valid identity) |
| `= 0` | Blocked; raw LLM output or completely untrusted |
