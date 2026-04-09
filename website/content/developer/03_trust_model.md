# CARTA Trust Model

Kest implements **Continuous Adaptive Risk and Trust Assessment (CARTA)** — a model where trust is not a static binary (authenticated/unauthenticated) but a **dynamic integer** that flows through the execution graph, degrading through untrusted nodes and increasing only through explicit sanitization.

## Trust Scores (0–100)

Trust is represented as an integer from 0 (completely untrusted) to 100 (maximum trust). The score quantifies confidence in the provenance of the execution chain.

![Trust score propagation showing degradation through a service chain](/images/trust-degradation.png)

### The ORIGIN_TRUST_MAP

Every data source has a default trust score defined in the `ORIGIN_TRUST_MAP` (Spec §7.1):

| Source Type | Trust Score | Rationale |
|---|---|---|
| `system` | 100 | Machine-generated, no human input |
| `internal` | 80 | Internal API, behind perimeter |
| `verified_partner` | 70 | Contractually bound external partner |
| `partner` | 60 | Third-party integration |
| `authenticated_user` | 50 | Known human user, verified identity |
| `user_input` | 40 | Unverified user-provided data |
| `third_party` | 30 | External, untrusted service |
| `unauthenticated` | 10 | No identity verification |
| `adversarial` | 0 | Explicitly hostile input (pen testing) |

### Using `source_type`

```python
@kest_verified(
    policy="kest/allow_trusted",
    source_type="user_input"  # trust = 40
)
def handle_form_submission(data: dict):
    return validate(data)
```

### Registering Custom Source Types

Extend the trust map with domain-specific source types:

```python
from kest.core import register_origin_trust

register_origin_trust("ml_model_output", 65)
register_origin_trust("llm_generated", 25)

@kest_verified(
    policy="kest/allow_trusted",
    source_type="llm_generated"  # trust = 25
)
def process_llm_output(text: str):
    return sanitize(text)
```

## Trust Propagation

When a `@kest_verified` function calls another `@kest_verified` function, trust propagates with **monotonic non-increase** — it can only stay the same or decrease:

```
effective_trust = min(parent_trust, self_origin_trust)
```

### Example: Trust Degradation

```python
@kest_verified(policy="allow", source_type="system")        # trust=100
def step_1():
    return step_2()

@kest_verified(policy="allow", source_type="internal")      # trust=min(100,80)=80
def step_2():
    return step_3()

@kest_verified(policy="allow", source_type="user_input")    # trust=min(80,40)=40
def step_3():
    return {"result": "processed"}
```

The trust at `step_3` is 40 — capped by `user_input` — regardless of how many trusted hops preceded it. This is the core CARTA principle: **one untrusted input taints the entire chain**.

## Trust Override

In some cases, you need direct control over the trust score — for example, when a function sanitizes input and should be trusted at a higher level:

```python
@kest_verified(
    policy="kest/allow_trusted",
    trust_override=80  # Override to 80, bypassing propagation
)
def sanitize_user_input(data: dict) -> dict:
    """After validation and sanitization, we trust this output."""
    validated = deep_validate(data)
    return escape_all_strings(validated)
```

> **Warning**: `trust_override` bypasses the normal propagation rules. Use it only for functions that genuinely transform untrusted data into a trusted form (sanitizers, validators, cryptographic verifiers). The override is recorded in the signed KestEntry, making it auditable.

## TrustEvaluator Interface

The trust computation logic is injectable via the `TrustEvaluator` interface (Spec §7):

```python
from abc import ABC, abstractmethod

class TrustEvaluator(ABC):
    @abstractmethod
    def compute_trust(
        self,
        source_type: str,
        parent_trust: int | None,
        trust_override: int | None,
    ) -> int:
        """Compute the trust score for the current hop."""
```

### DefaultTrustEvaluator

The built-in `DefaultTrustEvaluator` implements the standard propagation rules:

```python
from kest.core import DefaultTrustEvaluator

evaluator = DefaultTrustEvaluator()

# Root node, no parent
evaluator.compute_trust("internal", None, None)  # → 80

# Child node with parent trust
evaluator.compute_trust("user_input", 80, None)  # → 40

# With trust override
evaluator.compute_trust("user_input", 80, 90)    # → 90
```

### Custom TrustEvaluator

For organization-specific trust models (e.g., trust scores that factor in time-of-day, geographic region, or threat intelligence feeds):

```python
class ThreatAwareTrustEvaluator(TrustEvaluator):
    def __init__(self, threat_intelligence_client):
        self._threat = threat_intelligence_client

    def compute_trust(self, source_type, parent_trust, trust_override):
        base = ORIGIN_TRUST_MAP.get(source_type, 0)
        if parent_trust is not None:
            base = min(parent_trust, base)
        if trust_override is not None:
            base = trust_override
        # Reduce trust during active incidents
        if self._threat.active_incident():
            base = max(0, base - 20)
        return base
```

## Taints: Tracking Risk Tags

While trust is a numeric score, **taints** are named labels that track *what kind of risk* a node introduces:

### Adding Taints

```python
@kest_verified(
    policy="kest/allow_trusted",
    source_type="user_input",
    added_taints=["user_input", "contains_pii"]
)
def receive_user_profile(profile: dict):
    return profile
```

### Removing Taints (Sanitization)

```python
@kest_verified(
    policy="kest/allow_trusted",
    source_type="internal",
    removed_taints=["contains_pii"],
    trust_override=80
)
def redact_pii(profile: dict) -> dict:
    """Remove PII and declare data safe."""
    return {k: v for k, v in profile.items() if k != "ssn"}
```

### Taint Propagation Formula

```
taints(current) = (taints(parent) ∪ added_taints) − removed_taints
```

Taints are **cumulative** and **inherited** — a downstream function sees all taints from its ancestors plus its own additions, minus any declared removals.

### Using Taints in Policies

```rego
package kest.require_sanitized

default allow = false

# Only allow if no dangerous taints remain
allow {
    not input.subject.taints[_] == "user_input"
    not input.subject.taints[_] == "contains_pii"
}
```

---

*For the normative specification of trust propagation, see [Spec §7](../blog/design/kest_spec_v0.3.0). For the complete decorator parameters, see [Decorators Reference](decorators).*
