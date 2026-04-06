# Securing Execution (Decorators)

The core of Kest's Zero Trust framework is applied through the `@kest_verified` decorator. This simple wrapper orchestrates complex identity verification, fine-grained policy checks, and cryptographic Merkle chain linkage.

## Basic Usage

The simplest form of protection requires only the name of the policy you wish to enforce.

```python
from kest.core import kest_verified

@kest_verified(policy="process_payment")
async def execute_payment(transaction_id: str, amount: float):
    return {"status": "success", "id": transaction_id}
```

### What Happens Automatically?
When this function is called, Kest:
1. Extracts the execution lineage from the incoming context (OTel Baggage).
2. Sends the lineage and workload identity to the local OPA/Cedar sidecar to evaluate the `process_payment` policy.
3. If the policy returns `True` (Allow), it executes the function.
4. Generates a new JSON Web Signature (JWS) linking the current execution to the previous hop's hash.
5. Updates the context lineage and exports an OpenTelemetry audit span.

## Multi-Policy Aggregation

You can enforce multiple policies simultaneously. Kest evaluates them using strict **Logical AND**; if a single policy denies access, the function is blocked.

```python
@kest_verified(policy=["require_auth", "check_rate_limit", "verify_lineage"])
def process_data(data):
    pass
```

## Overriding Global Configuration

While Kest is typically configured globally during app startup, you can override the Policy Engine or Identity Provider on a per-function basis.

```python
from kest.core import OPASidecarEngine, CedarSidecarEngine

# A dedicated Cedar engine for high-performance sub-second checks
fast_engine = CedarSidecarEngine(url="http://localhost:8180")

@kest_verified(policy="fast_rule", engine=fast_engine)
def high_throughput_task():
    pass
```

## Bootstrapping Trust (Root Nodes)

If a function is the *first* execution node in a chain (e.g., an API Gateway or initial job consumer), it establishes the foundational trust score.

Use the `source_type` parameter to automatically bootstrap trust based on predefined heuristics.

```python
@kest_verified(policy="api_entry", source_type="internet")
async def public_api_endpoint(request):
    # This execution chain will start with a trust score of 0.1
    pass

@kest_verified(policy="internal_entry", source_type="system")
def process_internal_queue(msg):
    # This execution chain will start with a trust score of 1.0
    pass
```
