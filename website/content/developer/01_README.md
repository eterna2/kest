# Developer Guide

Welcome to the Kest Developer Guide. This section takes you from zero to a fully secured, policy-enforced, cryptographically audited microservice in Python.

## Learning Path

| Step | Article | What You'll Learn |
|---|---|---|
| 1 | [Getting Started](getting_started) | Installation, configuration, your first `@kest_verified` function |
| 2 | [Trust Model](trust_model) | CARTA trust scores, degradation, sanitizers, `ORIGIN_TRUST_MAP` |
| 3 | [Identity & Context](identity_context) | Identity providers, user/agent/task context, auto-detection |
| 4 | [Decorators Reference](decorators) | Every `@kest_verified` parameter, the 13-step lifecycle |
| 5 | [Distributed Propagation](middleware) | Middleware stack, `KestMiddleware`, `KestHttpxInterceptor`, Claim Check |
| 6 | [Testing & Kest Lab](testing) | `MockPolicyEngine`, unit tests, the kest-lab integration environment |
| 7 | [Telemetry & Visualization](visualization) | OTel setup, exporters, `kest-viz` CLI |
| 8 | [Kest Lab Deep Dive](kest_lab) | Docker Compose architecture, SPIRE, OPA, Cedar, Keycloak, 17 integration tests |

## Prerequisites

- **Python 3.11+** (the reference implementation)
- **pip** or **uv** for package management
- **Docker & Docker Compose** (for kest-lab integration tests)
- Basic familiarity with REST APIs and microservices

## Architecture at a Glance

```mermaid
graph TB
    subgraph "Your Application"
        A["@kest_verified decorator"]
        B["Business Logic"]
    end
    subgraph "Kest Core"
        C["IdentityProvider"]
        D["PolicyEngine"]
        E["Passport (Merkle DAG)"]
        F["TrustEvaluator"]
    end
    subgraph "Infrastructure"
        G["SPIRE Agent"]
        H["OPA / Cedar Sidecar"]
        I["OTel Collector"]
    end
    A --> C
    A --> D
    A --> E
    A --> F
    C --> G
    D --> H
    E --> I
    A --> B
```

## Quick Start

```python
from kest.core import configure, MockPolicyEngine, kest_verified

# 1. Configure (once at startup)
configure(engine=MockPolicyEngine(allow=True))

# 2. Protect your function
@kest_verified(policy="kest/allow_trusted", source_type="internal")
def process_data(payload: dict):
    return {"status": "processed", "items": len(payload)}

# 3. Call it normally
result = process_data({"key": "value"})
```

That's it. Kest handles identity, signing, policy evaluation, Merkle chain linkage, and OTel emission automatically.

---

*Ready to begin? Start with [Getting Started](getting_started).*
