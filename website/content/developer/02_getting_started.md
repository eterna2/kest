# Getting Started with Kest

This guide will walk you through securing a simple Python microservice using Kest.

## 1. Installation

Install the Kest core library along with the optional dependencies for your environment.

```bash
# Basic installation
pip install kest

# With SPIRE support
pip install kest[spiffe]

# With AWS support (IAM/KMS)
pip install kest[aws]

# With OPA/Cedar support
pip install kest[opa,cedar]
```

## 2. Configuration

Before Kest can evaluate policies or sign the cryptographic lineage, it requires access to an **Identity Provider** and a **Policy Engine**. In most applications, this is configured once during the startup phase.

```python
import os
from kest.core import configure, SPIREProvider, CedarLocalEngine

# 1. Initialize Workload Identity
# Kest auto-detects SPIRE, AWS, or Local environments if not provided.
identity = SPIREProvider()

# 2. Initialize Policy Engine
# Here we use an in-process Cedar engine for low-latency checks.
engine = CedarLocalEngine()

# 3. Apply Global Configuration
configure(engine=engine, identity=identity)
```

## 3. Securing Functions

Use the `@kest_verified` decorator to protect your critical business logic. Kest will automatically check policies and record the execution lineage.

```python
from kest.core import kest_verified

@kest_verified(policy="financial/transaction-limit")
async def transfer_funds(amount: float, recipient: str):
    # This code only executes if the policy allows it
    # and the caller has a valid, untampered lineage.
    print(f"Transferring ${amount} to {recipient}")
    return {"status": "success"}
```

## 4. Observability & Auditing

Kest exports the non-fungible audit trail as OpenTelemetry spans. Use the `KestTelemetry` helper to ship these logs to your preferred backend.

```python
from kest.core.telemetry import KestTelemetry

# Bootstrap OpenTelemetry with a local SQLite exporter for auditing
provider = KestTelemetry.setup(
    service_name="payment-service", 
    exporter_type="sqlite", 
    endpoint="audit_log.db"
)
```

## Next Steps

- Explore the **[Policy Library](../policies/overview.md)** for pre-built security models.
- Learn about **[Continuous Trust (CARTA)](../policies/trust.md)** and trust scores.
- Check the **[API Reference](../reference/api.md)** for detailed module documentation.
