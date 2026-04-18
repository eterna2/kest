# Kest Core (Python)

[![PyPI version](https://img.shields.io/pypi/v/kest.svg)](https://pypi.org/project/kest/)
[![License: PolyForm Shield 1.0.0](https://img.shields.io/badge/License-PolyForm%20Shield%201.0.0-blue.svg)](https://polyformproject.org/licenses/shield/1.0.0/)

Kest is a high-fidelity Zero Trust framework for enforcing execution lineage across polyglot microservices. It solves the **Secret Zero** problem by combining Workload Identity (SPIFFE), Policy-as-Code (OPA/Cedar), and Cryptographic Merkle DAGs.

This package provides the pure Python implementation of the core Kest framework, alongside Python decorators (`@kest_verified`), OpenTelemetry Baggage integration, and Policy/Identity provider abstractions.

> **⚠️ Breaking Change Notice (v0.3.0)**: Kest v0.3.0 is a complete architectural rewrite from v0.2.0. The core cryptographic engine has been ported to Rust (`kest-core-rs`), replacing the previous pure Python implementation. Identity is now strictly verified via SPIFFE/SPIRE, and policy evaluations have shifted from local embedded engines to scalable Sidecar patterns (OPA/Cedar). Please see the documentation for migration paths.

## Why Kest?

Traditional microservices rely on static API keys and perimeter security. If a key is compromised, attackers can move laterally. Kest changes this paradigm:
1. **Identity, Not Keys**: Services use short-lived, dynamically rotated X509-SVIDs provided by SPIRE.
2. **Cryptographic Lineage**: Every execution hop is signed and linked to its parent's signature hash via RFC 8785 JSON Canonicalization, creating a tamper-evident Merkle DAG.
3. **Continuous Verification**: Policy Engines (OPA/Cedar) evaluate the *entire* cryptographic lineage at every hop, enabling true Continuous Adaptive Risk and Trust Assessment (CARTA).
4. **Non-Fungible Audit**: Execution records are exported as OTel spans, forming an immutable audit trail.

## Installation

```bash
pip install kest opentelemetry-api opentelemetry-sdk httpx
```

## Quick Start

### 1. Configuration
Initialize Kest with your identity provider and policy engine (usually done once at application startup).

```python
from kest.core import configure
from kest.core import SPIREProvider
from kest.core import OPASidecarEngine

# Setup Identity (SPIRE)
identity = SPIREProvider(socket_path="/var/run/spire/agent/public/api.sock")

# Setup Policy (OPA Sidecar)
engine = OPASidecarEngine(url="http://localhost:8181")

configure(engine=engine, identity=identity)
```

### 2. Securing Functions
Use the `@kest_verified` decorator. Kest will automatically check the OPA policy, sign the execution lineage using your SPIFFE identity, and manage OpenTelemetry baggage before the function runs.

```python
from kest.core import kest_verified

@kest_verified(
    policy="financial_access",
    added_taints=["accessed_financial_data"]
)
def process_sensitive_data(data: str):
    # This logic only runs if 'financial_access' allows it based on the caller's lineage
    # It also taints the downward lineage, so downstream hops know financial data was accessed.
    return {"status": "success", "result": data}

@kest_verified(
    policy="sanitization_routine",
    trust_override=1.0,
    removed_taints=["accessed_financial_data"]
)
def sanitize_data(data: dict):
    # Explicitly overrides a low trust score and removes a taint after validation
    return "Sanitized: " + data["result"]
```

### 3. Distributed Context Propagation
To maintain the Merkle chain across network boundaries, use the provided transport middleware to automatically inject and extract OTel Baggage.

**FastAPI Middleware:**
```python
from fastapi import FastAPI
from kest.core import KestMiddleware

app = FastAPI()
app.add_middleware(KestMiddleware)
```

**HTTPX Interceptor:**
```python
import httpx
from kest.core import KestHttpxInterceptor

async def call_next_service(url: str):
    async with httpx.AsyncClient() as client:
        # Automatically injects kest.passport and kest.lineage_root into headers
        interceptor = KestHttpxInterceptor()
        request = client.build_request("GET", url)
        request = interceptor(request)
        return await client.send(request)
```

## Audit & Verification
You can programmatically verify an entire collected Merkle lineage chain to ensure non-repudiation.

```python
from kest.core import Passport
from kest.core.trust import PassportVerifier

# 1. Reconstruct Passport from audit logs (OTel spans)
passport = Passport(entries=[sig1, sig2, sig3])

# 2. Verify Merkle integrity and JWS Signatures
try:
    # Providers map SPIFFE IDs to public certs (or use the SPIRE trust bundle)
    PassportVerifier.verify(passport, providers={})
    print("Execution lineage is cryptographically valid and untampered.")
except Exception as e:
    print(f"Verification failed: {e}")
```

## Testing & Integration Lab
Kest manages an extensive suite of integration and end-to-end tests to guarantee structural integrity across policy scopes, asynchronous environments, and W3C OTel constraints.

To run the standalone unit tests:
```bash
moon run kest-core-python:test
```

For real-world architectural validation—including interactions across SPIFFE domains and independent OPA/Cedar execution engines—we utilize our integrated Docker Lab environment. For detailed instruction on simulating multi-hop asynchronous trace leakage tests and integration behaviors, read the [Kest Lab README](../../../showcase/kest-lab/README.md).

```bash
# Safely provisions the entire lab and executes live tests directly onto the internal workload container structure
moon run kest-core-python:test-live
```

## Lineage Visualization

Understanding the Merkle DAG of a distributed request can be complex. Kest includes a built-in visualization tool, `kest-viz`, to generate Mermaid.js diagrams from your audit logs.

### 1. Generate Audit Logs
Configure Kest to export telemetry to a local file or SQLite database:
```python
from kest.core.telemetry import KestTelemetry
KestTelemetry.setup("my-service", exporter_type="file", endpoint="kest_audit.json")
```

### 2. Visualize with Moon
Run the `viz` task to output a Mermaid.js graph string:
```bash
moon run kest-core-python:viz -- kest_audit.json
```

The output can be rendered in any Markdown viewer or the [Mermaid Live Editor](https://mermaid.live/).

## Performance

## Performance

Kest Python is designed to be highly efficient in capturing execution lineage. The pure Python inline framework imposes minimal overhead suitable for the vast majority of microservice transactions.

### Running Benchmarks
```bash
moon run kest-core-python:bench
```

## Documentation
For full documentation, architecture deep dives, and compliance frameworks mapping, please visit the [Official Kest Documentation Site](https://eterna2.github.io/kest/).
