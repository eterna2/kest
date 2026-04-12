# Kest: Zero Trust Execution Lineage

[![PyPI version](https://img.shields.io/pypi/v/kest.svg)](https://pypi.org/project/kest/)
[![Documentation](https://img.shields.io/badge/docs-stable-brightgreen)](https://eterna2.github.io/kest/)
[![CI](https://github.com/eterna2/kest/actions/workflows/ci.yml/badge.svg)](https://github.com/eterna2/kest/actions/workflows/ci.yml)
[![Coveralls](https://coveralls.io/repos/github/eterna2/kest/badge.svg?branch=main)](https://coveralls.io/github/eterna2/kest?branch=main)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eterna2/kest/badge)](https://scorecard.dev/viewer/?uri=github.com/eterna2/kest)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12453/badge)](https://www.bestpractices.dev/projects/12453)

> 📖 **[Full documentation → eterna2.github.io/kest](https://eterna2.github.io/kest/)**  
> 📐 **[Kest v0.3.0 Specification → spec/SPEC-v0.3.0.md](./spec/SPEC-v0.3.0.md)** · [Rendered on website →](https://eterna2.github.io/kest/)

**Kest** is a Zero Trust execution lineage framework for Python agentic workflows and data pipelines. Every function call decorated with `@kest_verified` produces a cryptographically signed audit entry that is chained into a tamper-evident **Merkle DAG Passport**. The Passport propagates automatically across distributed hops via OpenTelemetry baggage, giving you verifiable, non-repudiable lineage across any number of services.

> v0.3.0 is a complete rewrite. The signing and hashing primitives are implemented in Rust (via PyO3) for correctness and performance. A **security hardening patch** (2026-04-11) fixed cross-request identity collision in the policy cache, decoupled baggage reads from global lab state, and added a JWT verification guard to `KestIdentityMiddleware`. See the [Changelog](CHANGELOG.md) for the full list of changes.

---

## Key Features

| Capability | Description |
|---|---|
| **Merkle DAG Lineage** | Every execution step is hashed and chained. Tampering with any node invalidates the entire chain. |
| **CARTA Trust Scores** | Numeric trust (0–100) propagates through the DAG. One untrusted node degrades all downstream scores. |
| **Taint Propagation** | Risk labels (`added_taints` / `removed_taints`) accumulate across the chain. |
| **Policy Enforcement** | Pluggable engines: OPA, Cedar, AWS AVP, or in-process Rego / Cedar — all before the function runs. |
| **Multi-hop OBO** | `KestMiddleware` + `KestHttpxInterceptor` thread the Passport through HTTP service boundaries automatically. |
| **Three-Tier Baggage** | Inline → Compressed Inline (`kest.passport_z`) → Claim Check. Handles chains from 1 to 50+ hops without header bloat. |
| **Identity Flexibility** | SPIRE/SPIFFE, AWS STS, Bedrock Agents, OIDC JWTs, or a local Ed25519 ephemeral key. |
| **Rust Core** | RFC 8785 canonicalization + ED25519 signing via PyO3. Use `KEST_BACKEND=python` for multithreaded production (GIL cliff — see [#11](https://github.com/eterna2/kest/issues/11)). |

---

## Installation

```bash
# Core (remote OPA / Cedar servers)
uv add kest
pip install kest

# In-process Rego evaluation (regopy)
uv add "kest[rego]"

# In-process Cedar evaluation (cedarpy)
uv add "kest[cedar]"

# AWS Verified Permissions
uv add "kest[aws]"

# SPIRE/SPIFFE identity
uv add "kest[spiffe]"
```

---

## Quick Start

```python
from kest.core import (
    configure,
    kest_verified,
    CedarLocalEngine,
    LocalEd25519Provider,
)

# 1. One-time global configuration
configure(
    identity=LocalEd25519Provider(),   # auto-generates an ephemeral Ed25519 key
    engine=CedarLocalEngine(
        policies=[
            """
            permit(
                principal,
                action == Action::"invoke",
                resource
            );
            """
        ]
    ),
)

# 2. Decorate your functions
@kest_verified(policy="invoke")
def ingest_data(payload: dict) -> dict:
    return {"ingested": payload}

@kest_verified(policy="invoke", added_taints=["unverified"])
def fetch_external(url: str) -> dict:
    return {"source": url, "data": "..."}

@kest_verified(policy="invoke", removed_taints=["unverified"])
def validate(data: dict) -> dict:
    return {**data, "validated": True}

# 3. Call them — lineage is automatic
raw = ingest_data({"user": "alice", "amount": 100})
external = fetch_external("https://api.example.com/prices")
result = validate(external)

# The result carries a full Passport: a list of JWS-signed KestEntry records
# that form a cryptographically verifiable Merkle DAG.
```

### Using Rego In-Process

```python
from kest.core import configure, kest_verified, RegoLocalEngine, LocalEd25519Provider

POLICY = """
package kest.allow

import future.keywords

default allow := false

allow if {
    input.trust_score >= 70       # integer, 0-100
    input.is_root == false
}
"""

configure(
    identity=LocalEd25519Provider(),
    engine=RegoLocalEngine(policies={"kest/allow": POLICY}),
)

@kest_verified(policy="kest/allow")
def process(data: dict) -> dict:
    return data
```

### Trust Scores & Taint Propagation

Trust scores are **integers (0–100)**, not floats. The `DefaultTrustEvaluator` uses a weakest-link model: `score = (min(parent_scores) * self_score) // 100`.

```python
# Quality gate: block any pipeline where trust has degraded below 80
REGO_POLICY = """
package kest.quality

import future.keywords

default allow := false

allow if {
    input.trust_score >= 80     # integer threshold
}
"""

# Sanitizer: removes a taint and resets trust to 100
@kest_verified(
    policy="sanitizer_policy",
    trust_override=100,
    removed_taints=["unverified_input"],
)
async def input_scanner(data: dict) -> dict:
    # After this hop, trust_score=100 and "unverified_input" is gone from taints
    return {**data, "scanned": True}
```

### Multi-hop Propagation (FastAPI)

```python
from fastapi import FastAPI
from kest.core import KestMiddleware, KestHttpxInterceptor, configure, kest_verified

app = FastAPI()
app.add_middleware(KestMiddleware)   # extracts incoming Kest baggage

client = httpx.AsyncClient(transport=KestHttpxInterceptor())  # injects outgoing Kest baggage

@app.post("/process")
@kest_verified(policy="invoke")
async def process(body: dict):
    # The Passport from the caller is automatically extended here.
    result = await client.post("http://next-service/step", json=body)
    return result.json()
```

---

## Policy Engines

### Remote Servers

```python
from kest.core import OPAPolicyEngine, CedarPolicyEngine

# OPA (Open Policy Agent)
engine = OPAPolicyEngine(url="http://opa:8181")

# Remote Cedar service
engine = CedarPolicyEngine(url="http://cedar:8080")
```

### In-Process (no network)

```python
from kest.core import CedarLocalEngine, RegoLocalEngine

# Cedar (cedarpy) — requires: uv add "kest[cedar]"
engine = CedarLocalEngine(policies=["permit(principal, action, resource);"])

# Rego (regopy) — requires: uv add "kest[rego]"
engine = RegoLocalEngine(policies={"pkg/name": "package pkg.name\ndefault allow = true"})
```

### AWS Verified Permissions

```python
from kest.core import AVPPolicyEngine

engine = AVPPolicyEngine(policy_store_id="ps-abc123", region="us-east-1")
```

---

## Identity Providers

```python
from kest.core import (
    LocalEd25519Provider,   # ephemeral key (dev/test)
    StaticIdentity,          # explicit workload ID + key
    SPIREProvider,           # SPIRE SVID via Unix socket
    AWSWorkloadIdentity,     # AWS STS GetCallerIdentity
    BedrockAgentIdentity,    # AWS Bedrock Agent context
    OIDCIdentity,            # Generic OIDC JWT
)

# Auto-detect: SPIRE → AWS → local ephemeral key
from kest.core import get_default_identity
identity = get_default_identity()
```

---

## Bundled Access-Control Policies

`kest.core.policies` ships ready-to-load Cedar and Rego files for classical formal models:

| Model | Description |
|---|---|
| Bell-LaPadula | Mandatory read/write confidentiality (MLS) |
| Biba | Integrity confinement (no read-down, no write-up) |
| Brewer-Nash | Chinese Wall / conflict-of-interest separation |
| Clark-Wilson | Integrity guards with constrained data items |
| Goguen-Meseguer | Non-interference |
| Financial | Transaction-limit and approval-tier enforcement |
| Security | Clearance-level access control |

```python
from importlib.resources import files

# Load a bundled policy
policy_text = files("kest.core.policies").joinpath("bell_lapadula.rego").read_text()
engine = RegoLocalEngine(policies={"kest/blp": policy_text})
```

---

## Monorepo Structure

```
kest/
├── libs/
│   ├── kest-core/
│   │   ├── python/      # Python library (kest package)
│   │   └── rust/        # Rust core: canonicalization, signing, trust
├── showcase/
│   └── kest-lab/        # Docker Compose integration lab (SPIRE, OPA, Keycloak, Jaeger)
└── website/             # Documentation site (Next.js)
```

---

## The V2 Pipeline (`kest-runtime-rs`)

The new V2 execution environment (`KEST_BACKEND=rust`, default natively when built via `uv`/`maturin`) completely bypasses the Python Global Interpreter Lock (GIL) Contention Cliff observed in earlier versions. It delegates all policy evaluation, cryptographic signing, CARTA trust evaluations, OTel baggage extraction, and data constraints into highly-concurrent native Rust components. 

By default, your `@kest_verified` functions will seamlessly route traces down this `v2` pipeline layer.

### Extended Guide for the V2 Decorator

```python
from kest.core import kest_verified

# Implement optional dynamic trust capabilities via objects
class CustomEvaluator:
    def calculate(self, origin_score: int, parent_scores: list) -> int:
         return min(parent_scores + [origin_score]) - 5

# The V2 pipeline is integrated seamlessly.
@kest_verified(
    policy=["enterprise_baseline", "app_specific_route"],
    origin="verified_partner",        # Translates natively to score hooks
    trust_evaluator=CustomEvaluator() # Hook evaluates back across FFI transparently
)
def handle_partner_ingest(payload):
    return payload
```

**Key Differences & Improvements of V2:**
- **Concurrency Scaling:** Heavy I/O processing (calling `CedarPolicyEngine`, hashing massive `parent_ids`, building recursive DAG structures) operates outside the generic constraints of Python interpreter locking boundaries, scaling multi-threaded frameworks up to ~3,100+ requests per second natively.
- **Dynamic Spec-Aware Typing:** Even though Kest V2 universally handles OpenTelemetry Baggage metadata as strict String interfaces (`BTreeMap<String, String>`), policy evaluations specifically enforce primitive type conversions behind the scenes. Using `input.trust_score >= 80` inside Rego correctly receives dynamic Integers cleanly due to native adapter evaluation intercepts mapped in the `rust-v2` architecture.
- **Inversion of Control Hooks:** Foreign class objects (like any standard Python variable passed to evaluate `trust_override` or `trust_evaluator`) are evaluated sequentially without memory leaks. Rust manages execution contexts and only re-acquires the GIL efficiently exactly when dipping into Python evaluation methods.

Set `export KEST_BACKEND=python` locally if operating strictly single-thread or performing deep debugging of the internal validation pipeline steps. `KEST_BACKEND=rust` is the operational standard for live concurrent workflows.

---

## Production Notes

Policy decisions are cached for 5 seconds by default (TTL configurable):

```bash
# Reduce TTL for high-sensitivity services
export KEST_POLICY_CACHE_TTL=1.0

# Disable caching entirely (e.g., revocation-critical paths)
export KEST_POLICY_CACHE_TTL=0
```

For immediate revocation, call `invalidate_policy_cache()` from your application:

```python
from kest.core import invalidate_policy_cache
invalidate_policy_cache()   # flushes all cached decisions
```

### JWT Verification (`KestIdentityMiddleware`)

`KestIdentityMiddleware` requires a `jwks_uri` to verify JWT signatures. Without it, the middleware raises `RuntimeError` at startup (on the first request). To allow unsigned JWTs in development:

```bash
export KEST_INSECURE_NO_VERIFY=true   # dev/test only — never in production
```

### Baggage Key Names

As of v0.3.0 security hardening, baggage keys are aligned with the spec:

| Baggage Key | Description |
|---|---|
| `kest.passport` | Inline Passport (JWS chain, ≤ 4 KB) |
| `kest.passport_z` | Compressed inline Passport (zlib+base64url, ≤ 4 KB compressed) |
| `kest.claim_check` | Claim Check UUID (when Passport exceeds both thresholds) |
| `kest.chain_tip` | SHA-256 of the last entry (for quick chain validation) |
| `kest.user` | User subject from JWT `sub` claim |
| `kest.agent` | Agent/service identity from JWT `client_id` claim |
| `kest.task` | Task scope from JWT `scope` claim |

> ⚠️ Old containers (pre-hardening) write `kest.principal_user` / `kest.workload_agent`. Rebuild all services together when upgrading.


The most complete flow Kest supports is a **human → agent → gateway → task** delegation chain:

```
Alice → kest-agent (OBO exchange) → kest-gateway /authorise (scope check)
      → task token (scope: task:process-data only)
      → kest-gateway /execute-task → hop1 → hop2 → hop3
```

Every hop produces a signed `KestEntry`. At the end, you have **6 cryptographically linked audit entries** in a Merkle DAG, covering:

| # | Service | Trust Score | Policy |
|---|---|---|---|
| 1 | kest-agent (OBO delegation) | 10 (internet) | `delegation_policy` |
| 2 | kest-gateway /authorise | 100 (internal) | `gateway_policy` |
| 3 | kest-gateway /execute-task | 100 | `task_policy` |
| 4–6 | hop1, hop2, hop3 | 100 | `workload_user_policy` |

See the full step-by-step walkthrough — with actual token payloads, policy context dicts, and decoded audit entries at every hop — in the **[Gateway E2E documentation](https://eterna2.github.io/kest/stable/examples/gateway_e2e)**.

---

## Running the Lab

```bash
# Start the full integration environment
moon run kest-lab:up

# Run live integration tests (inside the lab containers)
moon run kest-lab:test-live

# Stop the lab
moon run kest-lab:down
```

---

## Documentation

Full reference documentation is available on the project website:

- [🚀 **Stable Documentation**](https://eterna2.github.io/kest/stable/)
- [📦 **v0.3.0 Reference**](https://eterna2.github.io/kest/v0.3.0/)

See the [Changelog](CHANGELOG.md) for the complete version history.

---

## Contributing

Please read the [AGENTS.md](AGENTS.md) for the mandatory toolchain, testing, and architectural rules that govern this repository. All contributions must pass `moon run kest-core-python:test` (unit) and `moon run kest-core-python:test-live` (live integration) before merging.
