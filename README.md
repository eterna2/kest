# Kest: Zero Trust Execution Lineage & AI Agent Security

[![PyPI version](https://img.shields.io/pypi/v/kest.svg)](https://pypi.org/project/kest/)
[![Documentation](https://img.shields.io/badge/docs-stable-brightgreen)](https://eterna2.github.io/kest/)
[![CI](https://github.com/eterna2/kest/actions/workflows/ci.yml/badge.svg)](https://github.com/eterna2/kest/actions/workflows/ci.yml)
[![Coveralls](https://coveralls.io/repos/github/eterna2/kest/badge.svg?branch=main)](https://coveralls.io/github/eterna2/kest?branch=main)
![PyPI - Downloads](https://img.shields.io/pypi/dm/kest)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eterna2/kest/badge)](https://scorecard.dev/viewer/?uri=github.com/eterna2/kest)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12453/badge)](https://www.bestpractices.dev/projects/12453)
[![License: PolyForm Shield 1.0.0](https://img.shields.io/badge/License-PolyForm%20Shield%201.0.0-blue.svg)](https://polyformproject.org/licenses/shield/1.0.0/)

> 📖 **[Full documentation → eterna2.github.io/kest](https://eterna2.github.io/kest/)**  
> 📐 **[Kest v0.3.0 Specification → spec/SPEC-v0.3.0.md](./spec/SPEC-v0.3.0.md)**

**Kest** is a unified Zero Trust execution lineage framework designed for secure Python agentic workflows, multi-agent collaborations, and distributed data pipelines.

Every interaction decorated with `@kest_verified` produces a cryptographically signed audit entry chained into a tamper-evident **Merkle DAG Passport**. Passports propagate automatically across distributed hops, ensuring verifiable, non-repudiable lineage across autonomous AI subagents, cloud infrastructure, and classical microservices.

---

## 🚀 Features at a Glance

### 🛡️ Kest Core (`libs/kest-core/python`)
> **📘 Deep Dive**: For comprehensive setup options, distributed OpenTelemetry Baggage propagation, and architectural internals, please see the [Kest Core README](libs/kest-core/python/README.md).

- **Merkle DAG Lineage**: Lineage chains with RFC 8785 strict canonicalization and Ed25519 signing mapped into OpenTelemetry baggage.
- **CARTA Trust Scores**: Weakest-link integer trust propagation (0–100) combining structural and identity-based origin validation.
- **Taint Boundaries**: Dynamic runtime tracking of accumulating risk profiles and constraints (e.g., `added_taints`, `removed_taints`).
- **Pluggable Identity**: OIDC, SPIRE/SPIFFE workload identity, AWS STS/Bedrock contexts, localized Ephemeral Ed25519, and human-in-the-loop Device Flow via `OAuthCliProvider` (with secure platform `keyring`).
- **Multi-Language Policy**: In-process runtime parity via `RegoLocalEngine` & `CedarLocalEngine`, alongside proactive AST syntax validations.

---

## Installation

Install via `uv` or `pip`. `kest` acts as the base framework and is explicitly extensible through optional dependencies (extras).

```bash
uv add kest
```

### Available Extras
- `rego`: Installs `regopy` for validating capabilities utilizing the `RegoLocalEngine`.
- `cedar`: Installs `cedarpy` to natively compile and evaluate policies via the `CedarLocalEngine`.
- `aws`: Installs `boto3` to evaluate external constraints via AWS Verified Permissions (`AVPPolicyEngine`).
- `spiffe`: Installs standard bindings for native Workload Identity via the `SPIREProvider`.

Example utilizing multiple extras:
```bash
uv add "kest[cedar,rego]"
```

---

## 🛠️ How Kest Works

### 1. Identify the Workload
The toolkit provides immediate integration paths to classical and AI-based environments, allowing seamless transitions from local development to cloud-native production.

```python
from kest.core import (
    SPIREProvider,           # SPIRE SVID via Unix socket (Kubernetes/Docker)
    OAuthCliProvider,        # Authorization Code + PKCE (CLI/human auth)
    AWSWorkloadIdentity,     # AWS STS GetCallerIdentity extraction
    BedrockAgentIdentity,    # AWS Bedrock Agent runtime context
    LocalEd25519Provider,    # Ephemeral keypair for dev/test
)

# Seamless SPIFFE Workload Validation
identity = SPIREProvider(socket_path="/var/run/spire/agent/public/api.sock")

# Or auto-detect based on environmental factors (SPIRE → AWS STS → Local Generate)
from kest.core import get_default_identity
auto_identity = get_default_identity()
```

### 2. Configure the Policy Engine
Engines are decoupled to provide ideal deployment architectures depending on your security posture, whether that is high performance in-process validation or centralized remote network validation.

```python
from kest.core import (
    RegoLocalEngine,      # High-speed in-process Rust Rego evaluation
    CedarLocalEngine,     # High-speed in-process Rust Cedar evaluation
    OPAPolicyEngine,      # Remote Open Policy Agent server
    AVPPolicyEngine,      # AWS Verified Permissions standard inference
)

# Initialize local or remote engine
engine = RegoLocalEngine(policies={"kest/allow": "package kest.allow\ndefault allow = true"})

# Apply global configuration
from kest.core import configure
configure(identity=identity, engine=engine)
```

> **Note**: Catch syntax problems before they are evaluated directly inside LLM multi-agent prompts using bundled AST validators like `CedarValidator` and `RegoValidator`.

### 3. Secure the Operation
Wrap operations with `@kest_verified` to automatically execute policy constraints, track context mutations, and digitally sign the subsequent lineage into the OpenTelemetry baggage.

```python
from kest.core import kest_verified

@kest_verified(policy="financial_read_access", added_taints=["contains_phi"])
def execute_sensitive_operation(payload: dict) -> dict:
    """
    Kest transparently evaluates incoming baggage against the active policy engine, 
    and digitally signs the successful execution into the Merkle DAG lineage chain.
    """
    return {"status": "success", "processed_by": "kest-worker"}
```

When evaluating a policy, Kest structures the deterministic execution lineage into a dictionary mapped specifically for your requested execution language (e.g., Rego or Cedar). The passed evaluation context looks like this:

```json
{
  "subject": {
    "workload": "spiffe://example.org/worker-node",
    "user": "alice",
    "agent": null,
    "task": "billing_admin",
    "trust_score": 80,
    "taints": ["contains_phi"]
  },
  "object": {
    "id": "resource_123",
    "attributes": {}
  },
  "environment": {
    "is_root": false,
    "source_type": "internal",
    "parent_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "policy_names": ["financial_read_access"],
    "policy_tier": "function",
    "active_deviations": []
  },
  "identity": "spiffe://example.org/worker-node",
  "trust_score": 80
}
```

### 4. The Cryptographic OTel Passport
Every interaction decorated with `@kest_verified` injects a non-repudiable audit entry natively into the OpenTelemetry baggage trace. The Passport is tracked as a JSON array of JWS compact strings (`header.payload.signature`). Before being signed with Ed25519, the canonicalized payload of each entry is formatted according to RFC 8785:

```json
{
  "schema_version": "0.3.0",
  "runtime": { "name": "kest-python", "version": "0.3.0" },
  "entry_id": "018f2d5e-85a2-73b9-a461-8f55b9e0f3b2",
  "operation": "execute_sensitive_operation",
  "classification": "system",
  "trust_score": 80,
  "parent_ids": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
  "added_taints": ["contains_phi"],
  "removed_taints": [],
  "taints": ["contains_phi"],
  "labels": {
    "principal": "spiffe://example.org/worker-node",
    "trace_id": "5b8aa5a2d2c88dced14032d84784be62"
  },
  "policy_context": {
    "enterprise_policies": [],
    "platform_policies": ["check_trust_score"],
    "function_policies": ["financial_read_access"],
    "deviations": []
  },
  "timestamp_ms": 1714574972124
}
```

---

## Monorepo Layout

```text
kest/
├── libs/                           
│   ├── kest-core/                  # Core Python Framework (`kest.core`)

├── showcase/                       
│   ├── kest-lab/                   # Complete Docker Compose integration stack (OPA, Keycloak, SPIRE)
├── website/                        # Next.js Official Documentation Site
```

---

## Running the Showcase Integration Lab

For real-world architectural validation—including interactions across SPIFFE domains and independent policy execution engines—we utilize our integrated Docker Lab environment. The `kest-lab` spins up a complete zero-trust testing stack featuring a SPIRE server for workload identity attestation, an Open Policy Agent (OPA) sidecar, Keycloak for OIDC JWT generation, and a Jaeger instance for OpenTelemetry collection. This sandbox natively replicates and validates multi-hop asynchronous trace leakage and production proxy configurations.

For detailed instructions on interacting with the instances and extending the sandbox, please see the [Kest Lab README](showcase/kest-lab/README.md).

```bash
# Provision the Docker environments (Keycloak, Jaeger, OPA, SPIRE, & hop microservices) 
moon run kest-lab:up

# Run live integration scripts safely verifying lineage injection flows
moon run kest-core-python:test-live

# Tear down the lab
moon run kest-lab:down
```

---

## Documentation

Full reference documentation is available on the project website:

- [🚀 **Stable Documentation**](https://eterna2.github.io/kest/stable/)
- [📦 **v0.3.0 Reference**](https://eterna2.github.io/kest/v0.3.0/)

See the [Root Changelog](CHANGELOG.md) to navigate version histories across all monorepo modules.

---

## Contributing

Please read the [AGENTS.md](AGENTS.md) for the mandatory toolchain, testing, and architectural rules that govern this repository. All contributions must pass `moon run kest-core-python:test` (unit) and `moon run kest-core-python:test-live` (live integration) before merging.
