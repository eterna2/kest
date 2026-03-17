# Kest: Attested Data Lineage

[![PyPI version](https://img.shields.io/pypi/v/kest.svg)](https://pypi.org/project/kest/)
[![Release](https://github.com/eterna2/kest/actions/workflows/release.yml/badge.svg)](https://github.com/eterna2/kest/actions/workflows/release.yml)
[![codecov](https://codecov.io/gh/eterna2/kest/branch/main/graph/badge.svg)](https://codecov.io/gh/eterna2/kest)

**Kest** is a high-integrity data lineage and security framework built for secure data pipelines and agentic workflows. It ensures that every piece of data carries a **Kest Passport**—a cryptographically verifiable record of its origin, the systems it traversed, and its accumulated risk profile (taints).

## Core Features

- **Data Lineage as a DAG**: Every execution step is recorded in a Directed Acyclic Graph (DAG) for non-repudiable audit trails.
- **Taint Tracking**: Data is automatically marked with "taints" as it flows through untrusted or sensitive processing nodes.
- **Trust Scores**: Numeric data quality indicators propagate alongside data, dynamically updating at processing boundaries via `trust_score_updater` lambdas.
- **OPA Policy Enforcement**: Native integration with Open Policy Agent (Rego) to enforce security constraints at runtime based on the data's entire history and current trust score.
- **Implicit Tracking**: Secure-by-default behavior. Any data crossing a `@verified` boundary is automatically tracked, even if it enters the system as a raw primitive.
- **Cryptographic Integrity**: Recursive DAG hashing ($H_{bind}$) ensures that any modification to historical data or node identities invalidates the final signature.

## Installation

### Using `pip`

```bash
pip install kest
```

To enable support for running OPA (Open Policy Agent) locally (via `lakera-regorus`):

> [!NOTE]
> The `kest[opa]` local evaluation extra currently only supports **Python 3.11** due to underlying upstream dependencies (`lakera-regorus`). For other Python versions, use the remote `opa-client` extra instead.

```bash
pip install kest[opa]
```

### Using `uv`

```bash
uv add kest
```

To enable support for running OPA (Open Policy Agent) locally (via `lakera-regorus`):

> [!NOTE]
> The `kest[opa]` local evaluation extra currently only supports **Python 3.11** due to underlying upstream dependencies (`lakera-regorus`). For other Python versions, use the remote `opa-client` extra instead.

```bash
uv add kest --extra opa
```

To enable support for running OPA against a remote server (via `opa-python-client`):

```bash
uv add kest --extra opa-client
```

## Quick Start

```python
from kest import verified, originate, config
from kest.core.policy import LocalOpaEngine

# 1. Setup a global policy engine
config.policy_engine = LocalOpaEngine()

policy = """
package kest.policy
default allow = false

# Specific rule: only allow input that came from System A
allow_system_a_only {
    input.taints[_] == "system_a"
}

# Generic rule: must not mix unstructured internet data with unstripped PII
allow_merge {
    not unsafe_mix
}

unsafe_mix {
    input.taints[_] == "pii_data"
    input.taints[_] == "internet_data"
    not input.taints[_] == "pii_stripped"
}
"""
config.policy_engine.add_policy("access", policy)

# 2. Annotate your domain functions
@verified(added_taint=["system_a"])
def process_on_system_a(data: dict):
    """Simulates processing on a specific approved system."""
    return {"system": "System A", "processed_data": data}

@verified(enforce_rules=["data.kest.policy.allow_system_a_only"])
def secure_restricted_process(data: dict):
    """A highly secure function that ONLY accepts data processed by System A."""
    return {"status": "highly_secure", "data": data}

@verified(added_taint=["internet_data"])
def fetch_internet_data(query: str):
    return {"source": "internet", "query": query}

@verified(added_taint=["pii_stripped"])
def strip_pii(data: dict):
    safe_data = data.copy()
    if "ssn" in safe_data:
        safe_data["ssn"] = "***-**-****"
    return safe_data

@verified(enforce_rules=["data.kest.policy.allow_merge"])
def merge_data(packet_a: dict, packet_b: dict):
    return {"merged": True, "a": packet_a, "b": packet_b}

# 3. Execute with tracking
# Input is a raw dict; Kest implicitly originates a Passport
raw_pii = originate({"user": "Alice", "ssn": "123-45-678"}, taint=["pii_data"])

# Securely process PII and internet data
safe_pii = strip_pii(raw_pii)
internet_data = fetch_internet_data("news")

# Lineage and taints are propagated dynamically across the DAG
result = merge_data(safe_pii, internet_data)

# Test System Origin Policy
system_a_data = process_on_system_a(internet_data)
restricted_result = secure_restricted_process(system_a_data)

print(result.data) 
# {'merged': True, ...}
print(result.passport.history) 
# Contains full DAG of 'originate' -> 'strip_pii', and 'fetch_internet_data' -> 'merge_data'
```

### 2. Manual Origination

For data entering from external or untrusted sources, use `originate` to define the genesis node:

```python
data = originate(
    {"raw": "payload"},
    taint=["untrusted_source"],
    labels={"env": "prod"},
    trust_score=0.4
)
```

### 3. Trust Scores & Validation

In addition to discrete taints, Kest models data quality dynamically using Trust Scores. A function can specify exactly how it modifies the running trust score of the DAG pipeline by assigning a lambda to `trust_score_updater`.

```python
# Upgrades the maximum trust score of all parents by 0.3
@verified(trust_score_updater=lambda scores: max(scores) + 0.3 if scores else 0.8)
def validate_and_clean(data: dict) -> dict:
    cleaned = data.copy()
    cleaned["validated"] = True
    return cleaned
```

By default (if no updater is provided), Kest inherently propagates the **minimum** trust score of all parents, guaranteeing that combining dirty data with clean data results in dirty data, unless explicitly washed and upgraded.

Policies can then easily block low-fidelity data:

```rego
allow {
    input.trust_score >= 0.70
}
```

## Documentation

For the full technical specification, see [Kest v0.1.0 Specification](docs/design/kest_spec_v0.1.0.md).
See the [Changelog](CHANGELOG.md) for a high-level overview of the initial release and version history.

## Contributing

We welcome contributions! Please see our [Contributor Guide](CONTRIBUTING.md) for details on our development process, coding standards, and architectural principles.
