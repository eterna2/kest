# Kest (Key + Trust): Attested AI Data Lineage

[![PyPI version](https://img.shields.io/pypi/v/kest.svg)](https://pypi.org/project/kest/)
[![Release](https://github.com/eterna2/kest/actions/workflows/release.yml/badge.svg)](https://github.com/eterna2/kest/actions/workflows/release.yml)

**Kest** is a high-integrity data lineage and security framework built specifically for secure multi-agent AI pipelines. It ensures that every piece of data carries a **Kest Passport**—a cryptographically verifiable record of its origin, the systems it traversed, its AI cognition context, and its accumulated risk profile (taints).

In v0.3.0, Kest adopts **OpenTelemetry Baggage**, **JSON Web Signatures (JWS)**, and **UUIDv7** to effortlessly scale from local test environments to distributed enterprise clusters.

## Core Features

- **Implicit Context Propagation**: Uses OpenTelemetry to abstract passport threading. Add `@kest_verified` and data magically retains its lineage across function calls and network boundaries.
- **Asynchronous AI Pipelines**: Native `async def` support enables mapping concurrent tools and fan-in/out DAGs smoothly without blocking event loops.
- **Cognition Lineage**: Go beyond standard provenance. Kest Passports track the exact `model_profile`, `system_prompt_hash`, and `confidence_score` used by an AI to generate the data.
- **Taint Tracking & Trust Math**: Data is automatically marked with infectious "taints". Trust Scores decay via explicit mathematical formulas to quarantine hallucinating agents.
- **Fail Open Audits (Exception Tainting)**: Exceptions raised inside AI endpoints are mathematically caught, appended with a `failed_execution` taint (and `0.0` trust), and re-raised natively. Nothing escapes the audit log.
- **OPA Policy Enforcement**: Native integration with Open Policy Agent (Rego) to gate access based on cryptographically-bound histories.

## Installation

```bash
uv add kest
```

### Optional Security Backends

- **Hardware KMS Pipelines (FIPS Compliant)**: Kest's abstract `KeyRegistry` supports routing signatures directly to AWS KMS or Vault.
- **Local Embedded OPA**: 
  ```bash
  uv add kest --extra opa
  ```
  *(Note: The embedded `lakera-regorus` dependency strictly supports Python 3.11. Kest automatically falls back to an external local API client if unsupported).*

## Quick Start (Async AI Pipelines)

### 1. Configure the Policy Engine & Rules
First, initialize an Open Policy Agent (OPA) engine. Kest natively evaluates pipeline bounds against your Rego rules to enforce compliance dynamically.

```python
from kest.config import config
from kest.core.policy import LocalOpaEngine

config.policy_engine = LocalOpaEngine()

policy = """
package kest.policy
default allow = false

# Block data that contains BOTH internet and internal DB taints
unsafe_mix {
    "internet_search" in input.taints
    "private_db" in input.taints
}

allow {
    not unsafe_mix
    input.trust_score >= 0.70  # Explicit trust boundary floor
}
"""
config.policy_engine.add_policy("access", policy)
```

### 2. Annotate AI Tools with Taints & Trust Decay
Use `@kest_verified` to wrap tools with cryptographic OTel context, infectious taints, and trust score math. 

By default, Trust Scores decay to the **minimum** of all parent histories, enforcing a strict "weakest link" quality floor.

```python
import asyncio
from kest.presentation.decorators import kest_verified

@kest_verified(added_taint=["internet_search"], node_trust_score=0.5)
async def web_search(query: str) -> dict:
    return {"result": f"Found info for {query}"}

@kest_verified(added_taint=["private_db"], node_trust_score=0.99)
async def query_internal_db(user_id: int) -> dict:
    return {"data": "Confidential Salary: $100k"}

# Bind the OPA rule to the egress boundary of the synthesis node
@kest_verified(
    enforce_rules=["data.kest.policy.allow"], 
    added_taint=["llm_synthesis"]
)
async def ai_synthesize_answer(public: dict, private: dict) -> str:
    # Notice the decorator extracts the underlying dictionaries securely!
    return f"Synthesis: {public.get('result')} | {private.get('data')}"
```

### 3. Trace Execution & Evaluate Denials
Kest mathematically merges DAGs across concurrent task limits.

```python
async def main():
    # Execute tools concurrently
    search_res, db_res = await asyncio.gather(
        web_search("Current CEO"),
        query_internal_db(42)
    )

    try:
        # This will securely raise a PermissionError!
        # 1. The taints unionize across fan-in, triggering the `unsafe_mix` OPA rule.
        # 2. The trust score degrades to 0.5 (min of 0.99 from DB and 0.5 from Web), 
        #    violating the 0.70 trust threshold rule!
        final_output = await ai_synthesize_answer(search_res, db_res)
    except PermissionError as e:
        print(f"Blocked Execution: {e}") 
        # Output: "Blocked Execution: Kest Policy Violation: Execution blocked by rule 'data.kest.policy.allow'"

if __name__ == "__main__":
    asyncio.run(main())
```

### 4. What does the Lineage Trace look like?
If we bypassed the OPA blocker to view the actual `KestPassport` history, you would see a cryptographically immutable DAG node securely anchoring the entire AI tool-use chain. 

```json
{
  "node_id": "ai_synthesize_answer",
  "node_type": "system",
  "parent_entry_ids": [
    "019313ac-1d2a-79b8-b83c-112233445566", // web_search UUIDv7
    "019313ac-1d2f-7ab1-c91f-aabbccddeeff"  // query_internal_db UUIDv7
  ],
  "accumulated_taint": [
    "internet_search",
    "private_db",
    "llm_synthesis"
  ],
  "trust_score": 0.5,
  "content_hash": "output_hash",
  "input_state_hash": "2fba...",
  "timestamp_ms": 1708453482121
}
```

## Documentation

Full documentation is available via MkDocs Material.

To view the architectural specifications and implementation guides:
```bash
uv run --with mkdocs-material mkdocs serve
```

## Contributing
We welcome contributions! Please see our `CONTRIBUTING.md` for details on our development process.
