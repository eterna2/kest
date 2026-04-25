# Kest Core (Python)

[![PyPI version](https://img.shields.io/pypi/v/kest.svg)](https://pypi.org/project/kest/)
[![License: PolyForm Shield 1.0.0](https://img.shields.io/badge/License-PolyForm%20Shield%201.0.0-blue.svg)](https://polyformproject.org/licenses/shield/1.0.0/)
![PyPI - Downloads](https://img.shields.io/pypi/dm/kest)

Kest is a high-fidelity Zero Trust framework for enforcing execution lineage across polyglot microservices and agentic workflows. It solves the **Secret Zero** problem by combining dynamically rotated identities (SPIFFE, OAuth), Policy-as-Code (OPA/Cedar), and Cryptographic Merkle DAGs.

This package provides the pure Python implementation of the core framework (`kest.core`), alongside OpenTelemetry Baggage integration and comprehensive Identity/Policy abstractions.

> **⚠️ Breaking Change Notice (v0.3.0)**: Kest v0.3.0 is a complete architectural rewrite. The core library has been decoupled into a pure Python namespace package (`kest.core`). Native Python implementations of RFC 8785 JSON canonicalization and Ed25519 signing eliminate former GIL lock contention bottlenecks and ensure cross-platform compatibility without compilation. All framework elements are decoupled per Single Responsibility Principles. See the [Changelog](CHANGELOG.md) for full details.

## Why Kest?

1. **Identity, Not Keys**: Services use short-lived, dynamically rotated identities (e.g., SPIRE X509-SVIDs or OAuth PKCE).
2. **Cryptographic Lineage**: Every execution hop is signed and linked to its parent's signature hash via RFC 8785 JSON Canonicalization, creating a tamper-evident Merkle DAG.
3. **Continuous Verification**: Pluggable Policy Engines evaluate the *entire* cryptographic lineage at every hop.
4. **CARTA Trust Scores**: Integer-based weakest-link trust evaluation degrades automatically upon downstream taint injection.

## Installation

Install via `uv` or `pip`. The core installation contains the framework, while explicitly needed execution environments are exposed as Python extras.

```bash
uv add kest
```

### Supported Extras
- **`rego`**: Installs `regopy`. Required to compile and run OPA Rego policies directly in-process via `RegoLocalEngine`.
- **`cedar`**: Installs `cedarpy`. Required to compile and run AWS Cedar policies directly in-process via `CedarLocalEngine`.
- **`aws`**: Installs `boto3`. Required to evaluate external constraints using the AWS Verified Permissions backend (`AVPPolicyEngine`).
- **`spiffe`**: Installs bindings required to extract workload identity natively through a SPIRE SVID socket (`SPIREProvider`).

Example of installing multiple extras:
```bash
uv add "kest[cedar,rego]"
```

## Quick Start

### 1. Configuration & Identity
Initialize Kest with your chosen identity provider and policy engine. `kest.core` supports standard providers like SPIRE, AWS STS, and a secure CLI-interactive OAuth Device Flow.

```python
from kest.core import configure, OAuthCliProvider, CedarLocalEngine

# Setup human-in-the-loop interactive identity using system keyring
identity = OAuthCliProvider(
    client_id="my-agent-client",
    issuer="https://auth.example.com",
    auto_open_browser=True,
)

# Setup embedded AST execution
engine = CedarLocalEngine(
    policies=[
        """
        permit(
            principal,
            action == Action::"invoke",
            resource
        );
        """
    ]
)

configure(engine=engine, identity=identity)
```

### 2. Securing Functions and Lineage Mutations
Use the `@kest_verified` decorator to automatically enforce policies and map logic into the Merkle execution trace. The decorator parameters control both contextual mutations and how policy engines apply to the hop.

```python
from kest.core import kest_verified

@kest_verified(
    policy="financial_access",     # Identifier for the policy engine to evaluate
    added_taints=["contains_phi"], # Append cumulative taint warnings to downstream luggage
    removed_taints=[],             # Erase explicit taints if you provide robust sanitization
    trust_override=None,           # Hardcode trust score back up to 100 on sanitizers
    operation_name="custom_op",    # Custom telemetry naming (defaults to function name)
    classification="system"        # 'system', 'user', or 'agent'
)
def process_sensitive_data(data: str):
    # This logic only executes if the Active Policy Engine verifies the incoming Passport
    # and all attached Taints / Trust Scores validate successfully.
    return {"status": "success", "result": data}
```

### 3. Writing Policy Definitions
Engines like Rego or Cedar evaluate the context state precisely. Kest maps its execution lineage directly into a deterministic `context` object, guaranteeing a uniform specification.

**Kest Engine Evaluation Context Schema:**
```json
{
  "subject": {
    "workload": "spiffe://...",         // Original workload origin ID
    "user": "alice",                     // Active user via Identity Interceptor
    "trust_score": 80,                   // Cumulative CARTA integer (0-100)
    "taints": ["contains_phi"]           // Active cumulated risk profiles
  },
  "object": {
    "id": "document:42",                 // Resource identifier (resource_id param)
    "attributes": { "dept": "finance" }  // Resource attributes (resource_attr param)
  },
  "environment": {
    "parent_hash": "e3b0c442...",        // Deterministic previous-hop JWS signature
    "policy_names": ["financial_access"] // Active policies triggered for current execution
  }
}
```

**Example (Cedar):**
When writing Cedar, map these structured payload nodes directly to your evaluation block:
```javascript
// cedar
permit(
    principal,
    action,
    resource
) when {
    context.subject.trust_score >= 80 &&
    !(context.subject.taints.contains("contains_phi"))
};
```

**Example (Rego):**
When writing Rego, the structured inputs are evaluated natively via global `input`:
```rego
package kest.allow

default allow = false

allow {
    input.subject.trust_score >= 80
    not has_taint("contains_phi")
}

has_taint(t) {
    t == input.subject.taints[_]
}
```

### 3. Resource Context (ABAC)

For Attribute-Based Access Control, pass `resource_id` and `resource_attr` to `@kest_verified`. Both accept a static value or a **resolver** — a callable that receives the decorated function's arguments at call time.

```python
from kest.core import kest_verified

# Static resource identity
@kest_verified(
    policy="document_read",
    resource_id="documents:42",
    resource_attr={"dept": "finance", "classification": "confidential"},
)
def read_document(doc_id: str) -> dict:
    ...

# Resolver: derive resource context dynamically from function arguments
@kest_verified(
    policy="document_read",
    resource_id=lambda doc_id, **kw: f"documents:{doc_id}",
    resource_attr=lambda doc_id, **kw: {"dept": "finance"},
)
def read_document_dynamic(doc_id: str) -> dict:
    ...
```

Resolved values are forwarded to the policy engine as `object.id` / `object.attributes` per SPEC §9.2 and serialized into `KestEntry.labels["kest.resource_attr"]` for tamper-evident audit.


### 4. Classification-Based Automatic Taint Tagging

Assign a **data classification** label to each `@kest_verified` function and let Kest automatically
apply the relevant taints — no more manual `added_taints` boilerplate.

```python
from kest.core import kest_verified

@kest_verified(policy="fetch_records", classification="data")
def fetch_user_records(user_id: str) -> list:
    ...
# KestEntry.taints automatically includes "contains_data"

@kest_verified(policy="review_output", classification="critic")
def review_agent_output(output: str) -> str:
    ...
# KestEntry.taints automatically includes "requires_review"
```

**Default classification → taint map:**
| Classification | Auto-taint |
|---|---|
| `"data"` | `"contains_data"` |
| `"critic"` | `"requires_review"` |
| `"sanitizer"` | `"sanitized"` |
| `"system"` *(default)* | *(none)* |

The map is fully configurable at startup and resets to defaults after `configure(clear=True)`:

```python
from kest.core import configure

configure(
    classification_taint_map={
        "data": ["pii_detected", "needs_encryption"],
        "agent": ["agent_output"],
    }
)
```

Auto-taints are **suppressed** if the same taint also appears in `removed_taints`.

### 5. Output Validators (Guardrails)

Protect against prompt injection artifacts and data leaks by validating function return values
before they reach the caller. If validation fails, the result is **not returned** and a
`"output_validation_failed"` taint is recorded in the audit chain.

```python
from kest.core import (
    kest_verified,
    MaxLengthValidator,
    RegexDenyListValidator,
)

@kest_verified(
    policy="summarize",
    output_validators=[
        MaxLengthValidator(max_chars=5000),
        RegexDenyListValidator(patterns=[
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"CONFIDENTIAL",
        ]),
    ],
)
def summarize_document(doc_id: str) -> str:
    ...
```

You can implement custom validators by subclassing `OutputValidator`:

```python
from kest.core import OutputValidator, OutputValidationError

class NoBinaryValidator(OutputValidator):
    def validate(self, output) -> None:
        if "\x00" in str(output):
            raise OutputValidationError("Null byte detected in output")
```

### 5. Policy Validation
To prevent faulty configurations, Kest provides static AST syntax validations that can proactively check LLM-generated or static policies before deploying them:

```python
from kest.core.policies.validators import CedarValidator, RegoValidator

cedar_validator = CedarValidator()
# Catch structural syntax failures immediately
cedar_validator.validate_syntax('permit(principal == User::"Alice", action, resource);')
```

### 4. Distributed Context Propagation
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
    async with httpx.AsyncClient(transport=KestHttpxInterceptor()) as client:
        return await client.post(url, json={})
```

## Audit & Verification
You can programmatically verify an entire collected Merkle lineage chain to ensure non-repudiation.

```python
from kest.core import Passport
from kest.core.trust import PassportVerifier

# 1. Reconstruct Passport from collected Baggage strings
passport = Passport.from_baggage(request_headers)

# 2. Verify all JWS Signatures & Topological Map Integrity
try:
    PassportVerifier.verify(passport, providers={})
    print("Execution lineage is cryptographically valid and untampered.")
except Exception as e:
    print(f"Verification failed: {e}")
```

## Lineage Visualization

Understanding the Merkle DAG of a distributed request can be complex. Kest includes a built-in visualization tool, `kest-viz`, to generate Mermaid.js diagrams from your audit logs.

```bash
# Output representation from a collected OpenTelemetry JSON trace export
moon run kest-core-python:viz -- kest_audit.json
```

## Testing & Integration Lab

For realistic local evaluation, especially involving cross-service credential leakage (SPIRE Workload Attestation) natively combined with a centralized sidecar verification proxy (OPA Engine), utilize the comprehensive Docker showcase: **[Kest Lab](../../showcase/kest-lab/README.md)**. 

The lab provisions a Keycloak server, Jaeger metric collection, OPA proxy sidecar, and isolated SPIRE architecture.

```bash
# Provision the Docker environments (Keycloak, Jaeger, OPA, SPIRE, etc) 
moon run kest-lab:up

# Run live integration scripts validating context transfers across independent containers
moon run kest-core-python:test-live
```

## Documentation
For full documentation, architecture deep dives, and compliance frameworks mapping, please visit the [Official Kest Documentation Site](https://eterna2.github.io/kest/).
