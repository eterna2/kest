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

#### Basic Validators

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

#### Structured Validation Pipeline

For comprehensive validation with severity levels and aggregated results, use `ValidationPipeline`.
Unlike individual validators, the pipeline **does not short-circuit** — it runs all validators and
collects every violation before deciding to block.

Pass the pipeline directly in `output_validators` on `@kest_verified`:

```python
from kest.core import (
    kest_verified,
    ValidationPipeline,
    LengthBoundsValidator,
    JsonSchemaValidator,
    ContentClassificationValidator,
)

# Build the pipeline once — reuse it across multiple decorated functions.
pipeline = ValidationPipeline(
    validators=[
        LengthBoundsValidator(min_chars=10, max_chars=5000),
        JsonSchemaValidator(schema={
            "type": "object",
            "required": ["summary", "confidence"],
        }),
        ContentClassificationValidator(expected=["safe", "neutral"]),
    ],
)

@kest_verified(
    policy="summarize",
    output_validators=[pipeline],   # <-- pipeline IS an OutputValidator
)
def summarize(doc: str) -> dict:
    return {"summary": "...", "confidence": 0.9, "label": "safe"}
```

If any validator raises, `@kest_verified` adds an `output_validation_failed` taint to the audit
entry and re-raises `OutputValidationError` — the result is **never returned** to the caller.

You can also run the pipeline manually to inspect all violations before deciding what to do:

```python
result = pipeline.run(output)
if not result.passed:
    for v in result.violations:
        print(f"[{v.severity.name}] {v.validator_name}: {v.message}")
```

> **Note:** `JsonSchemaValidator` requires `pip install kest[schema]` (installs `jsonschema>=4.0.0`).

#### Semantic Drift Detection

For similarity-based guardrails, subclass `SemanticDriftDetector` and implement `detect()`. It
returns a drift score in `[0.0, 1.0]` (0 = identical, 1 = completely different). If the score
meets or exceeds `threshold`, `@kest_verified` blocks the output.

```python
from kest.core import kest_verified, SemanticDriftDetector

class EmbeddingDriftDetector(SemanticDriftDetector):
    def detect(self, reference, output) -> float:
        # Return 0.0 = no drift, 1.0 = maximum drift
        return 1 - cosine_similarity(embed(reference), embed(output))

# The detector itself is an OutputValidator — pass it directly.
@kest_verified(
    policy="refund-policy-qa",
    output_validators=[
        EmbeddingDriftDetector(
            reference="Expected response topic: product refund policy",
            threshold=0.3,
        ),
    ],
)
def answer_refund_question(question: str) -> str:
    ...
```

You can also combine a drift detector with a `ValidationPipeline` for defence-in-depth:

```python
from kest.core import ValidationPipeline, LengthBoundsValidator

@kest_verified(
    policy="refund-policy-qa",
    output_validators=[
        ValidationPipeline([
            LengthBoundsValidator(min_chars=20, max_chars=2000),
            EmbeddingDriftDetector(
                reference="Expected response topic: product refund policy",
                threshold=0.3,
            ),
        ])
    ],
)
def answer_refund_question(question: str) -> str:
    ...
```

#### Custom Validators

```python
from kest.core import OutputValidator, OutputValidationError

class NoBinaryValidator(OutputValidator):
    def validate(self, output) -> None:
        if "\x00" in str(output):
            raise OutputValidationError("Null byte detected in output")
```





### 5. Data Vault / Opaque Handle

In a zero-trust AI architecture, raw sensitive data should **never** reach the LLM context window.
The `HandleVault` pattern solves this by storing sensitive payloads in a secure in-memory vault and
giving the LLM only a non-sensitive `safe_view` string alongside an opaque handle ID. A trusted
gateway later resolves (unseals) the handle with ACL enforcement.

```python
from kest.core import HandleVault, OpaqueHandle

vault = HandleVault()

# 1. Seal: sensitive data never leaves the vault
handle = vault.seal(
    data="John Doe, SSN: 123-45-6789",
    owner_principal="spiffe://example.com/service-a",
    safe_view="A person record with name and SSN",  # <-- safe for LLM
    ttl_seconds=300,
)

# handle.id        -> "hdl_a1b2c3..."     (opaque pointer — safe to pass around)
# handle.safe_view -> "A person record..."  (non-sensitive — safe for LLM prompts)

# 2. LLM operates on safe_view, returns handle.id in its output

# 3. Gateway unseals with ACL check
raw = vault.unseal(handle.id, requesting_principal="spiffe://example.com/service-a")
# raw -> "John Doe, SSN: 123-45-6789"
```

**Grant additional principals:**
```python
handle = vault.seal(
    data={"secret": "value"},
    owner_principal="spiffe://example.com/service-a",
    safe_view="Classified payload",
    granted_principals=["spiffe://example.com/gateway"],
)
vault.unseal(handle.id, requesting_principal="spiffe://example.com/gateway")  # OK
```

**Error handling:**
```python
from kest.core import HandleNotFoundError, HandleExpiredError, HandleAccessDeniedError

try:
    raw = vault.unseal(handle_id, requesting_principal=caller)
except HandleExpiredError:
    ...  # TTL elapsed — data no longer accessible
except HandleAccessDeniedError:
    ...  # principal not in ACL
except HandleNotFoundError:
    ...  # handle was invalidated or never existed
```

**Early invalidation** (e.g., after a one-shot use):
```python
vault.invalidate(handle.id)
```

#### 5a. VaultCodec — Encryption & Compression at Rest

Attach a `VaultCodec` to apply **optional** encryption and/or compression before data is written to
the cache. Both stages are independently optional.

```python
import os
from kest.core import HandleVault, VaultCodec, AES256GCMEncryptor, ZlibCompressor

# Compress then encrypt (recommended for large payloads)
key = os.urandom(32)  # store securely — e.g. in KMS
vault = HandleVault(
    codec=VaultCodec(
        compressor=ZlibCompressor(),      # optional: reduce cache size
        encryptor=AES256GCMEncryptor(key), # optional: encrypt at rest
    )
)

handle = vault.seal(data={"ssn": "123-45-6789"}, owner_principal="svc", safe_view="PII")
data = vault.unseal(handle.id, requesting_principal="svc")
# data -> {"ssn": "123-45-6789"}
```

**Available compressors** (pipeline order: pickle → compress → encrypt):

| Class | Extra | Notes |
|---|---|---|
| `ZlibCompressor` | stdlib | Configurable level (0–9) |
| `GzipCompressor` | stdlib | Configurable level |
| `LZ4Compressor` | `kest[lz4]` | Fastest compression |
| `ZstdCompressor` | `kest[zstd]` | Best ratio |

**Available encryptors:**

| Class | Notes |
|---|---|
| `AES256GCMEncryptor(key)` | AES-256-GCM; authenticated; random nonce per call; `key = os.urandom(32)` |
| `FernetEncryptor(key)` | AES-128-CBC + HMAC; `key = FernetEncryptor.generate_key()` |

#### 5b. Pluggable Cache Backends

`HandleVault` accepts any `CacheProvider`. Five built-in backends are available:

```python
from kest.core import HandleVault
from kest.core import SQLiteCache, CachetoolsCache, RedisCache, ValkeyCache

# Persistent SQLite (stdlib — no extra dep)
vault = HandleVault(cache=SQLiteCache(db_path="/var/kest/vault.db"))

# LRU in-memory (pure Python)
vault = HandleVault(cache=CachetoolsCache(maxsize=1024))

# Redis-backed (also compatible with KeyDB)
vault = HandleVault(cache=RedisCache(host="localhost", port=6379))

# Valkey-backed
vault = HandleVault(cache=ValkeyCache(host="localhost", port=6379))
```

Install optional extras:

```bash
pip install kest[lmdb]       # LMDBCache — fastest embedded reads
pip install kest[cachetools]  # CachetoolsCache — pure-Python LRU/TTL
pip install kest[redis]       # RedisCache
pip install kest[valkey]      # ValkeyCache
pip install kest[lz4]         # LZ4Compressor
pip install kest[zstd]        # ZstdCompressor
```

#### 5c. Vault Service Transports

Run a vault as an embeddable micro-service and access it via the unified `VaultClient`:

**HTTP (REST/JSON)**:
```python
from kest.core.vault.server import VaultHTTPServer, VaultClient

srv = VaultHTTPServer(port=8421)
srv.start()

client = VaultClient.http("http://localhost:8421")
handle = client.seal(data={"ssn": "123"}, owner_principal="svc", safe_view="PII")
data   = client.unseal(handle["id"], requesting_principal="svc")
client.invalidate(handle["id"])
srv.stop()
```

**XML-RPC**:
```python
from kest.core.vault.server import VaultRPCServer, VaultClient

srv = VaultRPCServer(port=8422)
srv.start()
client = VaultClient.rpc("localhost", 8422)
```

**TCP Socket (JSON-RPC 2.0)**:
```python
from kest.core.vault.server import VaultSocketServer, VaultClient

srv = VaultSocketServer(address=("localhost", 8423))
srv.start()
client = VaultClient.socket(("localhost", 8423))

# Unix domain socket also supported (Linux/macOS)
srv = VaultSocketServer(address="/tmp/kest-vault.sock")
client = VaultClient.socket("/tmp/kest-vault.sock")
```

All three clients raise the same typed errors as the local vault:
`HandleNotFoundError`, `HandleExpiredError`, `HandleAccessDeniedError`.

#### 5d. Using `HandleVault` with `@kest_verified`

```python
from kest.core import kest_verified, HandleVault, VaultCodec, AES256GCMEncryptor
import os

key = os.urandom(32)
vault = HandleVault(codec=VaultCodec(encryptor=AES256GCMEncryptor(key)))

@kest_verified(action="read_pii", owner="data-service")
def fetch_user_record(user_id: str) -> str:
    record = {"name": "Alice", "ssn": "123-45-6789"}
    handle = vault.seal(
        data=record,
        owner_principal="spiffe://example.com/data-service",
        safe_view=f"User record for {user_id}",
    )
    # Return only the opaque pointer to the LLM
    return handle.id

# Later, a trusted gateway resolves the handle with ACL enforcement:
handle_id = fetch_user_record("u-42")
record = vault.unseal(handle_id, requesting_principal="spiffe://example.com/gateway")
```


#### 5e. FastAPI Integration (`kest[fastapi]`)

The `kest.core.integrations.fastapi` plugin wires `HandleVault` directly into a FastAPI
application with zero boilerplate.  Install the extras first:

```bash
pip install "kest[fastapi]"
```

**Drop-in router**

```python
from fastapi import FastAPI
from kest.core import HandleVault, VaultCodec, ZlibCompressor
from kest.core.integrations.fastapi import VaultRouter, JWTPrincipalExtractor

app = FastAPI()
vault = HandleVault(codec=VaultCodec(compressor=ZlibCompressor()))

router = VaultRouter(
    vault=vault,
    extractor=JWTPrincipalExtractor(secret="your-secret", algorithm="HS256"),
    gateway_principals=["spiffe://example.com/services/gateway"],
)
app.include_router(router, prefix="/vault")
# Routes added:
#   GET /vault/safe-view/{handle_id}  → public; returns safe_view text
#   GET /vault/resolve/{handle_id}    → gateway only; returns raw data
```

**Sealing data in a route handler**

```python
from kest.core.integrations.fastapi import vault_seal_response, HandleResponse
from fastapi import APIRouter

router2 = APIRouter()

@router2.post("/patients", response_model=HandleResponse)
async def create_patient(record: dict) -> HandleResponse:
    return vault_seal_response(
        vault=vault,
        data=record,
        safe_view=f"Patient record: {record['name']}",
        owner_principal="spiffe://example.com/data-service",
        granted_principals=["spiffe://example.com/services/gateway"],
    )
```

**Custom route with `VaultDependency`**

```python
from fastapi import Depends
from kest.core.integrations.fastapi import VaultDependency

get_unsealed = VaultDependency(vault=vault, extractor=jwt_extractor)

@app.get("/records/{handle_id}")
async def get_record(data=Depends(get_unsealed)):
    # `data` is the raw unsealed dict; access denied → 403, expired → 410, missing → 404
    return {"record": data}
```

**Custom extractor (mTLS SPIFFE SAN, sidecar header, …)**

```python
from kest.core.integrations.fastapi import PrincipalExtractor
from fastapi import HTTPException, Request

class SpiffeSanExtractor(PrincipalExtractor):
    async def extract(self, request: Request) -> str:
        san = request.headers.get("X-SPIFFE-ID")
        if not san:
            raise HTTPException(status_code=401, detail="Missing SPIFFE identity header")
        return san
```

### 6. Policy Validation
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
