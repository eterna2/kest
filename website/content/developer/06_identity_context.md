---
title: Identity & Resource Context
description: Configure identity providers and pass user, agent, task, and resource attributes for fine-grained ABAC policy enforcement.
---

# Identity & Resource Context

Kest's `@kest_verified` decorator records **who** is executing (identity), **on behalf of whom** (user/agent/task), and **on what** (resource) — all as signed, auditable fields in the KestEntry.

## Identity Providers

Every identity provider implements the same interface (Spec §5.1):

```python
class IdentityProvider(ABC):
    @abstractmethod
    def get_workload_id(self) -> str:
        """Return the unique workload identifier."""

    @abstractmethod
    def sign(self, payload: bytes) -> str:
        """Sign payload → JWS compact serialization."""

    @property
    def public_key(self) -> str | None:
        """PEM-encoded public key for verification (optional)."""
        return None
```

### SPIREProvider

Production-grade provider using the SPIFFE Workload API:

```python
from kest.core import SPIREProvider

identity = SPIREProvider(
    socket_path="/run/spire/sockets/agent.sock"
)

# Returns: "spiffe://kest.internal/workload/payment-svc"
identity.get_workload_id()
```

The provider communicates with the SPIRE Agent via Unix domain socket. SVIDs are automatically rotated on expiry.

### AWSWorkloadIdentity

For ECS, EKS, and Lambda workloads on AWS:

```python
from kest.core import AWSWorkloadIdentity

identity = AWSWorkloadIdentity(
    kms_key_id="arn:aws:kms:us-east-1:123456789:key/mrk-abcd1234"
)

# Returns: "arn:aws:sts::123456789:assumed-role/my-role/session"
identity.get_workload_id()
```

Uses AWS STS for workload ID and KMS for signing — no static credentials needed.

### BedrockAgentIdentity

For Amazon Bedrock AgentCore:

```python
from kest.core import BedrockAgentIdentity

identity = BedrockAgentIdentity(
    agent_id="AGENT123",
    kms_key_id="arn:aws:kms:..."
)
```

### OIDCIdentity

For CI/CD pipelines and federated identity:

```python
from kest.core import OIDCIdentity

identity = OIDCIdentity(
    token_path="/var/run/secrets/oidc-token",
    issuer="https://token.actions.githubusercontent.com"
)
```

Works with **GitHub Actions**, **GitLab CI**, **Google Cloud Workload Identity Federation**, and any OIDC-compliant provider.

### LocalEd25519Provider

For local development — generates an ephemeral Ed25519 key pair in-process:

```python
from kest.core import LocalEd25519Provider

identity = LocalEd25519Provider()
# ⚠️ Prints a warning: "Using ephemeral Ed25519 key — not for production"
```

### MockIdentityProvider

For deterministic unit tests:

```python
from kest.core import MockIdentityProvider

identity = MockIdentityProvider(workload_id="test-service")
# Uses HMAC-SHA256 with a fixed key for reproducible signatures
```

### Auto-Detection

If you don't specify an identity provider, `configure()` probes the environment (Spec §5.9):

```python
from kest.core import configure, get_default_identity

configure(engine=my_engine)  # identity auto-detected

# Or inspect what was detected:
identity = get_default_identity()
print(type(identity))  # → <class 'kest.core.providers.local.LocalEd25519Provider'>
```

**Probe order**: `SPIFFE_ENDPOINT_SOCKET` → `AWS_BEDROCK_AGENT_ID` → `AWS_ROLE_ARN` → `KEST_OIDC_TOKEN_PATH` → `LocalEd25519Provider` (fallback with warning)

## Identity Context (ABAC Attributes)

Beyond workload identity, Kest supports passing **who initiated the action** (user/agent/task) and **what resource is being accessed**:

### User, Agent, Task

```python
@kest_verified(
    policy="kest/allow_trusted",
    user=lambda: get_current_user(),     # → {"sub": "alice", "role": "admin"}
    agent=lambda: "checkout-web-app",
    task=lambda: "process-order-123",
)
def process_order(order_id: str):
    ...
```

These are recorded as a JSON object in `labels.kest.identity`:

```json
{
  "user": {"sub": "alice", "role": "admin"},
  "agent": "checkout-web-app",
  "task": "process-order-123"
}
```

> **Note**: `user`, `agent`, and `task` accept either a value or a **callable** (zero-argument function). Callables are evaluated at execution time, which is essential for request-scoped values like the current user from a JWT.

### Resource Attributes

```python
@kest_verified(
    policy="kest/check_data_access",
    resource_attr=lambda: {
        "document_id": "DOC-456",
        "sensitivity": "confidential",
        "department": "finance"
    }
)
def read_document(doc_id: str):
    ...
```

Recorded in `labels.kest.resource_attr` — available to policy engines for fine-grained ABAC:

```rego
package kest.check_data_access

default allow = false

allow {
    input.subject.user.role == "admin"
    input.object.attributes.sensitivity != "top_secret"
}

allow {
    input.subject.user.department == input.object.attributes.department
}
```

### Static Identity Provider

For functions that always run with fixed identity context:

```python
from kest.core import StaticIdentity

static = StaticIdentity(
    workload_id="spiffe://my-service",
    user={"sub": "system", "role": "service-account"},
)

configure(identity=static, engine=my_engine)
```

## LazySigningProvider

The `LazySigningProvider` wraps any `IdentityProvider` and delays initialization until the first `sign()` call:

```python
from kest.core import LazySigningProvider, SPIREProvider

identity = LazySigningProvider(
    factory=lambda: SPIREProvider(
        socket_path="/run/spire/sockets/agent.sock"
    )
)
```

This is useful in containerized environments where the SPIRE Agent socket may not be available at import time but will be ready by the first request.

---

*For the policy evaluation context that receives these fields, see [Policy as Code](/concepts/design/abac_policy). For the full interface specification, see [Spec §5.1](../concepts/design/kest_spec_v0.3.0).*
