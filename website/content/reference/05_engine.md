---
title: Core Engine
description: Unified interface for policy evaluation across different engines.
sidebarTitle: engine.py
sidebarCode: |
  # Protocol Evaluation Contract
  class PolicyEngine(ABC):
      @abstractmethod
      def evaluate(
          self, entry_id, policy_names, context
      ) -> bool:
          pass
---

The `kest.core` module provides a unified interface for evaluating security policies across different engines.

The `kest.core` module provides a unified interface for evaluating security policies across different engines.

---

### `PolicyEngine` (Interface)

The abstract base class for all policy engines in Kest. A `PolicyEngine` identifies whether a specific action (`entry_id`) is authorized under a set of policies given a specific context.

#### Methods

- **`evaluate(entry_id, policy_names, context) -> bool`**: 
  Synchronously evaluates whether the request is authorized.
- **`async_evaluate(entry_id, policy_names, context) -> bool`**: 
  Asynchronously evaluates whether the request is authorized.

---

### `OPAPolicyEngine`

Evaluates policies by delegating to an Open Policy Agent (OPA) sidecar via its REST API (`v1/data`).

#### Configuration
- `url`: The base URL of the OPA sidecar (default: `http://localhost:8181`).
- `decision_path`: The dot-separated path to the boolean decision in the OPA response (default: `result.allow`).
- `timeout`: Request timeout in seconds.

---

### `CedarPolicyEngine`

Evaluates policies by delegating to a Cedar Agent / Sidecar implementing the `is_authorized` JSON interface.

#### Configuration
- `url`: The base URL of the Cedar agent (default: `http://localhost:8180`).
- `timeout`: Request timeout in seconds.

---

### `CedarLocalEngine`

In-process Cedar engine using the official `cedarpy` Rust-backed bindings. Ideal for edge environments or local testing.

#### Configuration
- `policies`: A dictionary of policy IDs to Cedar policy strings.
- `entities`: A list of Cedar entity dictionaries.

---

### `AVPPolicyEngine`

Evaluates policy by delegating to **Amazon Verified Permissions (AVP)**. It supports both synchronous (`boto3`) and asynchronous (`aioboto3`) clients.

#### Configuration
- `policy_store_id`: The AWS AVP Policy Store ID.
- `region_name`: AWS region (e.g., `us-east-1`).

---

### `PolicyCache`

Caches compiled policy results or metadata to avoid redundant lookups. Useful for local engines with expensive compilation or remote engines with high latency.
