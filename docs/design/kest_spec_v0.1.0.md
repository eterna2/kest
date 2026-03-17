# Technical Specification: Kest (v0.1.0)

## 1. Abstract
The Kest specification defines a standardized protocol for **Attested Data Lineage**. Every piece of data processed in a secure pipeline is encapsulated within a `KestData` wrapper, carrying a `KestPassport` that cryptographically proves its origin, the systems it traversed, and its risk profile (taints).

## 2. Core Data Structures

### KestData[R]
A generic wrapper used to pass domain data alongside its lineage metadata.
```python
class KestData(Generic[R]):
    data: R
    passport: Optional[KestPassport]
```

### KestPassport
The overall Passport object wraps the history of nodes in a **Directed Acyclic Graph (DAG)**.
* **Origin**: Metadata describing the root requestor and policy constraints.
* **History**: A map of `entry_id` to `KestEntry` objects.
* **Signature**: ED25519 signature covering the serialized history and origin.

### KestEntry
Represents a single execution step (node) in the lineage graph.
```json
{
  "entry_id": "uuid-v4",
  "parent_entry_ids": ["parent-uuid-1", "parent-uuid-2"], 
  "node_id": "namespace.function_name",
  "timestamp_ms": 1710685938000,
  "input_state_hash": "a1b2c3d4...", 
  "content_hash": "e5f6g7h8...",
  "environment": { "hostname": "worker-01" },
  "labels": { "confidentiality": "high" },
  "added_taint": ["pii_data"],
  "accumulated_taint": ["pii_data", "internet_data"]
}
```

## 3. Implementation Patterns (Reference v0.1.0)

### A. Implicit Tracking
In the `v0.1.0` implementation, Kest prioritizes "Secure by Default" tracking. 
* If a function decorated with `@verified` receives **raw untracked inputs** (e.g., standard Python strings or dicts), Kest **implicitly originates** a tracking Passport assigned the `"system-implicit"` identity.
* This ensures that any data crossing a verified boundary is immediately entered into the lineage graph without requiring explicit manual wrapping at every edge.

### B. Multi-Node Merging (Fan-In)
The `@verified` decorator is designed to handle complex data joins:
1. It iterates through all `*args` and `**kwargs`.
2. It extracts all `KestData` wrappers present in the arguments.
3. It merges their distinct `history` maps into the primary Passport.
4. It identifies the leaf nodes of all input branches as the `parent_entry_ids` for the current execution.
5. It aggregates the `accumulated_taint` from all parents to evaluate join-risk policies.

### C. Policy Enforcement (OPA Integration)
Kest integrates with **Open Policy Agent (Rego)** via the `kest.config.policy_engine`. 
* Functions specify `taint_rules` (Rego rule paths) in the decorator.
* Before execution, Kest provides the current node's context (accumulated taints, origin policies, environment) to the engine.
* Execution is blocked with a `PermissionError` if the policy evaluates to `false`.

## 4. Cryptographic Binding
To ensure history immutability, Kest uses a recursive DAG hash:
* $H_{ingress} = \text{Hash}( \text{Sort}(\text{Parent\_Entry\_Hashes}) )$
* $H_{entry} = \text{Hash}(H_{ingress} + \text{Payload\_Hash} + \text{Node\_Metadata})$
* Any tampering with historical taints or node identities will invalidate the final signature.

## 5. DX Tools
* `kest.originate(data, taint=..., labels=...)`: Create a manual genesis node for data entering the system from untrusted or external sources.
* `kest.verified(added_taint=..., taint_rules=...)`: Decorator to automatically manage unwrap/track/re-wrap/sign cycles.
* `kest.config`: Global singleton for configuring the `policy_engine` and default collectors.
