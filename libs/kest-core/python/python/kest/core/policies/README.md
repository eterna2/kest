# Kest Security Policies

This directory contains standard implementations of classical security models in both **Rego** (Open Policy Agent) and **Cedar**. These policies provide foundational access control logic for high-integrity systems.

## 🚀 Getting Started

Kest supports a variety of policy engines to fit different deployment architectures, from local in-process evaluation to managed cloud services.

### Installation

Install the library with the extras matching your target engine:

| Engine | Extra | Command |
| :--- | :--- | :--- |
| **Rego (OPA)** | `opa` | `pip install kest[opa]` |
| **Cedar (Local)** | `cedar` | `pip install kest[cedar]` |
| **AWS Managed** | `aws` | `pip install kest[aws]` |

---

## 🛠️ Policy Engines

All engines inherit from the base `PolicyEngine` class and implement a unified interface.

### `OPAPolicyEngine`
Delegates evaluation to an Open Policy Agent (OPA) sidecar via REST API.
- **Backend**: OPA External Service
- **Deployment**: Sidecar / Host Agent

### `RegoLocalEngine`
Evaluates Rego policies directly in-process using `regopy` (C++ bindings).
- **Backend**: `regopy`
- **Use Case**: High-performance, sidecar-free Rego.

### `CedarPolicyEngine`
Delegates to a Cedar Agent or Sidecar implementing the `is_authorized` JSON interface.
- **Backend**: Cedar Sidecar

### `CedarLocalEngine`
In-process evaluation using `cedarpy` (Rust-backed).
- **Backend**: `cedarpy`
- **Use Case**: Edge computing, CLI tools, or mobile environments.

### `AVPPolicyEngine`
Managed evaluation via Amazon Verified Permissions (AVP).
- **Backend**: AWS API
- **Use Case**: Cloud-native authorization for AWS workloads.

### `MockPolicyEngine`
Returns a static boolean decision.
- **Use Case**: Local development and unit testing.

---

## 📖 Usage Example

### Rego (Local)
```python
from kest.core.engine import RegoLocalEngine
from kest.core.policies import get_policy

# 1. Load pre-built policies
modules = {"blp": get_policy("bell_lapadula")}
engine = RegoLocalEngine(modules=modules)

# 2. Evaluate
allowed = engine.evaluate(
    entry_id="node_01",
    policy_names=["advanced.bell_lapadula"],
    context={"subject": {"clearance": 3}, "object": {"classification": 2}}
)
```

### Cedar (Agent / Sidecar)
```python
from kest.core.engine import CedarPolicyEngine

engine = CedarPolicyEngine(url="http://localhost:8180")

allowed = await engine.async_evaluate(
    entry_id="Resource::\"file_01\"",
    policy_names=["policy_id_v1"],
    context={"workload_id": "User::\"alice\""}
)
```

---

## 📚 Security Models Reference

### 🛡️ 1. Bell-LaPadula (Confidentiality)
The gold standard for multi-level security (MLS). It is designed to prevent unauthorized disclosure of information by ensuring that information only flows "upward" in terms of classification.
- **Problem**: Confidentiality leaks across clearance levels.
- **Invariants**: 
    - **Simple Security Property**: A user at a specific clearance level cannot read data classified at a higher level ("No Read Up").
    - **Star (*) Property**: A user cannot write information to a lower classification level, preventing the "leakage" of secret data to public channels ("No Write Down").
- **Attributes**: `subject.clearance`, `object.classification`.
- **Reference**: [Wikipedia](https://en.wikipedia.org/wiki/Bell%E2%80%93LaPadula_model)

### 🛡️ 2. Biba (Integrity)
The integrity-focused counterpart to Bell-LaPadula. While BLP prevents data leakage, Biba prevents data corruption by ensuring that high-integrity data is never influenced by low-integrity subjects.
- **Problem**: Data corruption and "poisoning" from untrusted sources.
- **Invariants**: 
    - **Simple Integrity Property**: A user cannot read data at a lower integrity level, as it might contain corrupt or untrusted information ("No Read Down").
    - **Integrity Star (*) Property**: A user cannot write data to a higher integrity level, preventing low-integrity users from modifying high-integrity data ("No Write Up").
- **Attributes**: `subject.integrity`, `object.integrity`.
- **Reference**: [Wikipedia](https://en.wikipedia.org/wiki/Biba_Model)

### 🛡️ 3. Brewer-Nash (The Chinese Wall)
A dynamic model specifically designed for commercial environments where conflicts of interest must be mitigated. Unlike static ACLs, accessibility changes based on the user's previous actions.
- **Problem**: Conflict of interest between competing clients in a single firm.
- **Invariants**: 
    - **Access Rule**: A user can access data from a company only if they have never accessed data from a different company within the same conflict class (e.g., if you've read documents from Bank A, you are blocked from Bank B's documents).
- **Attributes**: `subject.history`, `object.conflict_class`, `object.company_id`.
- **Reference**: [Wikipedia](https://en.wikipedia.org/wiki/Chinese_Wall)

### 🛡️ 4. Clark-Wilson (Operational Integrity)
A modern commercial integrity model that moves beyond simple levels to focus on **well-formed transactions** and **separation of duties**.
- **Problem**: Unauthorized or fraudulent internal transactions.
- **Invariants**: 
    - **Certified Triples**: Users are only allowed to perform specific **Actions (Programs)** on specific **Resources (Objects)** if that specific triple has been formally certified.
    - **Separation of Duties**: Ensures that critical tasks are divided among different subjects to prevent fraud.
- **Attributes**: `certified_triples`, `subject.id`, `program.id`, `object.id`.
- **Reference**: [Wikipedia](https://en.wikipedia.org/wiki/Clark%E2%80%93Wilson_model)

### 🛡️ 5. Goguen-Meseguer (Non-interference)
A formal mathematical approach to system isolation. It ensures that the actions of a "high-level" domain cannot have any observable effect on the state or output visible to a "low-level" domain.
- **Problem**: Side-channel attacks and implicit information leaks.
- **Invariants**: 
    - **Domain Isolation**: Strict boundaries between execution domains.
    - **Non-interference Mapping**: One domain's actions are mathematically proven to be invisible to another domain unless an explicit "declassification" or "interference" path is authorized.
- **Attributes**: `subject.domain`, `object.domain`, `non_interference_mappings`.
- **Reference**: [Wikipedia](https://en.wikipedia.org/wiki/Non-interference_(information_security))
