# Policy Library

**Kest** provides a library of battle-tested security policies that implement foundational security models. These are designed to be used as primitive building blocks for Zero-Trust architectures and decentralized authorization.

## 🚀 The Multi-Engine Approach

Every policy in this library is implemented with semantic parity in both **Rego** and **Cedar**.

- **Rego (OPA)**: Ideal for Kubernetes Admission, Envoy/Istio sidecars, and standard OPA deployments.
- **Cedar**: Optimized for performance and readability, compatible with **Cedar Agent** and **AWS Verified Permissions**.

This dual-language support ensures your security posture remains identical across polyglot infrastructures, from the edge to the cloud.

### 🛠️ Quick Integration
To evaluate these policies, initialize a `PolicyEngine` with the desired modules:

```python
from kest.core.engine import RegoLocalEngine
from kest.core.policies import get_policy

# 1. Load Bell-LaPadula model
modules = {"blp": get_policy("bell_lapadula")}

# 2. Use the engine of your choice
engine = RegoLocalEngine(modules=modules)
```

> [!TIP]
> See the [Core Engine Reference](/reference/engine) for detailed configuration and evaluation documentation.

---

## 🏛️ Foundational Security Models

The library includes the following standard security models, ready for production use:

### 🔒 Confidentiality & Integrity
- **[Bell-LaPadula (MLS)](/developers/policy/rego#bell-lapadula-confidentiality)**: The gold standard for multi-level confidentiality. Prevents unauthorized disclosure via "no read up, no write down".
- **[Biba Integrity Model](/developers/policy/cedar#biba-integrity)**: The integrity-focused counterpart to BLP. Prevents data corruption by untrusted subjects ("no read down, no write up").

### 🏗️ Operational Trust
- **[Clark-Wilson](/developers/policy/rego#clark-wilson-operational-integrity)**: A commercial integrity model focused on well-formed transactions and separation of duties.
- **[Brewer-Nash (Chinese Wall)](/developers/policy/cedar#brewer-nash-chinese-wall)**: A dynamic model to mitigate commercial conflicts of interest by tracking historical access patterns.

### 🛡️ Privacy & Isolation
- **[Goguen-Meseguer](/developers/policy/rego#goguen-meseguer-non-interference)**: A formal non-interference model ensuring strict domain isolation and deterministic privacy.
