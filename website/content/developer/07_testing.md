# Testing & Kest Lab

Kest provides a comprehensive testing strategy spanning unit tests with mocks to fully orchestrated integration tests in a Docker-based lab environment. This section describes the philosophy, tools, and how to run the full verification suite.

## Testing Philosophy

1. **Tests MUST be written before code** — Test-Driven Development (TDD) is mandatory (Principle from AGENTS.md)
2. **Unit tests are co-located** — alongside source files with `_test.py` suffix
3. **Mocking is only for external boundaries** — mock the policy engine and identity provider, not internal logic
4. **Integration tests use real infrastructure** — SPIRE, OPA, Cedar, Keycloak — not simulated

## Unit Testing with Mocks

Kest provides two mock implementations specifically designed for testing:

### MockPolicyEngine

```python
from kest.core import MockPolicyEngine

# Always allow — for testing business logic
engine = MockPolicyEngine(allow=True)

# Always deny — for testing error paths
engine = MockPolicyEngine(allow=False)

# Custom logic — for complex test scenarios
engine = MockPolicyEngine(
    allow=lambda context: context["subject"]["trust_score"] >= 50
)
```

### MockIdentityProvider

```python
from kest.core import MockIdentityProvider

# Deterministic signing with HMAC-SHA256
identity = MockIdentityProvider(workload_id="test-service")
```

The mock uses `HMAC-SHA256` with a fixed key (`"mock-key"`) for deterministic, reproducible signatures. This makes assertions on JWS content possible in tests.

### Example Unit Test

```python
import pytest
from kest.core import configure, kest_verified, MockPolicyEngine

@pytest.fixture(autouse=True)
def setup_kest():
    """Configure Kest for testing before each test."""
    configure(
        engine=MockPolicyEngine(allow=True),
        clear=True,  # Reset state between tests
    )
    yield
    configure(clear=True)

def test_process_payment_success():
    @kest_verified(policy="kest/allow_trusted", source_type="internal")
    def process_payment(amount: float) -> dict:
        return {"status": "completed", "amount": amount}

    result = process_payment(99.95)
    assert result["status"] == "completed"
    assert result["amount"] == 99.95

def test_process_payment_denied():
    configure(engine=MockPolicyEngine(allow=False))

    @kest_verified(policy="kest/allow_trusted", source_type="internal")
    def process_payment(amount: float) -> dict:
        return {"status": "completed"}

    with pytest.raises(Exception):
        process_payment(99.95)
```

### Running Unit Tests

```bash
# Via moonrepo
moon run kest-core-python:test

# Or directly with pytest
cd libs/kest-core/python
uv run pytest python/kest/core/ -v
```

## Kest Lab: Integration Testing

The **kest-lab** is a Docker Compose environment that spins up real infrastructure for end-to-end testing. It validates that Kest works correctly with real identity providers, real policy engines, and real telemetry collectors.

![Kest Lab Docker Compose architecture showing identity, policy, and application layers](/images/kest-lab-arch.png)

### Lab Architecture

The lab includes these services:

| Service | Purpose | Port |
|---|---|---|
| `spire-server` | SPIFFE identity root of trust | — |
| `spire-agent` | Workload attestation agent | Unix socket |
| `opa` | Open Policy Agent sidecar | 8181 |
| `cedar-agent` | Cedar policy sidecar | 8180 |
| `keycloak` | Human identity provider (OIDC) | 8080 |
| `otel-collector` | Telemetry aggregation | 4317 (gRPC) |
| `hop1`, `hop2`, `hop3` | Application nodes for chain testing | — |
| `kest-gateway` | Scope-delegated gateway | 8000 |
| `kest-agent` | AI agent simulation | 8001 |

### Running the Lab

```bash
# Start the lab (auto-creates containers)
moon run kest-lab:up

# Run all integration tests inside the hop1 container
moon run kest-core-python:test-live

# Tear down
moon run kest-lab:down
```

> **Why inside the container?** Tests run inside `hop1` because SPIRE requires PID namespace attestation. The test process must be running in the same PID namespace as the SPIRE Agent. On Docker Desktop (especially WSL2), this means running inside the container, not from the host.

### Test Categories (17 Integration Tests)

The lab validates 5 categories:

**1. Basic Lifecycle (5 tests)**
- Root entry creation with `parent_ids: ["0"]`
- 2-hop chain with correct parent hash linkage
- 3-hop chain with full Merkle verification
- Taint propagation through the chain
- Trust score degradation at each hop

**2. Security Enforcement (4 tests)**
- Signature verification on the complete chain
- Security halt on tampered Passport (HMAC mismatch)
- Policy denial blocks function execution
- Empty policy list rejected at config time

**3. Trust & Taints (3 tests)**
- Custom source types via `register_origin_trust()`
- Taint sanitization with `removed_taints`
- Trust override with `trust_override`

**4. Policy Hierarchy (3 tests)**
- Enterprise baseline evaluated first
- Function-level supplements (doesn't replace) enterprise
- Policy deviations recorded in signed entry

**5. Identity Context (2 tests)**
- User/agent/task recorded in `labels.kest.identity`
- Resource attributes in `labels.kest.resource_attr`

### Example Integration Test

```python
@pytest.mark.live
async def test_3hop_chain():
    """Validate a full 3-hop Merkle chain."""
    configure(engine=MockPolicyEngine(allow=True), clear=True)

    @kest_verified(policy="allow", source_type="system")
    def hop1():
        return hop2()

    @kest_verified(policy="allow", source_type="internal")
    def hop2():
        return hop3()

    @kest_verified(policy="allow", source_type="user_input")
    def hop3():
        return "final"

    result = hop1()
    assert result == "final"

    # Verify the chain
    passport = get_current_passport()
    assert len(passport.entries) == 3

    # Verify hash linkage
    for i in range(1, len(passport.entries)):
        prev_hash = sha256(passport.entries[i-1].encode()).hexdigest()
        entry = decode_jws_payload(passport.entries[i])
        assert entry["parent_ids"][0] == prev_hash
```

## Full Verification Workflow

Before any code changes are committed, both test levels MUST pass:

```bash
# Run everything — unit tests + live integration tests
# Using the @verify workflow:
moon run kest-core-python:test && moon run kest-core-python:test-live
```

Current suite health:
- **124/124** unit tests passing
- **17/17** integration tests passing

---

*For a deep dive into the lab architecture, see [Kest Lab Deep Dive](kest_lab). For the full spec on edge-case testing, see [Spec §11](../blog/design/kest_spec_v0.3.0).*
