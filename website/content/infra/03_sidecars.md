# Policy Sidecars (OPA/Cedar)

Kest evaluates policies locally using a sidecar architecture. Rather than relying on a centralized policy service that introduces latency and a single point of failure, Kest nodes evaluate complex rules directly alongside the workload.

## Open Policy Agent (OPA)

OPA is the industry standard for policy-as-code, utilizing the Rego language.

### Deployment

Deploy an OPA container alongside your Kest-protected service. The application communicates with OPA over `localhost`.

```yaml
services:
  # The OPA Sidecar
  opa:
    image: openpolicyagent/opa:latest
    command: ["run", "--server", "--log-level=info", "--addr", ":8181", "/policies"]
    volumes:
      - ./opa/policies:/policies
    ports:
      - "8181:8181"

  # The Application
  my-kest-service:
    image: my-app:latest
    environment:
      # Tell Kest to use the local OPA instance
      - KEST_OPA_URL=http://opa:8181
```

### Kest Integration

To connect Kest to OPA, initialize the `OPASidecarEngine`:

```python
from kest.core import OPASidecarEngine, configure

engine = OPASidecarEngine(url="http://localhost:8181")
configure(engine=engine)
```

## Amazon Cedar

Cedar is a fast, highly performant policy language open-sourced by AWS. It is optimized for sub-millisecond evaluation and is the foundation for Amazon Verified Permissions.

### Deployment

Similar to OPA, run the Cedar Agent alongside your application.

```yaml
services:
  # The Cedar Sidecar
  cedar-agent:
    image: permitio/cedar-agent:latest
    command: ["--addr", "0.0.0.0:8180"]
    volumes:
      - ./cedar/policies:/policies
    ports:
      - "8180:8180"
```

### Kest Integration

To connect Kest to Cedar, use the `CedarSidecarEngine`:

```python
from kest.core import CedarSidecarEngine, configure

engine = CedarSidecarEngine(url="http://localhost:8180")
configure(engine=engine)
```

By decoupling the policy engine from the application logic, security teams can update rules dynamically without requiring a code deploy.
