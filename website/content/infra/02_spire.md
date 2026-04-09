# SPIFFE/SPIRE Integration

Kest relies heavily on robust cryptographic identities to provide non-repudiation guarantees. While SPIFFE/SPIRE is the recommended, production-grade identity control plane, Kest v0.3.0 decoupled strict SPIFFE reliance to support various environments.

## Supported Identity Providers

Kest supports the following built-in `IdentityProvider`s:

- **`SPIREProvider`**: The reference production integration, relying on short-lived X509-SVIDs from a local SPIRE agent. (Requires the `spiffe` extra: `pip install kest[spiffe]`).
- **`AWSWorkloadIdentity`**: Identifies the workload using an AWS STS Role ARN and signs execution payloads.
- **`AgentcoreIdentity`**: Custom provider simulating identity fetching from an Agentcore control plane via JWT.
- **`OIDCIdentity`**: A generic identity provider using an injected OIDC token.
- **`StaticIdentity`**: A fallback identity provider primarily for testing and local/legacy integration.

## SPIRE Architecture

SPIRE consists of two main components:
1.  **SPIRE Server**: The centralized certificate authority and identity control plane. It manages the trust bundle and node registration.
2.  **SPIRE Agent**: A daemon running on every node (e.g., Kubernetes Node, EC2 Instance). It interrogates the host kernel to identify workloads and issues short-lived SVIDs via a Unix Domain Socket (UDS).

## Kest and SPIRE Integration

When a Kest-protected function is executed, the `SPIREProvider` connects to the local SPIRE Agent UDS.
1. It requests an X509-SVID for cryptographic signing.
2. It requests a JWT-SVID for lightweight, single-hop HTTP authentication (optional, depending on configuration).

### Docker Compose Example
For a complete, runnable example, see the `showcase/kest-lab/docker-compose.yml` file in the Kest repository.

```yaml
services:
  spire-server:
    image: ghcr.io/spiffe/spire-server:1.11.0
    volumes:
      - ./spire/server:/run/spire/config
      - spire-server-data:/opt/spire

  spire-agent:
    image: ghcr.io/spiffe/spire-agent:1.11.0
    volumes:
      - ./spire/agent:/run/spire/config
      - spire-agent-data:/opt/spire
      # Mount the socket directory so workloads can access it
      - spire-agent-socket:/var/run/spire/agent/public

  kest-workload:
    image: python:3.11-slim
    volumes:
      # The workload mounts the socket as read-only
      - spire-agent-socket:/var/run/spire/agent/public:ro
    environment:
      # Tell Kest where to find the SPIRE Agent
      - SPIFFE_ENDPOINT_SOCKET=unix:///var/run/spire/agent/public/api.sock
```

### Workload Registration

Workloads must be explicitly registered with the SPIRE Server. This process defines the `spiffe_id` (e.g., `spiffe://example.org/my-service`) based on kernel-level attributes like Linux UID or Kubernetes Pod labels.

```bash
docker compose exec spire-server bin/spire-server entry create \
    -parentID spiffe://example.org/spire/agent/my-node \
    -spiffeID spiffe://example.org/workload/my-service \
    -selector unix:uid:1000
```
