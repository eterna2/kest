# Solving the Secret Zero Problem

The "Secret Zero" problem describes the paradox of bootstrapping trust. How does a workload prove its identity to a secret manager (like Vault or AWS KMS) without already possessing a secret (an API key, token, or password) to authenticate itself? If that initial secret is compromised, the entire security model collapses.

## Traditional Approaches and Failures

Historically, organizations solved this by:
- **Hardcoding credentials**: Storing API keys in code or configuration files. This leads to leaked keys in source control.
- **Environment variables**: Injecting secrets at runtime. These can be exposed via `/proc`, crash dumps, or misconfigured dashboards.
- **IP-based authentication**: Trusting requests from specific network segments. This fails in dynamic cloud environments (Kubernetes) and provides zero defense against internal lateral movement.

## The SPIFFE Solution

Kest mitigates Secret Zero by integrating deeply with the **Secure Production Identity Framework for Everyone (SPIFFE)** and its reference implementation, **SPIRE**.

Instead of developers provisioning and managing secrets, SPIRE acts as an automated identity control plane.

### Node Attestation

1. A SPIRE Agent runs on every node (e.g., EC2 instance, Kubernetes worker).
2. The SPIRE Server attests the Agent's identity using platform-specific verifiable attributes (e.g., AWS Instance Identity Documents, GCP Instance Metadata).

### Workload Attestation

1. When a workload (e.g., a Python service) starts, it connects to the local SPIRE Agent via a Unix Domain Socket (UDS).
2. The Agent interrogates the host operating system kernel to discover the workload's properties (e.g., Linux UID/GID, Kubernetes Namespace/ServiceAccount, Docker labels).
3. If the workload's properties match a registered policy, the Agent issues a **Short-Lived Cryptographic Identity** to the workload.

## The SVID (SPIFFE Verifiable Identity Document)

Kest leverages two types of SVIDs:

1. **JWT-SVID**: Used for lightweight assertion over HTTP boundaries.
2. **X509-SVID**: Used for high-fidelity cryptographic signing.

By using X509-SVIDs, Kest ensures that every workload has a unique, dynamically rotated private key that is *never* transmitted over the network and *never* written to disk. The workload uses this in-memory key to sign its Merkle lineage, providing non-repudiable proof of execution.

If a workload is compromised, the attacker only gains access to a short-lived key (e.g., valid for 1 hour). Furthermore, because Kest tracks the entire lineage, the compromised workload's actions can still be isolated and denied by downstream policy engines.
