# Platform Identity & Context Resolution

Kest v0.3.0 introduced a modular identity system designed to solve the **Secret Zero** problem across a variety of runtime environments. 
Because identity must be established before any data can be hashed or signed, Kest's `@kest_verified` decorators rely on the `IdentityProvider` interface to securely fetch context and perform cryptographic signing.

## Zero-Config Auto-Detection

To streamline developer onboarding, Kest implements an `AutoDetector` that runs when no identity is explicitly provided to `configure()`. It interrogates environment variables to determine the execution context.

| Environment                 | Detection Variable                       | Configured Provider          |
|-----------------------------|------------------------------------------|------------------------------|
| **SPIRE/SPIFFE**            | `SPIFFE_ENDPOINT_SOCKET`                 | `SPIREProvider`              |
| **Amazon Bedrock Agents**   | `AWS_BEDROCK_AGENT_ID`                   | `BedrockAgentIdentity`       |
| **AWS ECS/EKS/Lambda**      | `AWS_EXECUTION_ENV` or `AWS_ROLE_ARN`*   | `AWSWorkloadIdentity`        |
| **OIDC / GitHub Actions**   | `KEST_OIDC_TOKEN_PATH`                   | `OIDCIdentity`               |
| **Local Development**       | *Fallback*                               | `LocalEd25519Provider`       |

*\*AWS requires `KEST_AWS_KMS_KEY_ID` to be set for cryptographic signing via KMS.*


## Supported Identity Providers

### 1. Amazon Bedrock Agents (`BedrockAgentIdentity`)
Designed specifically for AI agents running on Amazon Bedrock AgentCore.
- **Identity Source**: Uses the `AWS_BEDROCK_AGENT_ID` and `AWS_BEDROCK_AGENT_ALIAS_ID` environment variables.
- **Cryptographic Engine**: Leverages AWS KMS (`kms.sign()`) for hardware-backed JWS signing.
- **Setup Requirement**: Must provide the `KEST_BEDROCK_KMS_KEY_ID` (defaults to `alias/bedrock-agent-signing-key`).

### 2. AWS Workloads (`AWSWorkloadIdentity`)
For standard AWS applications running on ECS, EKS (IRSA), or Lambda.
- **Identity Source**: Dynamically resolves the assumed identity using `sts.get_caller_identity()`.
- **Cryptographic Engine**: Leverages AWS KMS (`kms.sign()`) for hardware-backed JWS signing. Default algorithm is `ECDSA_SHA_256`.
- **Setup Requirement**: Must provide the `KEST_AWS_KMS_KEY_ID`.

### 3. SPIRE/SPIFFE (`SPIREProvider`)
The reference production integration utilizing the SPIFFE Workload API.
- **Identity Source**: Connects to the local SPIRE agent socket and requests an `X509-SVID`.
- **Cryptographic Engine**: Uses the ephemeral private key embedded in the SVID to generate EdDSA or ECDSA signatures natively in memory.
- **Setup Requirement**: Requires the `spiffe` extra (`pip install kest[spiffe]`).

### 4. OIDC Identity (`OIDCIdentity`)
A highly portable provider that can consume JWT tokens injected by the environment (e.g., Kubernetes projected ServiceAccount tokens).
- **Identity Source**: Reads a JWT from the file specified by `KEST_OIDC_TOKEN_PATH`.

### 5. Local Development (`LocalEd25519Provider`)
For local debugging when no heavy control plane is available.
- **Identity Source**: Uses a static, hardcoded workload identifier.
- **Cryptographic Engine**: Generates a temporary, in-memory Ed25519 key pair on initialization.

---

## Overriding the Auto-Detector

If your application requires explicit configuration or dependency injection (for example, injecting a mocked KMS client during tests), you can bypass the auto-detector by passing a provider directly to `configure()`:

```python
import boto3
from kest.core import configure
from kest.core.identity import AWSWorkloadIdentity

# Explicitly configure a boto3 session
session = boto3.Session(region_name="eu-central-1")

identity = AWSWorkloadIdentity(
    kms_key_id="alias/MyCustomKey",
    sts_client=session.client("sts"),
    kms_client=session.client("kms")
)

# Lock in the configuration
configure(identity=identity)
```
