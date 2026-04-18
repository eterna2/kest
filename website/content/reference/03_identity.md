---
title: Identity Providers
description: Platform-specific workload identification and cryptographic signing.
sidebarTitle: identity.py
sidebarCode: |
  # IdentityProvider Interface
  class IdentityProvider(ABC):
      @abstractmethod
      def get_workload_id(self) -> str:
          pass

      @abstractmethod
      def sign(self, payload: bytes) -> str:
          pass
---

The `kest.core` module provides various implementations for identifying workloads and signing audit entries.

## Base Class

### `IdentityProvider(ABC)`
*Source: `kest.core.base`*

Abstract base class for all identity providers in Kest. An `IdentityProvider` is responsible for identifying the current workload and signing audit entries (Passport nodes).

#### Methods

- **`get_workload_id() -> str`**: Returns the unique identifier for the current workload (e.g., SPIFFE ID, AWS Role ARN).
- **`sign(payload: bytes) -> str`**: Signs a payload and returns a complete JWS string (`header.payload.signature`).
- **`verify_svid(svid: str) -> str`**: Verifies a SVID and extracts the workload ID.
- **`sign_payload(payload: bytes) -> str`**: Aliased bridge method for signing payloads.

## Providers

### Local & Testing
### `StaticIdentity`
*Source: `kest.core.providers.local`*

Basic fallback provider for local testing or less modern infrastructure. Uses a static workload ID and generates a fresh Ed25519 keypair for in-memory signing.

### `LocalEd25519Provider`
Legacy alias for `StaticIdentity`, maintaining backwards compatibility with existing test suites.

### `MockIdentityProvider`
Dummy provider for unit testing without cryptographic overhead. Generates a deterministic 'mock' signature string.

### SPIFFE/SPIRE
### `SPIREProvider`
*Source: `kest.core.providers.spiffe`*

Production-grade provider using SPIRE Workload API for X509-SVID signing. Communicates with the SPIRE agent's Unix Domain Socket to fetch identities and certificates.

**Requirements**: Requires the `spiffe` package.

### AWS IAM & KMS
### `AWSWorkloadIdentity`
*Source: `kest.core.providers.aws`*

Uses AWS STS to identify the workload's role and AWS KMS for signing. Designed for workloads running on AWS (EKS, Lambda).

**Requirements**: Requires the `boto3` package.

### Amazon Bedrock
### `BedrockAgentIdentity`
*Source: `kest.core.providers.bedrock`*

Standard provider for Amazon Bedrock Agent execution environments. Resolves Bedrock Agent ID and Alias ID from environment variables and uses AWS KMS to sign execution traces.

**Requirements**: Requires the `boto3` package.
