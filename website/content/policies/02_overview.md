# Policy Library

Kest provides a comprehensive library of pre-built security policies for both Open Policy Agent (Rego) and Cedar. These policies implement standard security models and industry-specific compliance requirements.

## Security Models

- **[Bell-LaPadula](/developers/policy/rego#bell-lapadula-confidentiality)**: Confidentiality model focused on "no read up, no write down".
- **[Biba](/developers/policy/cedar#biba-integrity)**: Integrity model focused on "no read down, no write up".
- **[Clark-Wilson](/developers/policy/rego#clark-wilson)**: Integrity model for commercial applications, focusing on separation of duties.
- **[Brewer-Nash (Chinese Wall)](/developers/policy/cedar#brewer-nash-chinese-wall)**: Model to prevent conflicts of interest.
- **[Goguen-Meseguer](/developers/policy/rego#goguen-meseguer)**: Non-interference model for multi-level security.

## Domain-Specific Policies

- **Financial**: Transaction limits, fraud detection patterns, and multi-signature requirements.
- **Healthcare**: HIPAA-aligned access controls for PHI (Protected Health Information).
- **Core Security**: Basic workload identity verification and lineage integrity checks.

## Engine Compatibility

Kest ensures that all policies are available in both **Rego** and **Cedar** formats wherever possible, allowing you to choose the engine that best fits your infrastructure.
