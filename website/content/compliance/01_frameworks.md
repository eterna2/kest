# Framework Mapping

Kest's architecture maps directly to the foundational requirements of modern security and compliance frameworks.

## NIST 800-207 (Zero Trust Architecture)

NIST SP 800-207 defines the core tenets of Zero Trust. Kest addresses several of these directly:

*   **Tenet 2: All communication is secured regardless of network location.** Kest uses SPIRE X509-SVIDs for execution signing. The network is assumed hostile, and the cryptographic lineage provides proof of execution independent of network segmentation.
*   **Tenet 3: Access to individual enterprise resources is granted on a per-session basis.** Kest enforces policies at the function level (`@kest_verified`), evaluating the entire execution lineage per request.
*   **Tenet 4: Access to resources is determined by dynamic policy.** Kest's integration with OPA and Cedar enables Attribute-Based Access Control (ABAC), utilizing the dynamic `trust_score` and accumulated taints from the execution lineage.
*   **Tenet 6: All resource authentication and authorization are dynamic and strictly enforced before access is allowed.** Kest policy sidecars evaluate the Merkle chain *before* the decorated function executes.

## SOC 2 Type II

SOC 2 audits focus heavily on Security, Availability, and Confidentiality.

*   **CC6.1: The entity implements logical access security.** Kest's granular ABAC policies restrict unauthorized execution at the code level.
*   **CC7.2: The entity monitors system components and the operation of those components for anomalies.** The non-fungible OpenTelemetry audit trail ensures that security incidents (like lateral movement or privilege escalation attempts) are immutably logged and mathematically verifiable.

## PCI-DSS v4.0

Payment Card Industry Data Security Standard (PCI-DSS) requires strict access control and auditing.

*   **Requirement 7: Restrict access to system components and cardholder data by business need to know.** Kest supports multi-policy aggregation. A service can enforce a strict "Chinese Wall" policy, ensuring that an execution path that previously handled untrusted or non-compliant data cannot later access the cardholder data environment (CDE).
*   **Requirement 10: Log and monitor all access to system components and cardholder data.** Traditional logs can be altered by an attacker who compromises a system within the CDE. Kest's Merkle-linked execution spans (signed with short-lived X509-SVIDs) provide an undeniable, tamper-evident audit log of every function execution affecting cardholder data.
