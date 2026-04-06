---
title: Pre-built Rego Policies (OPA)
description: Standard security models implemented in Rego for Open Policy Agent.
sidebarTitle: policy.rego
sidebarCode: |
  package kest.authz

  import rego.v1

  default allow := false

  # Swarm-level attestation
  allow if {
    input.identity.type == "kest_agent"
    input.action == "swarm_init"
  }
---
# Pre-built Rego Policies (OPA)

Kest provides several standard security models implemented in Rego for use with Open Policy Agent.

## Bell-LaPadula (Confidentiality)
Location: `kest/core/policies/advanced/bell_lapadula.rego`

Focuses on preventing unauthorized disclosure of information.
- **No Read Up**: A subject cannot read an object of higher sensitivity.
- **No Write Down**: A subject cannot write to an object of lower sensitivity.

## Biba (Integrity)
Location: `kest/core/policies/advanced/biba.rego`

Focuses on preventing unauthorized modification of information.
- **No Read Down**: A subject cannot read an object of lower integrity.
- **No Write Up**: A subject cannot write to an object of higher integrity.

## Clark-Wilson
Location: `kest/core/policies/advanced/clark_wilson.rego`

Implements separation of duties and well-formed transactions. Requires auditing of all changes to "Constrained Data Items" (CDIs).

## Financial Core
Location: `kest/core/policies/financial.rego`

Implements transaction limits and lineage-based verification for high-value operations.

## Goguen-Meseguer
Location: `kest/core/policies/advanced/goguen_meseguer.rego`

A non-interference model for multi-level security, ensuring that actions of high-security subjects do not affect the view of low-security subjects.
