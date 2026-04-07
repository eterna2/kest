---
title: Pre-built Cedar Policies
description: High-performance authorization policies implemented in Cedar.
sidebarTitle: policy.cedar
sidebarCode: |
  permit (
      principal,
      action == Action::"access",
      resource
  )
  when {
      resource.is_public == true ||
      principal.trust_score > 80
  };

  # Biba Integrity Model
  forbid (
      principal,
      action == Action::"write",
      resource
  )
  when { principal.integrity_level < resource.integrity_level };
---
# Pre-built Cedar Policies

Kest provides modern authorization policies implemented in Cedar for use with Cedar Agent or AWS Verified Permissions.

## Brewer-Nash (Chinese Wall)
Location: `kest/core/policies/advanced/brewer_nash.cedar`

Dynamically prevents conflicts of interest by restricting subjects from accessing information in competing datasets if they have already accessed data in a conflicting one.

## Biba (Integrity)
Location: `kest/core/policies/advanced/biba.cedar`

The Cedar implementation of the Biba integrity model.

## Financial Core
Location: `kest/core/policies/financial.cedar`

Implements transaction limits and trust-based authorization for financial workloads.

## Security Core
Location: `kest/core/policies/security.cedar`

Provides basic workload identity verification and MERKLE link validation.
