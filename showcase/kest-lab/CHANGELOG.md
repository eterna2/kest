# Changelog - Kest Lab

All notable changes to the `kest-lab` dockerized zero-trust testing sandbox will be documented in this file.

## [Unreleased]
- Ongoing lab integration tests and docker sidecar adjustments.

## [v0.3.0] - 2026-04-18
- Stabilized entire Docker sandbox lifecycle targeting pure Python validation models.
- Updated SPIRE, OPA, and Keycloak integrations.
- Converted container integration tests natively into the `moon run kest-core-python:test-live` execution cycle to natively test Linux-based PID/UID Workload Attestation accurately.
