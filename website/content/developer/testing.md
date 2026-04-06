# Testing Kest

Kest manages an extensive suite of integration and end-to-end (E2E) tests to guarantee structural integrity across policy scopes, asynchronous environments, and OpenTelemetry (OTel) constraints. We heavily rely on [Moonrepo](https://moonrepo.dev) as a task orchestrator.

## General Testing Philosophy

1. **Host-level Tests**: Unit tests of python logic, purely functional domain evaluation, and deterministic cryptographic tests.
2. **Container-Native Integration Tests**: Integration logic dependent on real infrastructure boundaries. This tests against actual running instances of OPA, SPIRE, Cedar-Agent, and OpenTelemetry Collectors.

---

## 1. Unit Testing (Local/Host)

For core library features that do not strictly require socket-level attestation:

```bash
moon run kest-core-python:test
```

This invokes standard `pytest` directly inside the virtual environment against isolated logic found in `libs/kest-core/python/`.

## 2. Live Integration Testing (Kest Lab)

Because Kest handles high-fidelity SPIFFE/SPIRE Unix socket authentication, **real security components depend on PID and UI namespacing provided by the OS**. Running tests from a local WSL, macOS, or abstract VM environment often breaks kernel-level abstractions needed for secure SVID mapping.

**The Solution:** Kest gracefully delegates E2E test execution dynamically directly into the `hop1` internal container.

```bash
moon run kest-core-python:test-live
```

### What this does:
1. Provisions the entire `kest-lab` docker environment seamlessly in the background.
2. Generates functional cryptographic tokens (SPIFFE X509-SVIDs).
3. Invokes an asynchronous, robust multi-hop trace propagation and CARTA evaluation suite directly within the boundaries of the internal container namespace.
4. Cleans up execution natively.

### Included Lab Scenarios
The live async-first E2E tests (located natively in `showcase/kest-lab/tests/`) cover:
- W3C Distributed Context Propagation (verifying `traceparent` integrity)
- Asynchronous Decorator Lineage (asserting logic integrity during Event Loop yields)
- OPA Authorization Logic via Rego evaluation
- Cedar ABAC Trust Score assessments against dynamically retrieved SVID payloads 

For granular insights into debugging traces over the integration network, please refer to the internal [Kest Lab Setup](kest_lab.md).
