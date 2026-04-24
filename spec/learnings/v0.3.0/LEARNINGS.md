# Kest v0.3.0 — Implementation Learnings

> **Audience:** AI agents and engineers working on `libs/kest-core/python` (and the `kest-lab` showcase) targeting the SPEC-v0.3.0.md spec.
> **Status:** Living document — append findings; never rewrite history.
> **Last updated:** 2026-04-12 (archived resolved bugs and stabilized deviations to ARCHIVES.md)

---

## Table of Contents

1. [How to Read This Document](#1-how-to-read-this-document)
2. [Spec Compliance Matrix](#2-spec-compliance-matrix)
3. [Architecture Decisions with Non-Obvious Rationale](#3-architecture-decisions-with-non-obvious-rationale)
4. [Performance Findings and Benchmarks](#4-performance-findings-and-benchmarks)
5. [Lab Infrastructure Gotchas](#5-lab-infrastructure-gotchas)
6. [Cedar & OPA Policy Engine Notes](#6-cedar--opa-policy-engine-notes)
7. [Known Production Risks](#7-known-production-risks)
8. [Test Patterns That Have Bitten Us](#8-test-patterns-that-have-bitten-us)

> **See also:** [`ARCHIVES.md`](./ARCHIVES.md) for resolved bugs, stabilized spec deviations, and superseded findings.

---

## 1. How to Read This Document

- **§N** references map to section numbers in `spec/SPEC-v0.3.0.md`.
- **F-XX-NN** references are the requirement IDs from the spec.
- **Source file** citations use repo-relative paths.

---

## 2. Spec Compliance Matrix

| Spec Requirement Area | Requirement IDs | Status | Notes |
|---|---|---|---|
| Identity & Signing | F-ID-01 → F-ID-05 | ✅ Implemented | SPIRE, LocalEd25519, Mock all present |
| KestEntry schema | F-AE-01 → F-AE-13 | ✅ Implemented | All fields populated |
| Passport / Merkle DAG | F-PA-01 → F-PA-07 | ✅ Implemented | PassportVerifier handles DAG, not just chain |
| Verification Hook lifecycle | F-PE-01 → F-PE-13 | ✅ Implemented | Steps 8→9→10→11 match spec exactly |
| Trust score | F-TS-01 → F-TS-06 | ✅ Implemented | All default origin scores correct |
| Taint tracking | F-TT-01 → F-TT-06 | ✅ Implemented | |
| Identity context (user/agent/task/resource) | F-IC-01 → F-IC-05 | ✅ Implemented | `user`, `agent`, `task` via Baggage; `resource_id`/`resource_attr` via decorator params (Issue #77) |
| Context propagation | F-CP-01 → F-CP-08 | ✅ Implemented | `kest.passport_z` (compressed) is now normative |
| Telemetry | F-TE-01 → F-TE-04 | ✅ Implemented | |
| Global configuration | F-GC-01 → F-GC-04 | ✅ Implemented | |
| PerfNFR 1ms signing | NF-PERF-02 | ✅ Met | Python backend; Rust backend scales with native provider |
| PerfNFR 2ms hook overhead | NF-PERF-03 | ✅ Met | Unloaded baseline |

---

## 3. Architecture Decisions with Non-Obvious Rationale

### A-01: `asyncio.to_thread` for Signing in Async Path

**Decision:** Ed25519 signing and baggage packing are offloaded to `asyncio.to_thread()` inside the async `async_wrapper`.  
**Rationale:** These are CPU-bound operations. Running them directly in the async event loop blocks the loop for all concurrent requests.
**Trade-off:** Adds ~10–20µs overhead at low concurrency; drastically improves responsiveness at high RPS.

**Future Improvement (A-01-I):** Use a bounded module-level `ThreadPoolExecutor` to prevent thread exhaustion under extreme load. [Issue #10](https://github.com/eterna2/kest/issues/10).

---

### A-02: Rust Backend GIL Contention Cliff

**Finding:** The Rust backend (`PyO3`) degrades significantly (~94%) under multi-threaded contention when calling back into Python-based `IdentityProvider` methods.

**Current Guidance:**
- For high-throughput multithreaded signing, use **`RustEd25519Provider`** with the Rust backend. This executes signing entirely in Rust, releasing the GIL.
- **SPIREProvider** still requires GIL re-acquisition due to its Python-based socket logic and remains a bottleneck under extreme contention.

### A-03: OpenTelemetry Baggage Context Lifecycle Inversion (V2 Backend)

**Finding:** Python OpenTelemetry `context_vars` behaves counterintuitively when manually detaching tokens inside a `with trace.use_span()` block. Explicitly detaching the context token *inside* the block gets overridden when the span's `__exit__` later completes, causing perpetual context leakage and breaking downstream baggage consumers test isolation.
**Current Guidance:**
- Always ensure `otel_context.detach()` executes in the **outermost `finally` block**, completely wrapping any `use_span` context managers.

### A-04: Trust and Taint Propagation inside Rust Pipeline

**Decision:** Trust score calculation and taint aggregation have been ported into the Rust runtime rather than computing them in Python prior to FFI boundary.
**Rationale:** The CARTA "weakest link" model (origin score bounded by the minimum parent score) relies on decoding the `kest.passport_z` baggage data to inspect parent entries. Performing this decoding twice (once in Python for trust/taints and once in Rust) became inefficient. 
**Trade-off:** Pass `trust_override` and the raw `origin_trust_score` binding directly to the FFI boundary (`pipeline_execute`) and construct the final trust context and accumulated taints within `kest-runtime-rs`.

---

## 4. Performance Findings and Benchmarks

### Summary Table

| Scenario | Throughput | p99 Latency | Notes |
|---|---|---|---|
| Python backend | ~3,200 RPS | <1 ms signing | Baseline |
| Rust (Native Provider) | ~3,100 RPS | <1 ms signing | Linear scaling (GIL-free) |
| Rust (Python Provider) | ~190 RPS | >10 ms | **GIL Bottleneck** |
| Claim-check path | −15% RPS | +0.3 ms | Cache write overhead |
| Compressed inline | ~0% overhead | ≈ 10 µs extra | zlib level-1 is essentially free |

### Key Production Finding: L1 Baggage Explosion

> [!IMPORTANT]
> A 10-hop chain carries ~10 JWS entries × ~500 bytes each = ~5KB raw baggage. This **exceeds the 4096-byte inline threshold on every hop starting at hop 4**, forcing the claim-check path.
> 
> **With compression:** A 10-hop chain compresses to ~1.5KB, staying inline until ~hop 28. This buys significant headroom but does NOT eliminate the issue for very deep pipelines.

---

## 5. Lab Infrastructure Gotchas

### L-01: Cedar Policy Store Bootstrap Is Not Automatic

The Cedar sidecar requires an explicit `POST /policies` on startup. Restarting the container without re-uploading policies results in 403s on all routes. Use `upload_cedar_policies.sh` in the lab environment.

### L-02: Moon Task Cache Aggressiveness

`moon` caches task output based on input hashes. Changing environment variables or Cedar policies might not trigger a re-run of live tests if Python files are untouched. Use `--force` to bypass.

### L-03: Integration Tests Must Run Inside Container (`hop1`)

SPIRE Agent attests workloads using Linux kernel-level PID namespace evidence. Running tests from the host environment (outside Docker) causes SVID delivery failures.

### L-04: OTel Baggage and `_LAB_BAGGAGE_STORE`

The `_LAB_BAGGAGE_STORE` dict is a secondary propagation channel for the lab. **Do not rely on this in production.** Core library reads now go exclusively through standard OTel context.

---

## 6. Cedar & OPA Policy Engine Notes

### C-01: Cedar Action Maps to Policy Name

The Cedar `action` entity ID must match the `policy` name passed to `@kest_verified`.
Example: `@kest_verified(policy="allow")` → Cedar evaluates `action == Action::"allow"`.

### C-02: Cedar Context Key Naming

The Cedar context is flattened to dot-notation using spec-compliant names:
- `context.user` (string, from `kest.user`)
- `context.agent` (string, from `kest.agent`)
- `context.task` (string, from `kest.task`)
- `context.trust_score` (integer)

### C-03: OPA Policy Path Corresponds to Package Name

For `OPAPolicyEngine`, the URL path `/v1/data/<policy_name>` must match the Rego `package` declaration.

---

## 7. Known Production Risks

### R-01: Policy Cache TTL Is a Security Trade-Off

The 5-second default TTL (`KEST_POLICY_CACHE_TTL`) means security policy changes (e.g., revoking a user) may take up to 5 seconds to propagate across all nodes.
- **Guideline:** Use `invalidate_policy_cache()` after sensitive updates.
- **Guideline:** Set `KEST_POLICY_CACHE_TTL=0` for high-security endpoints to disable caching entirely.

---

## 8. Test Patterns That Have Bitten Us

### T-01: Use `os.urandom` for Large Passport Tests

Always use incompressible random data to test the claim-check or compression paths. Repetitive JWS strings will compress too well to breach thresholds.

### T-02: Call `invalidate_policy_cache()` in Test Setup

Cached decisons leak between tests in the same process. Add `invalidate_policy_cache()` to your pytest session/function setup.

### T-03: Live Tests Require Full Stack

`@pytest.mark.live` tests depend on multiple sidecars (SPIRE, OPA, Cedar, Keycloak). Ensure the lab is fully up before running specific test files.

### T-04: Lazy Middleware Initialization

Starlette builds the middleware stack on the **first request**. Configuration errors (like missing JWKS URI) will surface as a 500 on the first hit, not as a crash at startup.

### T-05: JCS Sorting Discrepancy (Rust vs Python)

Bit-for-bit JWS equivalence requires RFC 8785 compliant canonicalization. Ensure control characters are handled by sorting raw UTF-16 code units (implemented via `serde_json_canonicalizer`).

### T-06: PyO3 Subclassing — Use `__new__`

When subclassing a PyO3 class (e.g., `RustNativeIdentityProvider`), override `__new__` to invoke the Rust constructor. Standard `super().__init__` may incorrectly route to `object.__init__`.

### A-06: V2 Context Normalization Resolution
**Resolution**: While the `rust-v2` backend generically stores tracking context as strings for OTel payload validation (`BTreeMap<String, String>`), Kest explicitly implements Spec-Aware Type Coercion directly inside the Engine Adapters (Cedar, OPA, and Foreign FFI engines). This specifically parses and intercepts standard specification integer fields like `trust_score` before policy evaluation, ensuring strict type compliance across language boundaries.
### T-07: Assert `context["object"]` Shape in Engine Override

When testing `resource_id` / `resource_attr` forwarding, override `evaluate()` in a `MockPolicyEngine` subclass to capture the `context` dict:

```python
class _CapturingEngine(MockPolicyEngine):
    def __init__(self): super().__init__(allow_all=True); self.contexts = []
    def evaluate(self, entry_id, policy_names, context):
        self.contexts.append(context); return True
```

Then assert:
```python
assert engine.contexts[0]["object"]["id"] == "expected-id"
assert engine.contexts[0]["object"]["attributes"] == {"dept": "eng"}
```

This avoids patching internals and tests the full end-to-end resolver path.
