# Kest v0.3.0 — Implementation Learnings

> **Audience:** AI agents and engineers working on `libs/kest-core/python` (and the `kest-lab` showcase) targeting the SPEC-v0.3.0.md spec.
> **Status:** Living document — append findings; never rewrite history.
> **Last updated:** 2026-04-11 (fixed stale entries, added ARCHIVES.md for resolved/false-alarm findings)

---

## Table of Contents

1. [How to Read This Document](#1-how-to-read-this-document)
2. [Spec Compliance Matrix](#2-spec-compliance-matrix)
3. [Bugs Discovered and Fixed](#3-bugs-discovered-and-fixed)
4. [Spec Gaps and Deviations](#4-spec-gaps-and-deviations)
5. [Architecture Decisions with Non-Obvious Rationale](#5-architecture-decisions-with-non-obvious-rationale)
6. [Performance Findings and Benchmarks](#6-performance-findings-and-benchmarks)
7. [Lab Infrastructure Gotchas](#7-lab-infrastructure-gotchas)
8. [Cedar & OPA Policy Engine Notes](#8-cedar--opa-policy-engine-notes)
9. [Known Production Risks](#9-known-production-risks)
10. [Test Patterns That Have Bitten Us](#10-test-patterns-that-have-bitten-us)

> **See also:** [`ARCHIVES.md`](./ARCHIVES.md) for resolved false alarms and superseded findings (D-03, T-07, L-04 original).

---

## 1. How to Read This Document

- **§N** references map to section numbers in `spec/SPEC-v0.3.0.md`.
- **F-XX-NN** references are the requirement IDs from the spec.
- **Source file** citations use repo-relative paths.
- When a finding changes the implementation, note both what was changed and *why* the spec is subtly silent on it.

---

## 2. Spec Compliance Matrix

Quick reference for the state of the Python implementation against spec requirements.

| Spec Requirement Area | Requirement IDs | Status | Notes |
|---|---|---|---|
| Identity & Signing | F-ID-01 → F-ID-05 | ✅ Implemented | SPIRE, LocalEd25519, Mock all present |
| KestEntry schema | F-AE-01 → F-AE-13 | ✅ Implemented | All fields populated |
| Passport / Merkle DAG | F-PA-01 → F-PA-07 | ✅ Implemented | PassportVerifier handles DAG, not just chain |
| Verification Hook lifecycle | F-PE-01 → F-PE-13 | ✅ Implemented | Steps 8→9→10→11 match spec exactly (D-03 closed — no deviation) |
| Trust score | F-TS-01 → F-TS-06 | ✅ Implemented | All default origin scores correct |
| Taint tracking | F-TT-01 → F-TT-06 | ✅ Implemented | |
| Identity context (user/agent/task) | F-IC-01 → F-IC-05 | ✅ Resolved (2026-04-11) | Baggage keys now match spec: `kest.user`, `kest.agent`, `kest.task` (see §4.1 — D-01 resolved) |
| Context propagation | F-CP-01 → F-CP-08 | ✅ Implemented | `kest.passport_z` normative as F-CP-07/F-CP-08; Claim Check Pattern renumbered §8.6 (D-02 resolved) |
| Telemetry | F-TE-01 → F-TE-04 | ✅ Implemented | |
| Global configuration | F-GC-01 → F-GC-04 | ✅ Implemented | |
| PerfNFR 1ms signing | NF-PERF-02 | ✅ Met (Python backend) | Rust backend GIL-degraded — see §6 |
| PerfNFR 2ms hook overhead | NF-PERF-03 | ✅ Met (unloaded) | Degrades under GIL contention — see §6 |
| Policy cache | (not in spec) | ➕ Extension | `_PolicyDecisionCache` is an impl-level optimization — see D-05 |
| Cedar policy context | §9.4 | ✅ Implemented | Context keys now spec-compliant: `user`, `agent`, `task`, `scope` (C-02) |
| Lab fallback gate | (not in spec) | ➕ Extension | `KEST_LAB_FALLBACK=true` required to activate filesystem fallback (D-04 resolved) |
| Policy cache TTL | (not in spec) | ➕ Extension | Configurable via `KEST_POLICY_CACHE_TTL` env var (D-05 resolved) |
| Core baggage reads | (not in spec) | ✅ Hardened (2026-04-11) | `_get_baggage()` is now pure OTel — no global dict/filesystem coupling (R-02 resolved) |
| JWT verification gate | (not in spec) | ✅ Hardened (2026-04-11) | `KEST_INSECURE_NO_VERIFY=true` required to start without `jwks_uri` (R-03 resolved) |

---

## 3. Bugs Discovered and Fixed

### B-01: Policy Decision Cache — Cross-Request Identity Collision

**Component:** `libs/kest-core/python/python/kest/core/decorators.py` — `_PolicyDecisionCache._make_key`  
**Spec reference:** F-PE-01 (policy must be evaluated per invocation), §9.2 (context)  
**Symptom:** A workload serving multiple Keycloak users would return a cached `Allow` decision for a second user even when that user's scope or identity should produce a `Deny`. This caused `test_gateway_denies_insufficient_scope` to receive 200 instead of 403.  
**Root cause:** The original cache key was `(principal, trust_score, classification, policies)`. This is the SPIRE-level identity — it is shared across all HTTP requests hitting the same workload process. Different Keycloak-issued JWTs with the same SPIRE SVID but different `scope`, `user`, or `agent` would collide on the key.  
**Fix (2026-04-11):** Expanded cache key to include `user`, `agent`, and `task`. These are extracted from the JWT via `KestIdentityMiddleware` and propagated via OTel Baggage as `kest.user`, `kest.agent`, `kest.task` (spec-compliant names, SPEC-v0.3.0 §8.4).  
**Lesson:** The spec's "principal" is the *workload* SVID. The policy evaluation context also has user/agent/task from Keycloak. Any cache that keys only on workload identity is wrong in a multi-tenant or user-delegated deployment.

**Correct cache key tuple:**
```python
(principal, trust_score, classification, tuple(sorted(policy_names)),
 user, agent, task)  # spec-compliant names (SPEC-v0.3.0 §8.4)
```

**Test coverage (2026-04-11):** `policy_decision_cache_test.py` — `test_cache_different_user_produces_distinct_key`, `test_cache_different_agent_produces_distinct_key`, `test_cache_different_task_produces_distinct_key`, `test_cache_hit_identical_identity`.

---

### B-02: Claim Check Test Using Compressible Data

**Component:** `showcase/kest-lab/tests/test_claim_check_live.py`  
**Spec reference:** F-CP-04 / F-CP-05  
**Symptom:** After Fix 3 (zlib compression of baggage), the test `test_live_claim_check_rehydration` began passing through the compression path instead of the claim-check path. The test asserted `kest.claim_check` was in the baggage, but the compressed string fit within 4096 bytes.  
**Root cause:** The original test used 15 identical JWS strings, which zlib compresses to near-zero due to repetition. The threshold was never breached.  
**Fix (2026-04-11):** Replaced repeated entries with `os.urandom(400)` per entry so each has a distinct, incompressible random signature. Confirmed the packed baggage reliably exceeds 4096 bytes even post-compression, forcing the claim-check path.  
**Lesson:** Any test that relies on "large passport" must use cryptographically random (incompressible) data, not repeated real-looking JWS strings which are highly regular and compress well.

---

### B-03: Cedar Policy File Missing for `allow` Policy

**Component:** `showcase/kest-lab/cedar/policies/allow.cedar`  
**Symptom:** All requests to `/hop1`, `/hop2`, `/hop3` returned 403, even with valid SPIRE attestation and correct trust scores. The Cedar engine responded with "no policies matched".  
**Root cause:** The `@kest_verified(policy="allow")` decorator expects a Cedar policy named `allow` to be loaded. No such policy file existed in the `cedar/policies/` directory.  
**Fix (2026-04-11):** Created `allow.cedar` with spec-compliant context key names (post D-01 alignment):
```cedar
permit(principal, action, resource) when {
  10 <= context["trust_score"] &&
  context has "user" &&
  !(context["user"] == "")
};
```
**Lesson:** The lab ships with OPA policies for all routes but Cedar policies must be explicitly created for each named action. `action` in Cedar maps directly to the `policy` string passed to `@kest_verified`. There is no "default allow" in Cedar.

**Note:** The original snippet in this entry used `context.principal_user` (the pre-D-01 key name). The actual file uses the spec-compliant `context["user"]` as of 2026-04-11. See `showcase/kest-lab/cedar/policies/allow.cedar`.

---

### B-04: OTel Baggage Propagation Loss in ThreadPoolExecutor

**Component:** `libs/kest-core/python/python/kest/core/decorators.py`  
**Spec reference:** F-CP-05 (baggage must propagate reliably downstream)  
**Symptom:** In the GIL-free Rust signing path, OpenTelemetry baggage (`kest.user`, `kest.agent`) was silently omitted from JWS labels. The baggage was completely lost when execution offloaded to a background thread to prevent event loop blocking. This caused `403 Forbidden` errors in downstream hops.  
**Root cause:** Python `contextvars` (which underpin OTel baggage) are thread-local and coroutine-local. `asyncio.get_running_loop().run_in_executor()` runs the target function in a bare thread without propagating the caller's context variables. Any read or write of OTel baggage inside the background thread operated with a fresh, empty context.  
**Fix (2026-04-12):** Explicitly capture the context before offloading with `cv = contextvars.copy_context()` and execute the background operation within it via `cv.run()`.  
**Lesson:** Any offloading to `ThreadPoolExecutor` or `ProcessPoolExecutor` inside a Python async context MUST explicitly pass and run within `contextvars.copy_context()` if it interacts with OpenTelemetry, tracing, or logging frameworks that rely on ContextVars.

---

## 4. Spec Gaps and Deviations

### D-01: Baggage Key Naming — RESOLVED (2026-04-11)

**Spec says (F-IC-05, §8.4):** JWT `sub` claim → `kest.user`; `client_id` claim → `kest.agent`; `scope` → `kest.task`.  
**Was:** `kest.principal_user`, `kest.principal_agent`, `kest.principal_scope`, `kest.principal_roles`.  
**Now:** `kest.user`, `kest.agent`, `kest.task` (spec-compliant). Kept `kest.scope` as a non-normative extension for Cedar ABAC policies that need to match the raw OAuth scope string.

**Files changed (2026-04-11):**  
- `libs/kest-core/python/python/kest/core/ext.py` — `KestIdentityMiddleware` writes spec keys  
- `libs/kest-core/python/python/kest/core/decorators.py` — `ctx_to_eval` dict uses spec keys  
- `libs/kest-core/python/python/kest/core/identity_test.py` — tests updated  
- `showcase/kest-lab/cedar/policies/*.cedar` — all Cedar policies updated  
- `showcase/kest-lab/opa/policies/kest.rego` — OPA policy updated  
- `showcase/kest-lab/agent.py`, `app.py`, **`gateway.py`** — baggage reads/writes updated  
- `showcase/kest-lab/tests/*.py` — test assertions and comments updated  

**Extension retained:** `kest.scope` (non-normative) carries the raw OAuth scope string. This is read by the gateway policy for user-delegated authorization (`gateway_policy.cedar`). Cedar's `workload_user_policy` uses `context["task"]` (the spec key), while `gateway_policy` uses `context["scope"]` for the OAuth scope `like "*read:data*"` check.

**Impact on interoperability:** Other language implementations that expect `kest.principal_user` must be updated to read `kest.user`. Previous versions of the Python impl wrote the old keys — do not mix old and new containers in one lab stack.

**Test coverage (2026-04-11):** `ext_test.py` — `test_identity_middleware_writes_spec_keys` asserts that `kest.user`, `kest.agent`, and `kest.task` are present in OTel baggage after JWT decoding, and that the old `kest.principal_*` keys are absent.

---

### D-02: Compressed Baggage Variant (`kest.passport_z`) — RESOLVED (2026-04-11, spec updated)

**Spec said (F-CP-01–F-CP-06, §8.3):** Two baggage states: `kest.passport` (inline, ≤ 4096 bytes) and `kest.claim_check` (UUID reference when > 4096 bytes).  
**Implementation added:** A third intermediate state: `kest.passport_z` — a zlib-compressed, base64url-encoded inline Passport.  

**Why:** A 10-hop chain at ~500 bytes/entry = ~5KB uncompressed, but only ~1.5KB after zlib level-1. This keeps most real production chains inline without hitting the cache, radically reducing cache dependency and latency for deep call stacks.

**Resolution (2026-04-11):** `kest.passport_z` is now normative. Added to SPEC-v0.3.0.md as **F-CP-07** (produce, optional) and **F-CP-08** (consume, MUST). The §8.3 Claim Check pseudocode updated to **§8.6** with three-tier logic. §11.3 edge case updated. The baggage key table in §8.4 updated.

**Interoperability contract:** Produce is optional (MAY use `kest.passport_z`); consume is mandatory (MUST be able to decompress `kest.passport_z` if encountered).

**Test coverage (2026-04-11):** `models_test.py` — `test_baggage_manager_compressed_above_threshold` (F-CP-07 path: compressible data uses `kest.passport_z`), `test_baggage_manager_claim_check_incompressible` (F-CP-08 path: incompressible data falls through to `kest.claim_check`), `test_baggage_manager_inline_below_threshold` (F-CP-01 baseline). Also `claim_check_test.py` — `test_full_claim_check_lifecycle`, `test_claim_check_failure_no_cache`, `test_claim_check_expired_ttl_fails_closed`.

---

### D-03 — archived

> This entry has been moved to [`ARCHIVES.md`](./ARCHIVES.md). Summary: no deviation was ever present. Steps 8→9→10→11 match the spec exactly. Compliance matrix is ✅.

---

### D-04: `LabFallbackBaggageProvider` — RESOLVED (2026-04-11)

**Component:** `decorators.py` — `LabFallbackBaggageProvider` class  
**Issue:** This class uses filesystem-backed hash tracking (`last_hash_<service>.txt` files) and an in-memory global dict (`_LAB_BAGGAGE_STORE`) to compensate for OTel Baggage propagation failures in the Docker lab environment. **This code path should never run in production.**  
**Spec reference:** §13.2 Note 4 — "OTel context is the source of truth for Passport propagation."  

**Fix (2026-04-11):** Added an `_LAB_FALLBACK_ENABLED` module-level gate controlled by the `KEST_LAB_FALLBACK` environment variable. All four `LabFallbackBaggageProvider` filesystem methods (`append_audit`, `update_chain`, `get_parent_hash`, `get_passport_entries`) now return immediately without touching the filesystem unless `KEST_LAB_FALLBACK=true`.  

**docker-compose.yml updated:** `KEST_LAB_FALLBACK=true` added to all five workload service environment blocks (hop1, hop2, hop3, kest-agent, kest-gateway).  

**Production behaviour:** With `KEST_LAB_FALLBACK` unset (or set to `false`), the fallback is fully inactive. The core library is safe to deploy in production without removing this class — it simply does nothing.

**Remaining risk:** `LabFallbackBaggageProvider.get_baggage()` and `set_baggage()` still use `_LAB_BAGGAGE_STORE` (in-memory dict), which has no concurrency isolation. Under high concurrency, trace_id collisions are theoretically possible. This class is still debt to remove from the core library into a lab-only monkey-patch layer.

---

### D-05: Policy Decision Cache — RESOLVED (2026-04-11)

**The spec defines no caching of policy decisions.** The `_PolicyDecisionCache` (5-second TTL, 1024 LRU entries) is a pure implementation optimization.  

**Fix (2026-04-11):** TTL is now configurable via the `KEST_POLICY_CACHE_TTL` environment variable (float, seconds, default `5.0`). Operators can tune this: lower values reduce the stale-decision window for security-sensitive deployments; higher values improve throughput under heavy OPA round-trip load.

**Risk:** A 5-second TTL means a policy change (e.g., Cedar policy hot-reload, OPA bundle update) may not take effect for up to 5 seconds. This is a security trade-off that must be documented and configurable. Call `invalidate_policy_cache()` after any policy reload.

**The cache is NOT used for `CedarLocalEngine`** when it loads policies from disk — each `cedarpy` call re-evaluates from the compiled policy in memory. The cache is most impactful for `OPAPolicyEngine` (network round-trip) and `CedarPolicyEngine` (HTTP call).

---

## 5. Architecture Decisions with Non-Obvious Rationale

### A-01: `asyncio.to_thread` for Signing in Async Path

**File:** `decorators.py` — `async_wrapper`  
**Decision:** Ed25519 signing and baggage packing are offloaded to `asyncio.to_thread()` inside the async `async_wrapper`.  
**Why:** These are CPU-bound operations. Running them directly in the async event loop blocks the loop for all concurrent requests. The thread pool offload keeps the event loop responsive at high RPS.  
**Trade-off:** This adds one thread pool dispatch per request. At very low concurrency this is measurable overhead (~10–20µs). At high concurrency (100+ concurrent requests) the benefit of not blocking the loop far outweighs this cost.

**Better solution — Rust `sign_entry` with `py.allow_threads` is already partially correct (see A-02).** For the Python backend, `asyncio.to_thread` is the correct approach because the Python backend's `sign_entry` cannot release the GIL. However, a structural improvement is possible:

> **Improvement A-01-I (medium risk):** Pre-build a module-level `ThreadPoolExecutor` with a fixed size (e.g., `min(4, os.cpu_count())`) and share it across all `@kest_verified` calls via `loop.run_in_executor(pool, ...)`. The default `asyncio.to_thread` uses `concurrent.futures.thread._worker`, which scales unbounded under extreme load and can exhaust OS thread limits. A bounded pool degrades gracefully instead.

**Tracking:** [eterna2/kest#10](https://github.com/eterna2/kest/issues/10)

```python
_SIGN_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=min(4, os.cpu_count() or 1),
    thread_name_prefix="kest-sign"
)
# In async_wrapper:
loop = asyncio.get_running_loop()
new_ctx = await loop.run_in_executor(_SIGN_EXECUTOR, _execute_core_post_auth, ...)
```

> **Improvement A-01-II (future / Python 3.13+):** Python 3.13 introduced an experimental free-threaded build (PEP 703, `python3.13t`). In the free-threaded build, `to_thread` achieves true CPU parallelism without a bounded pool. Monitor adoption — when FastAPI/Starlette officially support the no-GIL build, `to_thread` becomes the optimal approach for CPU-bound signing with no changes to the call site.

---

### A-02: Rust Backend GIL Contention Cliff

**Finding:** Under GIL-contention benchmarks (multiple threads, each executing `@kest_verified`), the Rust backend (`_core.abi3.so` via PyO3) degrades **~94%** in throughput compared to the Python backend (`_core_py.py`). The Python backend degrades only ~21%.

**Root Cause (precise, from reading `lib.rs`):**

The current `sign_entry` Rust implementation does this:
1. Clones the inner Rust struct (GIL held)
2. Calls `py.allow_threads(|| ...)` — releases GIL for canonicalization (pure Rust)
3. Calls `Python::with_gil(|py2| provider.call_method1(py2, "sign_payload", ...))` — **re-acquires** GIL to call the Python identity provider
4. Returns to Python

Step 3 is the cliff. `sign_payload` is a **Python callback** (a method on `LocalEd25519Provider`, `SPIREProvider`, etc.). Every Rust thread must re-acquire the GIL to call it. Under 8-thread contention, threads spend most of their time queued waiting for the GIL to execute a single `sign_payload` call. The Python backend avoids this because it holds the GIL in one uninterrupted stretch through `rfc8785.dumps` + `provider.sign_payload` — fewer acquisitions, less scheduling overhead.

**Fix Path Options (ranked by impact and feasibility):**

> **Option A-02-A (recommended, medium effort):** Move the `IdentityProvider.sign_payload()` method for the key providers into Rust entirely. `LocalEd25519Provider` uses PyNaCl (`nacl.signing.SigningKey`) today; replace it with the `ed25519-dalek` crate in Rust. This eliminates the Python callback in step 3 entirely. The full `sign_entry` path would then be a single `py.allow_threads(...)` block with no GIL re-acquisition.

```rust
// Proposed: sign_entry in lib.rs with a native Rust signer
let signing_key: ed25519_dalek::SigningKey = /* load from Rust IdentityProvider */;
let result = py.allow_threads(|| {
    let signing_input = canonicalize_and_build_jws(&inner)?;
    let sig = signing_key.sign(signing_input.as_bytes());
    Ok::<_, String>(format!("{}.{}", signing_input, base64url_encode(&sig.to_bytes())))
});
```

This requires adding a `RustNativeIdentityProvider` pyclass that holds an `ed25519_dalek::SigningKey` internally (or a path to a key file). The Python-callable `sign_payload` interface stays for SPIRE (which needs the SPIFFE socket), but local key signing can be fully GIL-free.

> **Option A-02-B (low effort, bypass):** Don't use the Rust backend for the signing path at all in async contexts. Use the Rust backend only for `KestEntry` construction (which is allocation-only and does not benefit from GIL release anyway), and use the Python backend's `sign_entry` for the actual JWS generation. This is effectively what `KEST_BACKEND=python` does, but scoped to the sign step. Not a clean fix, but unblocks production immediately.

> **Option A-02-C (future):** Python 3.13 free-threaded (`python3.13t`) eliminates the GIL entirely. With no GIL, PyO3 callbacks into Python no longer serialize threads. Both the Rust and Python backends would scale linearly. **Do not block on this** — FastAPI/Starlette ecosystem support for the free-threaded build is still incomplete as of 2026-04.

**Tracking:** [eterna2/kest#11](https://github.com/eterna2/kest/issues/11)

**Fixed (2026-04-11):** Implemented `RustEd25519Provider` (A-02-A). Local Ed25519 signing is now performed entirely in Rust using the `ed25519-dalek` crate. The `sign_entry` function in `lib.rs` detects the native provider and executes canonicalization + signing in a single `py.allow_threads` block. This eliminates GIL re-acquisition for local signing, achieving linear scaling under thread contention.

**Current guidance:** For high-throughput multithreaded signing, use `RustEd25519Provider` with the Rust backend. SPIREProvider still requires GIL re-acquisition (due to the SPIFFE socket Python callback) and remains a bottleneck under extreme contention.

---

### A-03: `Passport.accumulated_taints` and `trust_scores` Are Lazy-Cached Properties — RESOLVED (2026-04-12)

**File:** `models.py` — `Passport._get_parsed_entries()`  
**Decision:** Parsing all JWS payloads in a passport on every `@kest_verified` call is O(n) in chain length. The parsed entries are cached in `_parsed_cache` and invalidated only when `entries` changes (via `add_signature()`).  
**Why L1 Baggage is still a problem:** Even with caching, a 10-hop chain carries ~10 full JWS entries (~5KB raw, ~1.5KB compressed). Parsing is amortized, but the baggage size itself still triggers claim-check on very deep chains with incompressible (random-signed) data.

**Resolved (2026-04-12, eterna2/kest#12):**

> **A-03-I (RESOLVED):** Replaced list-snapshot comparison (`_entries_snapshot != self.entries`, O(n)) with integer version counter (`_cache_version != _version`, O(1)). The `_entries_snapshot` field was removed entirely.

> **A-03-II (RESOLVED):** `accumulated_taints` now returns `frozenset` in O(1) — maintained incrementally in `add_signature()`. New `min_trust_score` property returns `int` in O(1). `trust_scores` (per-entry list) still requires the parsed cache. The `frozenset` return type is an intentional minor API change — callers that need mutation must use `set(passport.accumulated_taints)`. The one internal caller in `decorators.py` was updated.

> **A-03-III (RESOLVED):** `@dataclass(slots=True)` added. No subclasses of `Passport` exist. Confirmed compatible with Python 3.11+ (pinned in `.prototools`).

**`__post_init__` note:** `Passport(entries=[...])` (used by `merge()`, `deserialize()`, and direct construction) triggers `__post_init__()` which rebuilds `_taints_cache`, `_min_trust_cache`, and `_version` from the initial entries. This ensures correct caches regardless of construction path.

**Test coverage (2026-04-12):** `models_test.py` — `test_passport_version_counter_invalidation`, `test_passport_accumulated_taints_returns_frozenset`, `test_passport_accumulated_taints_incremental`, `test_passport_accumulated_taints_empty`, `test_passport_min_trust_score_property`, `test_passport_min_trust_score_empty`, `test_passport_slots_no_dict`, `test_passport_deserialize_rebuilds_caches`, `test_passport_merge_rebuilds_caches`.

**Tracking:** [eterna2/kest#12](https://github.com/eterna2/kest/issues/12)

---

## 6. Performance Findings and Benchmarks

See also: `libs/kest-core/python/examples/bench/BENCHMARK.md` for the full benchmark methodology and raw numbers.

### Summary Table (v0.3.0 Python reference implementation)

| Scenario | Throughput | p99 Latency | Notes |
|---|---|---|---|
| Python backend, single-threaded | ~3,200 RPS | <1 ms signing | Baseline |
| Rust backend, single-threaded | ~3,100 RPS | <1 ms signing | ~3% slower than Python due to PyO3 overhead |
| Python backend, 8 threads, GIL-contended | ~2,530 RPS | 2–3 ms | 21% degradation |
| Rust backend, 8 threads, GIL-contended | ~190 RPS | >10 ms | **94% degradation — do not use in MT Python** |
| With policy cache (OPA, warm) | +40–60% RPS | < 0.1 ms policy | Skips OPA network round-trip |
| Claim-check path (>4096 bytes) | −10–15% RPS | +0.3 ms | Cache write overhead |
| Compressed inline (`kest.passport_z`) | ~0% overhead | ≈ 10 µs extra | zlib level-1 is essentially free |

### Key Production Finding: L1 Baggage Explosion

> **IMPORTANT:** A 10-hop chain carries ~10 JWS entries × ~500 bytes each = ~5KB raw baggage. This **exceeds the 4096-byte inline threshold on every hop starting at hop 4**, triggering the claim-check path. This is a real production bottleneck that the naive benchmark (single-hop) is completely blind to.
>
> **With compression (Fix 3):** A 10-hop chain compresses to ~1.5KB, staying inline until ~hop 28. This buys significant headroom but does NOT eliminate the issue for very deep pipelines or large entry payloads.
>
> **What to measure in production:** Always benchmark at the actual chain depth you expect (e.g., 5-hop, 10-hop). Single-hop benchmarks are misleading.

---

## 7. Lab Infrastructure Gotchas

### L-01: Cedar Policy Store Bootstrap Is Not Automatic

The `cedar/policies/` directory is bind-mounted into the Cedar sidecar, but the Cedar agent requires an explicit `POST /policies` or policy-bundle upload on startup. If you restart the Cedar container without re-uploading policies:
- All `@kest_verified` calls get 403 from Cedar.
- The error message from Cedar is generic ("no matching policy") and does not indicate the policy is missing vs denied.

**Fix:** Ensure `showcase/kest-lab/scripts/upload_cedar_policies.sh` (or equivalent) runs before tests. In the lab compose, this is handled by the `kest-agent` startup script.

---

### L-02: Moon Task Cache Aggressiveness

`moon run kest-lab:test-live` caches task output based on input file hashes. If you change Cedar policies or environment config but NOT any Python source files, Moon will use the cached test result and skip execution.

**Fix:** Use `moon run kest-lab:test-live --force` to bypass cache, or `--affected` mode after touching any file moon tracks.

---

### L-03: Integration Tests Must Run Inside Container (`hop1`)

Per NF-TEST-03 and per SPIRE's PID namespace attestation requirements: SPIRE Agent attests workloads using Linux kernel-level cgroup/PID namespace evidence. Running tests from the host (outside Docker) means the test process has a different PID namespace than the workload, causing SVID delivery to fail.

**Correct invocation:** `moon run kest-lab:test-live` delegates to `docker compose exec hop1 pytest ...` automatically.

**Symptom if run from host:** `SpiffeEndpointSocket` errors, or empty SVID responses, even when the stack is fully up.

---

### L-04: OTel Baggage and `_LAB_BAGGAGE_STORE` — Scope Reduced (2026-04-11)

The `_LAB_BAGGAGE_STORE` dict (in `ext.py`, keyed by OTel trace_id) was originally added as a secondary propagation channel because standard W3C Baggage propagation was observed to drop values across async context switches in the lab.

**Current scope (post R-02 fix):** `_LAB_BAGGAGE_STORE` is now **only** used by `KestHttpxInterceptor` for outbound HTTP injection. Core library baggage reads (`_get_baggage()` in `decorators.py`) go exclusively through `baggage.get_baggage()` (OTel context) and are no longer coupled to this dict at all.

**Remaining risk:** `KestHttpxInterceptor` still reads `_LAB_BAGGAGE_STORE[trace_id]` as a fallback when no OTel baggage is set. This is not thread-safe under high concurrency (no per-request isolation guarantee). Do not rely on this path in production.

**Original concern:** See [`ARCHIVES.md`](./ARCHIVES.md) — "L-04 (original)" for the full history.

---

## 8. Cedar & OPA Policy Engine Notes

### C-01: Cedar Action Maps to Policy Name

In `CedarLocalEngine`, the Cedar `action` entity ID must match the policy name passed to `@kest_verified`. Example:
```python
@kest_verified(policy="allow")
```
→ Cedar evaluates `action == Action::"allow"`.

This is **not stated in the spec** but is the implementation contract. If you create a new Cedar policy for a new `@kest_verified(policy="my_policy")` call, you MUST create a `.cedar` file with `action == Action::"my_policy"`.

---

### C-02: Cedar Context Is Flattened to Dot-Notation

Per §9.2, Cedar requires a flat string-keyed context. The `CedarLocalEngine` maps (spec-compliant names as of 2026-04-11):
- `trust_score` → `context.trust_score` (integer)
- `user` → `context.user` (string, from `kest.user` baggage, spec §8.4)
- `agent` → `context.agent` (string, from `kest.agent` baggage)
- `task` → `context.task` (string, from `kest.task` baggage — OAuth scope / task ID)
- `scope` → `context.scope` (string, impl extension — raw OAuth scope, for `like "*read:data*"` gates)
- `classification` → `context.classification` (string)

Cedar policies reference these as `context.user`, `context.trust_score`, etc. Verify your policy uses the **new** key names (not `context.principal_user`) when debugging 403s on a post-2026-04-11 deployment.

---

### C-03: OPA Policy Path Corresponds to Package Name

For `OPAPolicyEngine`, the URL path `/v1/data/<policy_name>` must match the Rego `package` declaration. Example:
```rego
package allow   # → POST /v1/data/allow
```
The `default allow = false` statement is required or OPA returns `{"result": {}}` (no `allow` key), which the engine interprets as denial.

---

## 9. Known Production Risks

### R-01: Policy Cache TTL Is a Security Trade-Off

A 5-second TTL means policy changes take up to 5 seconds to propagate. For most ABAC policies this is acceptable, but for revocation scenarios (e.g., a user's scope is revoked after a compromise), the window is exploitable.

**Public API (2026-04-11):** `invalidate_policy_cache()` is now exported from `kest.core` as a first-class public API. Call it after any security-sensitive policy update to flush the cache immediately:
```python
from kest.core import invalidate_policy_cache
invalidate_policy_cache()  # clears all entries; next call forces fresh evaluation
```
Alternatives: reduce `KEST_POLICY_CACHE_TTL` for high-sensitivity endpoints (e.g., `KEST_POLICY_CACHE_TTL=1.0`), or set it to `0` to disable caching entirely.

**Test coverage (2026-04-11):** `policy_decision_cache_test.py` — `test_invalidate_clears_module_cache` (verifies a cached decision is re-evaluated after `invalidate_policy_cache()`) and `test_ttl_zero_disables_caching` (verifies every call evaluates fresh when TTL=0).

---

### R-02: `LabFallbackBaggageProvider` — RESOLVED (2026-04-11)

**Previous risk:** The fallback in `decorators.py` used `/workspace/app/last_hash_<service>.txt` files. Concurrent worker writes caused silent Merkle chain corruption.

**Fix:** Removed `LabFallbackBaggageProvider.get_baggage()` and `set_baggage()` from the class entirely. Introduced a module-level `_get_baggage(key)` helper in `decorators.py` that reads directly from `baggage.get_baggage()` (OTel context), with no global dict or filesystem I/O. The remaining filesystem methods (`append_audit`, `update_chain`, `get_parent_hash`, `get_passport_entries`) remain, but are strictly no-ops unless `KEST_LAB_FALLBACK=true`.

**Result:** Core library baggage reads and writes are now pure OTel context operations. No global state, no filesystem coupling.

**Test coverage (2026-04-11):** `decorators_baggage_test.py` — three tests:
- `test_get_baggage_reads_from_otel_context` — confirms value set via OTel baggage API is returned.
- `test_get_baggage_returns_none_without_context` — confirms None on missing context.
- `test_get_baggage_ignores_lab_store` — **regression guard**: injects into `_LAB_BAGGAGE_STORE` directly and asserts `_get_baggage()` sees nothing. Would catch any re-coupling immediately.

---

### R-03: Unverified JWT Decoding — RESOLVED (2026-04-11)

**Previous risk:** When `jwks_uri=None`, `KestIdentityMiddleware` decoded JWTs without signature verification silently. A misconfigured production deployment (forgotten env var) was indistinguishable from a properly configured one at runtime.

**Fix:** `KestIdentityMiddleware.__init__` now raises `RuntimeError` at construction time if `jwks_uri=None` AND the environment variable `KEST_INSECURE_NO_VERIFY` is not set to `true`. This makes production misconfiguration fail loudly — on the **first request** (due to Starlette's lazy middleware stack build). The error message names the exact env var to set, making it self-documenting in crash logs.

**Lab configuration updated:** All 5 lab workloads now receive `KEYCLOAK_JWKS_URI` in `docker-compose.yml`, so they use verified JWT decoding. No service requires `KEST_INSECURE_NO_VERIFY=true` in the lab.

**Gotcha (T-08):** Starlette/FastAPI builds the middleware stack lazily on the first HTTP request — not at startup. A `RuntimeError` in middleware `__init__` will therefore surface as a 500 Internal Server Error on the first request, not at process boot. If you see unexplained 500s after changing middleware config, check stdout for `RuntimeError` lines.

**Test coverage (2026-04-11):** `ext_test.py` — `test_identity_middleware_no_jwks_no_env_raises` and `test_identity_middleware_no_jwks_with_env_succeeds`. The first verifies the `RuntimeError` is raised and mentions `KEST_INSECURE_NO_VERIFY` in the message. The second confirms the guard does not block explicitly acknowledged insecure mode.

---

## 10. Test Patterns That Have Bitten Us

### T-01: Use `os.urandom` for Large Passport Tests

Any test that must trigger the claim-check path (or remain above the compression threshold) MUST use `os.urandom`-based random signatures. Repeated or structured JWS strings compress down to near-zero and never trigger the threshold.

```python
def _make_incompressible_entry():
    random_sig = base64.urlsafe_b64encode(os.urandom(400)).decode()
    payload = base64.urlsafe_b64encode(b'{"trust_score":100}').decode()
    return f"header.{payload}.{random_sig}"
```

---

### T-02: Call `invalidate_policy_cache()` in Test Setup

If tests share a process (e.g., pytest session-scoped fixtures), cached policy decisions from one test leak into the next. Add `invalidate_policy_cache()` to your test setup:

```python
@pytest.fixture(autouse=True)
def reset_kest():
    from kest.core.decorators import invalidate_policy_cache
    invalidate_policy_cache()
```

---

### T-03: Live Tests Require the Full Stack to Be Running

`@pytest.mark.live` tests depend on: SPIRE, OPA, Cedar, Keycloak, all hop services, kest-gateway, kest-agent. Running a subset will produce confusing failures. Use `moon run kest-lab:up` before `moon run kest-lab:test-live`.

---

### T-04: `requires_keycloak` / `requires_gateway` Decorators

Tests decorated with `@requires_keycloak` or `@requires_gateway` will be skipped automatically if those services are unreachable. If tests are silently passing in CI, check whether they were skipped rather than executed.

### T-05: `KEST_LAB_FALLBACK` Must Be Set for Lab Integration Tests

As of 2026-04-11, the `LabFallbackBaggageProvider` filesystem methods are *inactive by default*. All lab integration tests that depend on the audit file (`/workspace/app/lab_audit.json`) or the per-service hash files (`last_hash_<service>.txt`) will produce empty results unless `KEST_LAB_FALLBACK=true` is set in the container environment.

**This is set automatically in `docker-compose.yml`** for all workload services. But if you spin up containers manually (e.g., `docker run ...` without the compose file), remember to pass `-e KEST_LAB_FALLBACK=true`.

**Symptom if missing:** `test_passport_audit_trail` and gateway E2E audit tests pass with empty `audit_trail` lists (zero entries), because the fallback never wrote any signatures.

---

### T-06: Spec Key Name Rollover — Do Not Mix Old and New Containers

After the 2026-04-11 spec-alignment (D-01), the Python implementation writes `kest.user` / `kest.agent` / `kest.task` into OTel baggage. If you have old containers (built before this change) running alongside new containers:
- Old containers emit `kest.principal_user`; new containers read `kest.user`.
- The new container will see no `kest.user` baggage, causing Cedar policies that check `context has "user"` to return 403.

**Fix:** Always rebuild all lab containers together after this change (`moon run kest-lab:down && moon run kest-lab:up`).

---

### T-07 — archived

> This entry has been moved to [`ARCHIVES.md`](./ARCHIVES.md). Summary: OPA now auto-reloads `.rego` changes via `--watch /policies`. No container restart needed.

---

### T-08: Starlette Middleware Stack Is Built Lazily (First Request)

Starlette/FastAPI does not build the middleware stack at startup. It builds it on the first incoming HTTP request. Consequence: a `RuntimeError` raised in a middleware `__init__` (e.g., the new `KEST_INSECURE_NO_VERIFY` guard) surfaces as a **500 Internal Server Error** on the first request, not as a process crash at boot.

**Symptom:** Service passes healthcheck and appears running, but every request returns 500.  
**Diagnosis:** Check `docker compose logs <service>` for `RuntimeError` lines printed inline with the 500 trace.  
**Fix:** Correct the misconfiguration (e.g., set `KEST_INSECURE_NO_VERIFY=true` or provide `KEYCLOAK_JWKS_URI`), then restart the service.

---

### T-09: Testing `KestIdentityMiddleware` Requires a Real Coroutine as `app`

**File:** `libs/kest-core/python/python/kest/core/ext_test.py`

`KestIdentityMiddleware.__call__` attaches the OTel context and then calls `await self.app(scope, receive, send)`. To observe the baggage values the middleware sets, the inner `app` must:

1. Be a genuine `async def` coroutine, **not** a lambda or `lambda s, r, sd: None` (those are not awaitable).
2. Be wired in at **construction time** (`KestIdentityMiddleware(app=inner_app, ...)`), not injected later.
3. Call `baggage.get_all()` *inside* the coroutine body — the OTel context is thread-local and only attached during the `await self.app(...)` call.

```python
async def inner_app(scope, receive, send):
    captured.update(baggage.get_all())  # context is live here

mw = KestIdentityMiddleware(app=inner_app, jwks_uri=None)
scope = {"type": "http", "headers": [(b"authorization", b"Bearer <token>")]}
await mw(scope, noop_receive, noop_send)
```

**Symptom if wrong:** Test passes trivially because `captured` is empty — the lambda was called but returned `None`, which is awaited without error, and no baggage was captured.

---

### T-10: PyO3 `#[pyclass(subclass)]` — Use `__new__` Not `__init__` in Python Subclasses

**File:** `libs/kest-core/python/python/kest/core/identity/providers/local.py` — `RustEd25519Provider`

PyO3's `#[new]` maps to Python `__new__`, **not** `__init__`. When a Python class subclasses a PyO3 `#[pyclass(subclass)]` (e.g., `RustNativeIdentityProvider`), calling `super().__init__(args...)` will **not** reach the Rust constructor — due to MRO, it routes through `IdentityProvider`, `ABC`, and reaches `object.__init__()`, which does not accept arguments.

**Wrong approach (generates `TypeError: object.__init__() takes exactly one argument`):**

```python
class RustEd25519Provider(RustNativeIdentityProvider, IdentityProvider):
    def __init__(self, private_key_bytes: bytes, principal: str):
        super().__init__(private_key_bytes, principal)  # BUG: routes to object.__init__
```

**Correct approach — override `__new__` to invoke the Rust constructor:**

```python
class RustEd25519Provider(RustNativeIdentityProvider, IdentityProvider):
    def __new__(cls, private_key_bytes: bytes, principal: str = "..."):
        # Explicitly routes to the PyO3 #[new] constructor, bypassing MRO ambiguity.
        return RustNativeIdentityProvider.__new__(cls, private_key_bytes, principal)

    def __init__(self, private_key_bytes: bytes, principal: str = "..."):
        pass  # No-op: __new__ handled all Rust initialization.
```

**Symptom:** `TypeError: object.__init__() takes exactly one argument (the instance to initialize)` when constructing any `RustEd25519Provider` instance.

**Discovered during:** Rebase of PR #35 onto main (2026-04-12). Jules generated the subclass with `pass` in `__init__` (which avoids the TypeError but leaves the Rust struct uninitialized), and the initial fix attempt used `super().__init__()` which routes to `object.__init__()`.

### T-11: JCS Sorting Discrepancy (Rust vs Python)
- **Problem**: Bit-for-bit JWS equivalence failed for labels containing control characters (e.g., `\x1f`).
- **Root Cause**: `serde_jcs` (v0.1.0) is **abandoned** and violates RFC 8785 §3.2.3. The RFC requires sorting by raw (unescaped) UTF-16 code unit values. `serde_jcs` incorrectly sorted by the JSON-escaped representation (treating `\u001f` as `\` + `u` + ...), causing `\x1f` (U+001F = 31) to sort *after* `"0"` (U+0030 = 48) instead of before it.
- **Fix**: Replaced `serde_jcs` with `serde_json_canonicalizer` (v0.2.0+) in both `libs/kest-core/rust/Cargo.toml` and `libs/kest-core/python/Cargo.toml`. The new crate explicitly sort keys as UTF-16 code unit arrays (`sorting_key: Vec<u16>`) as mandated by the RFC. Call sites updated to use `to_vec()` instead of `to_string()`.
- **Impact**: The Hypothesis property-based test now passes with full Unicode coverage (excluding lone surrogates `Cs`, which are invalid per RFC 8785 / I-JSON).
- **Files**: `canonical.rs`, `crypto.rs` (Rust core); `lib.rs` (PyO3 extension); both `Cargo.toml` files.
