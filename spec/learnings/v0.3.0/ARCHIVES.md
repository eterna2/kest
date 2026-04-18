# Kest v0.3.0 — Archived Learnings

> **Why this file exists:** Learnings that were resolved as false alarms, superseded by later findings, or are no longer actionable are archived here rather than deleted. This preserves the reasoning trail for future agents.

---

## D-03: Verification Hook Step Ordering — FALSE ALARM (archived 2026-04-11)

**Originally logged as:** A deviation from the normative 13-step lifecycle where signing appeared to happen "before" the policy check.

**Spec says (§5.8):** The normative 13-step lifecycle is:
```
8. Canonicalize and sign the KestEntry payload.
9. Call engine.evaluate() → raise error on denial.
10. Execute the protected operation.
11. Append JWS to Passport.
```

**Finding:** The implementation matches the spec exactly — steps 8→9→10→11 in order. The concern arose from reading the code and seeing `sign()` called before `engine.evaluate()`, but this is the correct spec order. The signed JWS is only **appended** to the Passport at step 11, after execution succeeds. A policy denial at step 9 discards the signed entry without propagating it.

**Why archived:** This was never a deviation. The compliance matrix has been updated to ✅. No code change needed, no test gap.

---

## T-07: OPA Hot-Reload (archived 2026-04-11 — now a standard feature)

**Originally logged as:** A gotcha requiring `docker compose restart opa` after every `.rego` edit.

**Resolution:** `--watch /policies` flag added to the OPA container in `docker-compose.yml`. OPA now auto-reloads within ~1 second of any `.rego` file change. No container restart required.

**Why archived:** This is no longer a gotcha — it's standard behaviour of the lab. Any agent starting fresh will simply observe that OPA hot-reloads automatically and will not be confused by it. The `--watch` flag is visible in `docker-compose.yml`.

---

## L-04 (original): OTel Baggage Propagation Via `_LAB_BAGGAGE_STORE` (archived 2026-04-11 — partially superseded)

**Originally logged as:** `_LAB_BAGGAGE_STORE` (the in-memory global dict keyed by trace_id in `ext.py`) was the secondary propagation channel because OTel baggage was observed to drop values across async context switches in the lab.

**What changed (R-02, 2026-04-11):** `_get_baggage()` in `decorators.py` was refactored to read exclusively from `baggage.get_baggage()` (OTel context). The `_LAB_BAGGAGE_STORE` dict is now **only** used by `KestHttpxInterceptor` for outbound propagation — it is no longer read by any core baggage accessor.

**Why archived:** The original warning ("do not rely on `_LAB_BAGGAGE_STORE` in production") still applies to the interceptor, but its scope is now much narrower. The core risk (core library reading from a non-thread-safe global) is resolved. See R-02 in LEARNINGS.md for the current state.

---

## B-01: Policy Decision Cache — Cross-Request Identity Collision (archived 2026-04-11)

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

---

## B-02: Claim Check Test Using Compressible Data (archived 2026-04-11)

**Component:** `showcase/kest-lab/tests/test_claim_check_live.py`  
**Spec reference:** F-CP-04 / F-CP-05  
**Symptom:** After Fix 3 (zlib compression of baggage), the test `test_live_claim_check_rehydration` began passing through the compression path instead of the claim-check path. The test asserted `kest.claim_check` was in the baggage, but the compressed string fit within 4096 bytes.  
**Root cause:** The original test used 15 identical JWS strings, which zlib compresses to near-zero due to repetition. The threshold was never breached.  
**Fix (2026-04-11):** Replaced repeated entries with `os.urandom(400)` per entry so each has a distinct, incompressible random signature. Confirmed the packed baggage reliably exceeds 4096 bytes even post-compression, forcing the claim-check path.  
**Lesson:** Any test that relies on "large passport" must use cryptographically random (incompressible) data, not repeated real-looking JWS strings which are highly regular and compress well.

---

## B-03: Cedar Policy File Missing for `allow` Policy (archived 2026-04-11)

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

---

## B-04: OTel Baggage Propagation Loss in ThreadPoolExecutor (archived 2026-04-12)

**Component:** `libs/kest-core/python/python/kest/core/decorators.py`  
**Spec reference:** F-CP-05 (baggage must propagate reliably downstream)  
**Symptom:** In the GIL-free Rust signing path, OpenTelemetry baggage (`kest.user`, `kest.agent`) was silently omitted from JWS labels. The baggage was completely lost when execution offloaded to a background thread to prevent event loop blocking. This caused `403 Forbidden` errors in downstream hops.  
**Root cause:** Python `contextvars` (which underpin OTel baggage) are thread-local and coroutine-local. `asyncio.get_running_loop().run_in_executor()` runs the target function in a bare thread without propagating the caller's context variables. Any read or write of OTel baggage inside the background thread operated with a fresh, empty context.  
**Fix (2026-04-12):** Explicitly capture the context before offloading with `cv = contextvars.copy_context()` and execute the background operation within it via `cv.run()`.  
**Lesson:** Any offloading to `ThreadPoolExecutor` or `ProcessPoolExecutor` inside a Python async context MUST explicitly pass and run within `contextvars.copy_context()` if it interacts with OpenTelemetry, tracing, or logging frameworks that rely on ContextVars.

---

## D-01: Baggage Key Naming — RESOLVED (archived 2026-04-11)

**Spec says (F-IC-05, §8.4):** JWT `sub` claim → `kest.user`; `client_id` claim → `kest.agent`; `scope` → `kest.task`.  
**Was:** `kest.principal_user`, `kest.principal_agent`, `kest.principal_scope`, `kest.principal_roles`.  
**Now:** `kest.user`, `kest.agent`, `kest.task` (spec-compliant). Kept `kest.scope` as a non-normative extension for Cedar ABAC policies that need to match the raw OAuth scope string.

---

## D-02: Compressed Baggage Variant (`kest.passport_z`) — RESOLVED (archived 2026-04-11)

**Spec said (F-CP-01–F-CP-06, §8.3):** Two baggage states: `kest.passport` (inline, ≤ 4096 bytes) and `kest.claim_check` (UUID reference when > 4096 bytes).  
**Implementation added:** A third intermediate state: `kest.passport_z` — a zlib-compressed, base64url-encoded inline Passport.  
**Resolution (2026-04-11):** `kest.passport_z` is now normative. Added to SPEC-v0.3.0.md as **F-CP-07** (produce, optional) and **F-CP-08** (consume, MUST).

---

## D-04: `LabFallbackBaggageProvider` — RESOLVED (archived 2026-04-11)

**Component:** `decorators.py` — `LabFallbackBaggageProvider` class  
**Issue:** This class uses filesystem-backed hash tracking (`last_hash_<service>.txt` files) and an in-memory global dict (`_LAB_BAGGAGE_STORE`) to compensate for OTel Baggage propagation failures in the Docker lab environment.  
**Fix (2026-04-11):** Added an `_LAB_FALLBACK_ENABLED` module-level gate controlled by the `KEST_LAB_FALLBACK` environment variable.

---

## D-05: Policy Decision Cache — RESOLVED (archived 2026-04-11)

**Issue:** The spec defines no caching of policy decisions. The `_PolicyDecisionCache` (5-second TTL, 1024 LRU entries) is a pure implementation optimization.  
**Fix (2026-04-11):** TTL is now configurable via the `KEST_POLICY_CACHE_TTL` environment variable.

---

## A-03: `Passport.accumulated_taints` and `trust_scores` Are Lazy-Cached Properties — RESOLVED (archived 2026-04-12)

**File:** `models.py` — `Passport._get_parsed_entries()`  
**Resolved (2026-04-12, eterna2/kest#12):**
- Replaced list-snapshot comparison with integer version counter.
- `accumulated_taints` now returns `frozenset` in O(1).
- `@dataclass(slots=True)` added.

---

## R-02: `LabFallbackBaggageProvider` — RESOLVED (archived 2026-04-11)

**Previous risk:** The fallback in `decorators.py` used `/workspace/app/last_hash_<service>.txt` files. Concurrent worker writes caused silent Merkle chain corruption.
**Fix:** Removed `LabFallbackBaggageProvider.get_baggage()` and `set_baggage()` from the class entirely. Introduced a module-level `_get_baggage(key)` helper in `decorators.py` that reads directly from `baggage.get_baggage()` (OTel context).

---

## R-03: Unverified JWT Decoding — RESOLVED (archived 2026-04-11)

**Previous risk:** When `jwks_uri=None`, `KestIdentityMiddleware` decoded JWTs without signature verification silently.
**Fix:** `KestIdentityMiddleware.__init__` now raises `RuntimeError` at construction time if `jwks_uri=None` AND the environment variable `KEST_INSECURE_NO_VERIFY` is not set to `true`.
