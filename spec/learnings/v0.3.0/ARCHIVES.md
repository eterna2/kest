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
