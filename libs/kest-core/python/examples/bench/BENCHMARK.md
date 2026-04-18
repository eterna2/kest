# Kest Core: Comprehensive Performance Benchmark

Measured on **2026-04-18** — kest v0.4.0-dev (Pure Python), Python 3.11, Linux.  

---

## Active Pipeline Performance (Pure Python)

Following the removal of the PyO3/Rust bindings, Kest now operates exclusively via a pure Python pipeline backed by the `rfc8785` C extension.

### L0: Core Primitive Micro-benchmarks (Single Thread)

| Benchmark | Latency (µs) |
|---|---|
| `entry_create` | 0.89 µs |
| `sign_entry` | 23.20 µs |
| `canonical_json` | 4.23 µs |
| `chain_10` | 261 µs |
| `chain_100` | 2,600 µs |

### L0: Scalability (ops/sec vs. thread count)

| Threads | `sign_entry` (ops/sec) | `verify` (5-hop) (ops/sec) |
|---|---|---|
| 1 | 15,830 | 31,283 |
| 2 | 15,925 | 31,713 |
| 4 | 16,345 | 30,667 |
| 8 | 18,237 | 34,337 |

### L0: GIL Contention (`sign_entry`)

| Metric | Throughput |
|---|---|
| Baseline (4 threads) | 15,848 ops/sec |
| Contested (+ GIL-holder) | 12,719 ops/sec |
| **Degradation** | **19.7%** |

### L1: BaggageManager Packaging

| Hops | Pack (ms) | Unpack (ms) | Raw Bytes | Packed Bytes | Tier |
|---|---|---|---|---|---|
| 1 | 0.003 | 0.008 | 829 | 829 | inline ✓ |
| 5 | 0.020 | 0.037 | 4,145 | 820 | compressed ✓ |
| 10 | 0.029 | 0.076 | 8,290 | 988 | compressed ✓ |
| 25 | 0.057 | 0.159 | 20,725 | 1,284 | compressed ✓ |
| 50 | 0.105 | 0.341 | 41,450 | 1,716 | compressed ✓ |

### L2: Decorator Overhead

| Configuration | Cold Start (ms) | Warm Hit (ms) | Overhead vs Raw |
|---|---|---|---|
| Raw function | - | 0.0001 | - |
| `@kest_verified` (Mock) | - | 0.1067 | +0.1066 ms |
| `@kest_verified` (Cedar) | 1.215 | 0.1064 | +0.1064 ms |
| `@kest_verified` (Rego) | 1.744 | 0.1094 | +0.1093 ms |

### L3: Policy Engine Scalability (4 threads)

| Engine | ops/sec |
|---|---|
| Cedar (in-process) | 20,511 |
| `sign_entry` | 16,884 |

### L4: Multi-hop End-to-End Latency

| Hops | Total Latency (ms) | Per-hop Latency (ms) |
|---|---|---|
| 3 | 0.299 | 0.100 |
| 5 | 0.505 | 0.101 |
| 10 | 1.423 | 0.142 |


---

## [Historical] Rust vs Python Backend Comparison (Pre-0.4.0)

> [!NOTE]
> The following results reflect historical tests capturing the performance differential between the pure python implementation and the legacy PyO3/Rust and active Rust multi-threading extensions. They are preserved for architectural context on why the GIL-release in Rust bounds didn't significantly outperform python-level C extensions (`rfc8785`) for typical signing paths.


## Overview: Backend Comparison

Kest supports two runtime backends selected via `KEST_BACKEND` environment variable or `set_backend()`:

| Backend | How it works | Use case |
|---|---|---|
| `rust` (default) | PyO3 compiled extension; canonicalization runs in native Rust with GIL released | Production |
| `rust-v2` | FFI-Optimized PyO3 extension; entirely GIL-free pipeline parsing | Next-Gen Production |
| `python` | Pure-Python fallback using `rfc8785` | Portability, sdist, no Rust toolchain |

> For the full rationale, see the [README Performance section](../../README.md#performance).

---

## L0: Core Primitive Benchmarks

### Micro-benchmarks (single thread, pyperf calibrated)

| Benchmark | Rust (µs) | Rust v2 (µs) | Python (µs) | Speedup |
|---|---|---|---|---|
| `entry_create` | 0.80 | 0.83 | 0.81 | ~1.0x |
| `sign_entry` | 24.70 | 22.30 | 24.70 | ~1.0x |
| `canonical_json` | 3.89 | 4.01 | 3.98 | ~1.0x |
| `chain_10` | 276 | 248 | 281 | ~1.05x |
| `chain_100` | 2,790 | 2,490 | 2,790 | ~1.1x |

> Single-threaded latency is virtually identical. The difference emerges under concurrency.

### Scalability: sign_entry (ops/sec vs. thread count)

| Threads | Rust (ops/sec) | Rust v2 (ops/sec) | Python (ops/sec) | Winner |
|---|---|---|---|---|
| 1 | 9,158 | 7,840 | 16,608 | Python (1.8x) |
| 2 | 16,941 | 14,179 | 16,397 | ~parity |
| 4 | 13,852 | 11,747 | 16,480 | Python +19% |
| 8 | 12,945 | 11,330 | 17,319 | Python +34% |

> **Interpretation**: With GIL release added to Rust canonicalization, the expected advantage did not materialise because
> the Python `sign_payload` callback (Ed25519 via OpenSSL) dominates wall time and holds the GIL briefly in both paths.
> The Python backend's `rfc8785` C extension has less fragmented GIL usage, causing fewer context switches.

### Scalability: PassportVerifier.verify (ops/sec vs. thread count)

| Threads | Rust (ops/sec) | Rust v2 (ops/sec) | Python (ops/sec) |
|---|---|---|---|
| 1 | 27,582 | 33,742 | 29,632 |
| 2 | 28,630 | 33,492 | 29,802 |
| 4 | 29,190 | 32,793 | 28,615 |
| 8 | 29,803 | 34,823 | 28,239 |

> `verify` is pure Python for both backends — confirming both hit the same GIL-bound ceiling. This motivates a future `verify_passport` Rust extension.

### GIL Contention: sign_entry (4 threads + CPU-bound background thread)

| Metric | Rust | Rust v2 | Python |
|---|---|---|---|
| Baseline ops/sec (4 threads) | 13,868 | 11,804 | 15,625 |
| Contested ops/sec (+ GIL-holder) | 806 | 830 | 12,521 |
| **Degradation** | **94.2%** | **92.9%** | **19.9%** |

> **Key finding**: The **Rust backend degrades 94%** under GIL contention, far worse than the Python backend's 20%. 
> The PyO3 boundary (cloning the Rust struct, constructing PyBytes, calling into Python) creates a pattern where
> the Rust thread yields the GIL frequently, making it highly sensitive to other GIL-hungry threads.
> The Python backend's `rfc8785` C extension and OpenSSL calls are less fragmented in their GIL usage, causing fewer context switches.
>
> **Action item**: Investigate moving the Ed25519 signing step to a pure-Rust provider so the entire `sign_entry` path
> can be GIL-free, rather than only the canonicalization. *(Tracked as Fix 5 — deferred.)*

### Payload Size Sensitivity: sign_entry (single thread)

| Entry size | Labels | Rust (ops/sec) | Rust v2 (ops/sec) | Python (ops/sec) |
|---|---|---|---|---|
| Small | 4 | 9,242 | 7,831 | 16,364 |
| Medium | 20 | 6,386 | 5,389 | 13,140 |
| Large | 100 | 2,296 | 1,859 | 6,661 |

### Memory Allocation per Call

| Operation | Rust (bytes) | Rust v2 (bytes) | Python (bytes) |
|---|---|---|---|
| sign_entry | 4,871 | 3,731 | 7,930 |
| verify (5-hop passport) | 10,237 | 9,057 | 10,124 |

---

## ✅ L1: Baggage — Compression Fix Applied

**Previous behaviour**: Claim-check threshold crossed at hop 3. Any service mesh with ≥ 3 hops
required a distributed cache backend on every request. Without one, the passport was silently dropped.

**Fix 3 (zlib level-1 compression)**: Three-tier pack strategy — plain JSON → compressed → claim-check.

### Post-fix results (Rust backend, identical on Python)

| Hops | Raw bytes | Packed bytes | pack (ms) | unpack (ms) | Tier |
|---|---|---|---|---|---|
| 1 | 1,775 | 1,775 | 0.005 | 0.003 | inline ✓ |
| 5 | 8,875 | 1,672 | 0.042 | 0.018 | compressed ✓ |
| 10 | 17,750 | 1,916 | 0.052 | 0.035 | compressed ✓ |
| 25 | 44,375 | 3,268 | 0.185 | 0.081 | compressed ✓ |
| 50 | 88,750 | 3,840 | 0.192 | 0.111 | compressed ✓ |

> ✅ **No claim-check triggered up to hop 50.** Compression achieves 95%+ reduction on typical JWS passport data.
> The plain inline threshold still crosses at hop 3 (5,325 raw bytes), but zlib reduces 8,875 bytes to 1,672 — well under 4,096.
> 
> Compression cost is ~10µs for a 50-hop passport (well within single-hop latency budget).

---

## L2: Decorator Overhead

**Fix 2 (policy decision cache, 5s TTL)**: Policy evaluation results are cached per `(principal, trust_score, classification, policies)` tuple.

| Configuration | Cold (first call) | Warm (cache hit) | Overhead vs. raw (warm) |
|---|---|---|---|
| Raw function (baseline) | 0.0001 ms | 0.0001 ms | — |
| `@kest_verified` (Mock, Rust) | — | 0.184 ms | +0.184 ms |
| `@kest_verified` (Mock, Rust v2) | — | 0.390 ms | +0.390 ms |
| `@kest_verified` (Cedar, Rust) | 1.348 ms | 0.321 ms | +0.321 ms |
| `@kest_verified` (Cedar, Rust v2) | 1.458 ms | 0.469 ms | +0.469 ms |
| `@kest_verified` (Rego, Rust) | 1.983 ms | 0.196 ms | +0.196 ms |
| `@kest_verified` (Rego, Rust v2) | 2.072 ms | 0.836 ms | +0.836 ms |

> - **Cold path**: Cedar initialises the Cedar VM on first call (JIT compilation), taking ~56ms. This is a one-time cost at process startup. Rego cold start is ~6ms.
> - **Warm path**: With the policy decision cache, repeated calls to the same decorated function by the same principal reduce policy evaluation cost from ~0.6ms to essentially zero. At 10K RPS with the same workload identity, Cedar evaluation drops from 6M eval calls/min to only ~500 (cache misses on TTL expiry).
> - **Net decorator overhead (warm)**: ~0.18ms — dominated by Ed25519 signing + baggage packing.

### Scalability: L2 Decorator Throughput (Realistic Evaluation)

This tests the full `@kest_verified` decorator lifecycle, including automatic OTel Context/Baggage extraction, payload mapping, and real-world evaluation overhead using `CedarLocalEngine` executing policy: `context.role == "admin"`.

**Performance:**

| Threads | `python` (ops/sec) | `rust` (V1) (ops/sec) | `rust-v2` (ops/sec) |
|---|---|---|---|
| 1 | ~8506 | ~4102 | ~2026 |
| 2 | ~6558 | ~4519 | ~1913 |
| 4 | ~8084 | ~4197 | ~1937 |
| 8 | ~6529 | ~4355 | ~2031 |

> **Interpretation**: 
> - **Python**: Best baseline single-thread throughput since `CedarLocalEngine`, context mapping, and identity packing are fully executed within the interpreter without serialization overhead. However, throughput is erratic and drops up to 25% under concurrency due to GIL contention.
> - **Rust (V1)**: The Python FFI overhead + OTel tracing boundary extraction causes a significant 50% penalty off the Python baseline.
> - **Rust-v2**: Throughput is lowest (~2000 ops/sec) due to deep payload conversion into `HashMap<String, String>` and context wrapping. However, scaling remains highly stable (flatline), proving the background-thread GIL release eliminates contention, making it the most reliable engine for high-concurrency systems despite the serialization baseline tax.

### FastAPI Endpoint Concurrency (Up to 32 threads)

This assesses Kest's overhead when decorated on standard API routes served by `FastAPI` + `uvicorn` (on a single event loop). It compares `async def` routes (where validation happens on the main event loop) vs `def` routes (where FastAPI pushes execution to a threadpool).

**Sync Endpoint (`def` route -> AnyIO Threadpool)**:

| Threaded Requests | `python` (ops/sec) | `rust` (V1) (ops/sec) | `rust-v2` (ops/sec) |
|---|---|---|---|
| 1 | ~614.7 | ~552.3 | ~580.0 |
| 4 | ~481.7 | ~461.0 | ~476.7 |
| 8 | ~339.3 | ~341.0 | ~337.7 |
| 16 | ~265.3 | ~264.0 | ~255.3 |
| 32 | ~262.3 | ~259.3 | ~259.0 |

**Async Endpoint (`async def` route -> Event Loop)**:

| Concurrent Tasks | `python` (ops/sec) | `rust` (V1) (ops/sec) | `rust-v2` (ops/sec) |
|---|---|---|---|
| 1 | ~552.7 | ~528.3 | ~532.0 |
| 4 | ~509.0 | ~481.3 | ~469.3 |
| 8 | ~355.3 | ~347.3 | ~348.3 |
| 16 | ~290.3 | ~275.3 | ~261.7 |
| 32 | ~264.3 | ~263.7 | ~252.0 |

> **Interpretation:** Throughput identically degrades across all backends as concurrency approaches 32 on a single worker server. This signifies that at this layer, ASGI/Event-loop context switching and AnyIO thread-swapping boundaries are the primary bottleneck—not the cryptographic signing or PyO3/GIL constraints—because Kest execution overhead per-request (~0.5ms) is negligible relative to the HTTP framing/event-loop dispatch time.

---

## L3: Policy Engine Throughput (4 threads)

| Engine | ops/sec |
|---|---|
| Rego (in-process) | 628,319 |
| Cedar (in-process) | 20,471 |
| sign_entry (4 threads) | 14,861 |

> Rego throughput is ~30x higher than Cedar at 4 threads. Cedar's throughput matches signing latency —
> at high concurrency, Cedar becomes the combined bottleneck with signing. Rego is unambiguously the higher-throughput in-process option.

---

## L4: Multi-hop End-to-End

| Hops | Total (ms) | Per-hop (ms) |
|---|---|---|
| 3 | 0.419 | 0.140 |
| 5 | 0.799 | 0.160 |
| 10 | 1.852 | 0.185 |

> Per-hop latency increases slightly with chain length due to growing passport size (O(n) serialization).
> However, because L1 compression now handles 50-hop passports inline, there is no cliff at hop 3 (no cache required).

### Passport Merge Overhead

| Input passports | merge (ms) |
|---|---|
| 2 | 0.0008 |
| 5 | 0.0015 |
| 10 | 0.0028 |

---

## Summary: Production Throughput Projection

Assuming SPIRE + Cedar + 10-hop service mesh at 10K RPS:

| Metric | Before Fixes | After Fixes | Change |
|---|---|---|---|
| Cache backend required at hop | 3 | >50 | ✅ Eliminated for typical workloads |
| Cedar eval calls/min @ 10K RPS | 600,000 | ~500 | ✅ -99.9% (cache hits) |
| SVID socket fetch/call | 1 (5ms) | 0 (cached 5 min) | ✅ Eliminated |
| Per-call overhead (warm) | ~0.8ms | ~0.18ms | ✅ -77% |
| Event loop blocked (async) | Yes (signing) | No (to_thread) | ✅ Fixed |
| GIL degradation (Rust / Rust v2, 4thr) | 94% | 94% | ⚠ Unresolved (Fix 5 deferred) |

---


---

## Reproducing Results

### Prerequisites
```bash
uv sync --all-extras
```

### Running
```bash
moon run kest-core-python:bench
```

Or manually run the active (pure Python) backend benchmarks:
```bash
cd libs/kest-core/python

# L0: pyperf micro-benchmarks
uv run python examples/bench/bench_kest_core.py -o examples/bench/python.json

# L0: GIL-aware throughput
uv run python examples/bench/bench_throughput.py

# L1–L4: System benchmarks
uv run python examples/bench/bench_system.py
```

> [!NOTE]
> Historical benchmark reproducer instructions for the deprecated `rust` and `rust-v2` backends have been removed following their decommissioning.

## Raw Data

> [!NOTE] 
> Raw `.json` and `.txt` artifacts are now ignored by git to keep the repository clean. The tables above preserve the full historical comparison between the `python`, `rust`, and `rust-v2` bindings.

| File | Contents |
|---|---|
| `python.json` | pyperf results, Python backend |
| `throughput_python.json` | L0 threading results, Python backend |
| `system_python.json` | L1–L4 system results, Python backend |
| `decorator_throughput_python.json` | L2 decorator throughput, Python backend |
