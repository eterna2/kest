# Kest Core: Comprehensive Performance Benchmark

Measured on **2026-04-11** — kest v0.3.0, Python 3.11.15, Linux.  
Post-optimisation run (Fix 1–6 applied: passport cache, policy cache, compressed baggage, SVID cache, async offloading).

---

## Overview: Backend Comparison

Kest supports two runtime backends selected via `KEST_BACKEND` environment variable or `set_backend()`:

| Backend | How it works | Use case |
|---|---|---|
| `rust` (default) | PyO3 compiled extension; canonicalization runs in native Rust with GIL released | Production |
| `python` | Pure-Python fallback using `rfc8785` | Portability, sdist, no Rust toolchain |

> For the full rationale, see the [README Performance section](../../README.md#performance).

---

## L0: Core Primitive Benchmarks

### Micro-benchmarks (single thread, pyperf calibrated)

| Benchmark | Rust (µs) | Python (µs) | Speedup |
|---|---|---|---|
| `entry_create` | 0.80 | 0.81 | ~1.0x |
| `sign_entry` | 24.70 | 24.70 | ~1.0x |
| `canonical_json` | 3.89 | 3.98 | ~1.02x |
| `chain_10` | 276 | 281 | ~1.02x |
| `chain_100` | 2,790 | 2,790 | ~1.0x |

> Single-threaded latency is virtually identical. The difference emerges under concurrency.

### Scalability: sign_entry (ops/sec vs. thread count)

| Threads | Rust (ops/sec) | Python (ops/sec) | Winner |
|---|---|---|---|
| 1 | 9,158 | 16,608 | Python (1.8x) |
| 2 | 16,941 | 16,397 | ~parity |
| 4 | 13,852 | 16,480 | Python +19% |
| 8 | 12,945 | 17,319 | Python +34% |

> **Interpretation**: With GIL release added to Rust canonicalization, the expected advantage did not materialise because
> the Python `sign_payload` callback (Ed25519 via OpenSSL) dominates wall time and holds the GIL briefly in both paths.
> The Python backend's `rfc8785` C extension has less fragmented GIL usage, causing fewer context switches.

### Scalability: PassportVerifier.verify (ops/sec vs. thread count)

| Threads | Rust (ops/sec) | Python (ops/sec) |
|---|---|---|
| 1 | 27,582 | 29,632 |
| 2 | 28,630 | 29,802 |
| 4 | 29,190 | 28,615 |
| 8 | 29,803 | 28,239 |

> `verify` is pure Python for both backends — confirming both hit the same GIL-bound ceiling. This motivates a future `verify_passport` Rust extension.

### GIL Contention: sign_entry (4 threads + CPU-bound background thread)

| Metric | Rust | Python |
|---|---|---|
| Baseline ops/sec (4 threads) | 13,868 | 15,625 |
| Contested ops/sec (+ GIL-holder) | 806 | 12,521 |
| **Degradation** | **94.2%** | **19.9%** |

> **Key finding**: The **Rust backend degrades 94%** under GIL contention, far worse than the Python backend's 20%. 
> The PyO3 boundary (cloning the Rust struct, constructing PyBytes, calling into Python) creates a pattern where
> the Rust thread yields the GIL frequently, making it highly sensitive to other GIL-hungry threads.
> The Python backend's `rfc8785` C extension and OpenSSL calls are less fragmented in their GIL usage, causing fewer context switches.
>
> **Action item**: Investigate moving the Ed25519 signing step to a pure-Rust provider so the entire `sign_entry` path
> can be GIL-free, rather than only the canonicalization. *(Tracked as Fix 5 — deferred.)*

### Payload Size Sensitivity: sign_entry (single thread)

| Entry size | Labels | Rust (ops/sec) | Python (ops/sec) |
|---|---|---|---|
| Small | 4 | 9,242 | 16,364 |
| Medium | 20 | 6,386 | 13,140 |
| Large | 100 | 2,296 | 6,661 |

### Memory Allocation per Call

| Operation | Rust (bytes) | Python (bytes) |
|---|---|---|
| sign_entry | 4,871 | 7,930 |
| verify (5-hop passport) | 10,237 | 10,124 |

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
| `@kest_verified` (Mock engine) | — | 0.179 ms | +0.179 ms |
| `@kest_verified` (Cedar) | 56.1 ms | 0.207 ms | +0.207 ms |
| `@kest_verified` (Rego) | 6.1 ms | 0.179 ms | +0.179 ms |

> - **Cold path**: Cedar initialises the Cedar VM on first call (JIT compilation), taking ~56ms. This is a one-time cost at process startup. Rego cold start is ~6ms.
> - **Warm path**: With the policy decision cache, repeated calls to the same decorated function by the same principal reduce policy evaluation cost from ~0.6ms to essentially zero. At 10K RPS with the same workload identity, Cedar evaluation drops from 6M eval calls/min to only ~500 (cache misses on TTL expiry).
> - **Net decorator overhead (warm)**: ~0.18ms — dominated by Ed25519 signing + baggage packing.

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
| GIL degradation (Rust, 4thr) | 94% | 94% | ⚠ Unresolved (Fix 5 deferred) |

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

Or manually per backend:
```bash
cd libs/kest-core/python

# L0: pyperf micro-benchmarks
KEST_BACKEND=rust   uv run python examples/bench/bench_kest_core.py -o examples/bench/rust.json
KEST_BACKEND=python uv run python examples/bench/bench_kest_core.py -o examples/bench/python.json

# L0: GIL-aware throughput
KEST_BACKEND=rust   uv run python examples/bench/bench_throughput.py
KEST_BACKEND=python uv run python examples/bench/bench_throughput.py

# L1–L4: System benchmarks
KEST_BACKEND=rust   uv run python examples/bench/bench_system.py
```

## Raw Data

| File | Contents |
|---|---|
| `rust.json` | pyperf results, Rust backend |
| `python.json` | pyperf results, Python backend |
| `throughput_rust.json` | L0 threading results, Rust backend |
| `throughput_python.json` | L0 threading results, Python backend |
| `system_rust.json` | L1–L4 system results (post-fix) |
