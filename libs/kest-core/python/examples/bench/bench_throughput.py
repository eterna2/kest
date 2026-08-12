"""
bench_throughput.py — L0 GIL-aware throughput benchmarks for kest-core.

Covers:
  - Scalability: sign_entry under N threads (1, 2, 4, 8)
  - Scalability: PassportVerifier.verify under N threads
  - GIL contention: sign_entry with a CPU-bound GIL-holder background thread
  - Payload size sensitivity: sign_entry with small/medium/large KestEntry
  - Memory allocation: tracemalloc peak per sign/verify call

Usage:
    KEST_BACKEND=rust   uv run python examples/bench/bench_throughput.py
    KEST_BACKEND=python uv run python examples/bench/bench_throughput.py
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import threading
import time
import tracemalloc
from typing import Any

# Allow running from the bench directory or from the project root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from kest.core import (
    KestEntry,
    sign_entry,
    LocalEd25519Provider,
    Passport,
    PassportVerifier,
)

PROVIDER = LocalEd25519Provider()
THREAD_COUNTS = [1, 2, 4, 8]
WINDOW_SECS = 3
BACKEND = "python"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(n_labels: int = 4) -> KestEntry:
    """Create a KestEntry with n_labels labels to control payload size."""
    labels = {f"key_{i}": f"value_{i}" for i in range(n_labels)}
    return KestEntry(
        entry_id="bench-entry",
        operation="benchmark",
        classification="system",
        parent_ids=[],
        trust_score=100,
        labels=labels,
    )


def _build_passport(chain_length: int = 10) -> Passport:
    """Build a pre-signed passport with chain_length entries."""
    passport = Passport()
    for i in range(chain_length):
        entry = _make_entry()
        jws = sign_entry(entry, PROVIDER)
        passport.add_signature(jws)
    return passport


def _throughput(fn, n_threads: int, window: float = WINDOW_SECS) -> float:
    """Run fn in n_threads threads for window seconds, return ops/sec."""
    stop = threading.Event()
    counter = [0]
    lock = threading.Lock()

    def worker():
        while not stop.is_set():
            fn()
            with lock:
                counter[0] += 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_threads) as pool:
        futs = [pool.submit(worker) for _ in range(n_threads)]
        time.sleep(window)
        stop.set()
        concurrent.futures.wait(futs)

    return counter[0] / window


# ---------------------------------------------------------------------------
# Benchmark: Scalability — sign
# ---------------------------------------------------------------------------


def bench_sign_scalability():
    entry = _make_entry(4)

    print("\n## Scalability: sign_entry")
    print(f"{'Threads':>8} | {'ops/sec':>10}")
    print("-" * 25)
    results = {}
    for n in THREAD_COUNTS:
        ops = _throughput(lambda: sign_entry(entry, PROVIDER), n)
        results[n] = ops
        print(f"{n:>8} | {ops:>10.1f}")
    return results


# ---------------------------------------------------------------------------
# Benchmark: Scalability — verify
# ---------------------------------------------------------------------------


def bench_verify_scalability():
    passport = _build_passport(5)
    providers = {PROVIDER.get_identity(): PROVIDER}

    print("\n## Scalability: PassportVerifier.verify (5-entry passport)")
    print(f"{'Threads':>8} | {'ops/sec':>10}")
    print("-" * 25)
    results = {}
    for n in THREAD_COUNTS:
        ops = _throughput(lambda: PassportVerifier.verify(passport, providers), n)
        results[n] = ops
        print(f"{n:>8} | {ops:>10.1f}")
    return results


# ---------------------------------------------------------------------------
# Benchmark: GIL Contention
# ---------------------------------------------------------------------------


def bench_gil_contention():
    entry = _make_entry(4)
    n_sign_threads = 4

    def baseline():
        return _throughput(lambda: sign_entry(entry, PROVIDER), n_sign_threads)

    # CPU-bound GIL-holder: pure Python loop
    def gil_burner():
        x = 0
        while not gil_stop.is_set():
            x = sum(range(10_000))  # noqa: F841

    print("\n## GIL Contention: sign_entry (4 threads) vs. CPU-bound background thread")

    baseline_ops = baseline()

    gil_stop = threading.Event()
    t = threading.Thread(target=gil_burner, daemon=True)
    t.start()
    contested_ops = _throughput(lambda: sign_entry(entry, PROVIDER), n_sign_threads)
    gil_stop.set()
    t.join()

    degradation = (baseline_ops - contested_ops) / baseline_ops * 100
    print(f"  Baseline ops/sec : {baseline_ops:>10.1f}")
    print(f"  Contested ops/sec: {contested_ops:>10.1f}")
    print(f"  Degradation      : {degradation:>10.1f}%")
    return {
        "baseline": baseline_ops,
        "contested": contested_ops,
        "degradation_pct": degradation,
    }


# ---------------------------------------------------------------------------
# Benchmark: Payload Size Sensitivity
# ---------------------------------------------------------------------------


def bench_payload_size():
    configs = [
        ("small", 4),
        ("medium", 20),
        ("large", 100),
    ]

    print("\n## Payload Size Sensitivity: sign_entry (single thread)")
    print(f"{'Size':>8} | {'labels':>7} | {'ops/sec':>10}")
    print("-" * 32)
    results = {}
    for name, n_labels in configs:
        entry = _make_entry(n_labels)
        ops = _throughput(lambda: sign_entry(entry, PROVIDER), 1)
        results[name] = ops
        print(f"{name:>8} | {n_labels:>7} | {ops:>10.1f}")
    return results


# ---------------------------------------------------------------------------
# Benchmark: Memory Allocation
# ---------------------------------------------------------------------------


def bench_memory():
    entry = _make_entry(4)
    passport_5 = _build_passport(5)
    providers = {PROVIDER.get_identity(): PROVIDER}

    # Sign
    tracemalloc.start()
    tracemalloc.reset_peak()
    sign_entry(entry, PROVIDER)
    _, sign_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Verify
    tracemalloc.start()
    tracemalloc.reset_peak()
    PassportVerifier.verify(passport_5, providers)
    _, verify_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print("\n## Memory Allocation per Operation")
    print(f"  sign_entry peak  : {sign_peak:>8,} bytes")
    print(f"  verify (5 hops) peak: {verify_peak:>8,} bytes")
    return {"sign_peak_bytes": sign_peak, "verify_peak_bytes": verify_peak}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"# Kest Throughput Benchmark — backend={BACKEND}")
    print(f"  Window: {WINDOW_SECS}s per test | Threads tested: {THREAD_COUNTS}")

    results: dict[str, Any] = {"backend": BACKEND}
    results["sign_scalability"] = bench_sign_scalability()
    results["verify_scalability"] = bench_verify_scalability()
    results["gil_contention"] = bench_gil_contention()
    results["payload_sensitivity"] = bench_payload_size()
    results["memory"] = bench_memory()

    out = f"examples/bench/throughput_{BACKEND}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out}")
