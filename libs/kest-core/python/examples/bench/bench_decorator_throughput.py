"""
bench_decorator_throughput.py — Throughput benchmarks for @kest_verified across backends.

Benchmarks the full decorator lifecycle:
  1. Context mapping
  2. Baggage unpacking
  3. Policy evaluation (Mock)
  4. Audit entry signing
  5. Baggage packing

Usage:
    KEST_BACKEND=rust   uv run python examples/bench/bench_decorator_throughput.py
    KEST_BACKEND=rust-v2 uv run python examples/bench/bench_decorator_throughput.py
    KEST_BACKEND=python uv run python examples/bench/bench_decorator_throughput.py
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import threading
import time
from typing import Any

# Allow running from the bench directory or from the project root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from kest.core import get_backend, configure, PolicyEngine, LocalEd25519Provider

# Configure the right decorator based on backend
BACKEND = get_backend()
if BACKEND == "rust-v2":
    from kest.core.decorators_v2 import kest_verified
else:
    from kest.core import kest_verified

PROVIDER = LocalEd25519Provider()
THREAD_COUNTS = [1, 2, 4, 8]
WINDOW_SECS = 3

class MockPolicyEngine(PolicyEngine):
    def evaluate(self, entry_id: str, policy_names: list[str], context: dict) -> bool:
        return True

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
# Benchmarks
# ---------------------------------------------------------------------------

@kest_verified("allow-all")
def target_function(x: int):
    return x + 1

def bench_decorator_throughput():
    configure(engine=MockPolicyEngine(), identity=PROVIDER)

    print(f"\n## Scalability: @kest_verified ({BACKEND})")
    print(f"{'Threads':>8} | {'ops/sec':>10}")
    print("-" * 25)
    
    results = {}
    for n in THREAD_COUNTS:
        # Warmup
        target_function(1)
        
        ops = _throughput(lambda: target_function(1), n)
        results[n] = ops
        print(f"{n:>8} | {ops:>10.1f}")
    return results

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"# Kest Decorator Throughput Benchmark — backend={BACKEND}")
    print(f"  Window: {WINDOW_SECS}s per test | Threads tested: {THREAD_COUNTS}")

    results: dict[str, Any] = {"backend": BACKEND}
    results["decorator_throughput"] = bench_decorator_throughput()

    out = f"examples/bench/decorator_throughput_{BACKEND}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out}")
