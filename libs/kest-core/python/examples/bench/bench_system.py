"""
bench_system.py — L1–L4 system-level benchmarks for kest-core.

Covers:
  L1 - BaggageManager: pack/unpack latency & size vs. chain length
  L2 - Decorator: @kest_verified overhead (no-policy, Cedar, Rego)
  L3 - Policy Engine: Cedar vs. Rego decision rate under threading
  L4 - Multi-hop: end-to-end simulate N service hops
  L4 - Passport merge overhead

Usage:
    KEST_BACKEND=rust   uv run python examples/bench/bench_system.py
    KEST_BACKEND=python uv run python examples/bench/bench_system.py
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import threading
import time
import timeit
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from kest.core import (
    CedarLocalEngine,
    KestEntry,
    MockPolicyEngine,
    RegoLocalEngine,
    configure,
    get_backend,
    kest_verified,
    sign_entry,
)
from kest.core.identity.providers.local import LocalEd25519Provider
from kest.core.models import BaggageManager, Passport

PROVIDER = LocalEd25519Provider()
BACKEND = get_backend()

if BACKEND == "rust-v2":
    from kest.core.decorators_v2 import kest_verified

REPS = 100
CHAIN_LENGTHS = [1, 5, 10, 25, 50]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry() -> KestEntry:
    return KestEntry(
        entry_id="bench",
        operation="bench-op",
        classification="system",
        parent_ids=[],
        trust_score=100,
    )


def _build_passport(n: int) -> Passport:
    p = Passport()
    for _ in range(n):
        jws = sign_entry(_make_entry(), PROVIDER)
        p.add_signature(jws)
    return p


def _timeit_ms(fn, reps: int = REPS) -> float:
    """Return mean latency in ms over reps repetitions."""
    t = timeit.timeit(fn, number=reps)
    return (t / reps) * 1000


def _throughput(fn, n_threads: int, window: float = 3.0) -> float:
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
# L1: Baggage pack / unpack vs. chain length
# ---------------------------------------------------------------------------


def bench_l1_baggage():
    print("\n## L1: BaggageManager pack/unpack latency vs. chain length")
    print(
        f"{'Hops':>6} | {'pack (ms)':>10} | {'unpack (ms)':>12} | {'raw bytes':>10} | {'packed bytes':>12} | {'tier':>12}"
    )
    print("-" * 80)

    results = {}
    for n in CHAIN_LENGTHS:
        passport = _build_passport(n)
        raw_size = len(passport.serialize().encode())
        packed = BaggageManager.pack(passport)
        packed_val = packed.get("kest.passport_z") or packed.get("kest.passport") or ""
        packed_size = len(packed_val.encode()) if packed_val else 0

        if "kest.claim_check" in packed:
            tier = "claim-check 🔁"
        elif "kest.passport_z" in packed:
            tier = "compressed ✓"
        else:
            tier = "inline ✓"

        pack_ms = _timeit_ms(lambda p=passport: BaggageManager.pack(p))

        def _unpack(b=packed):
            BaggageManager.unpack(lambda k: b.get(k))

        unpack_ms = _timeit_ms(_unpack)

        print(
            f"{n:>6} | {pack_ms:>10.3f} | {unpack_ms:>12.3f} | "
            f"{raw_size:>10,} | {packed_size:>12,} | {tier:>12}"
        )
        results[n] = {
            "pack_ms": pack_ms,
            "unpack_ms": unpack_ms,
            "raw_bytes": raw_size,
            "packed_bytes": packed_size,
            "tier": tier,
        }

    # Confirm the exact hop where each tier boundary is crossed
    p = Passport()
    plain_crossed = False
    compress_crossed = False
    for i in range(max(CHAIN_LENGTHS)):
        jws = sign_entry(_make_entry(), PROVIDER)
        p.add_signature(jws)
        sz = len(p.serialize().encode())
        packed_i = BaggageManager.pack(p)
        if not plain_crossed and sz > BaggageManager.MAX_BAGGAGE_SIZE:
            print(
                f"\n  ℹ  Plain inline threshold crossed at hop {i + 1} ({sz:,} raw bytes)"
            )
            plain_crossed = True
        if not compress_crossed and "kest.claim_check" in packed_i:
            print(f"  ⚠  Claim-check triggered at hop {i + 1} ({sz:,} raw bytes)")
            compress_crossed = True
            results["claim_check_at_hop"] = i + 1
            break
    if not compress_crossed:
        print(
            f"  ✅ No claim-check triggered up to hop {max(CHAIN_LENGTHS)} (compression sufficient)"
        )
        results["claim_check_at_hop"] = None

    return results


# ---------------------------------------------------------------------------
# L2: @kest_verified decorator overhead
# ---------------------------------------------------------------------------


def bench_l2_decorator():
    print(
        "\n## L2: @kest_verified decorator overhead (cold = first call, warm = cache hit)"
    )
    from kest.core.decorators import invalidate_policy_cache

    results = {}

    def raw_fn(x: int) -> int:
        return x

    baseline_ms = _timeit_ms(lambda: raw_fn(1))
    print(f"  Raw function (baseline)  : {baseline_ms:.4f} ms")
    results["baseline_ms"] = baseline_ms

    # No policy (MockPolicyEngine always allows) — warm only (no network/eval path)
    configure(identity=PROVIDER, engine=MockPolicyEngine())
    invalidate_policy_cache()

    @kest_verified(policy="allow")
    def no_policy_fn(x: int) -> int:
        return x

    no_policy_fn(1)  # warmup
    no_policy_ms = _timeit_ms(lambda: no_policy_fn(1))
    overhead = no_policy_ms - baseline_ms
    print(
        f"  @kest_verified (Mock)    : {no_policy_ms:.4f} ms  (+{overhead:.4f} ms overhead)"
    )
    results["no_policy_ms"] = no_policy_ms

    # Cedar (in-process) — cold vs warm
    try:
        cedar_engine = CedarLocalEngine(
            policies={'kest::Action::"allow"': "permit(principal, action, resource);"},
            entities=[],
        )
        configure(identity=PROVIDER, engine=cedar_engine)
        invalidate_policy_cache()

        @kest_verified(policy="allow")
        def cedar_fn(x: int) -> int:
            return x

        # Cold (cache miss — Cedar evaluates)
        t0 = time.perf_counter()
        cedar_fn(1)
        cedar_cold_ms = (time.perf_counter() - t0) * 1000

        # Warm (cache hit — no Cedar eval)
        cedar_warm_ms = _timeit_ms(lambda: cedar_fn(1))
        print(
            f"  @kest_verified (Cedar)   : cold={cedar_cold_ms:.3f} ms, "
            f"warm={cedar_warm_ms:.4f} ms  (+{cedar_warm_ms - baseline_ms:.4f} ms overhead)"
        )
        results["cedar_cold_ms"] = cedar_cold_ms
        results["cedar_warm_ms"] = cedar_warm_ms
    except Exception as e:
        print(f"  Cedar: skipped ({e})")

    # Rego (in-process) — cold vs warm
    try:
        REGO = "package kest.allow\ndefault allow := true"
        rego_engine = RegoLocalEngine(policies={"kest/allow": REGO})
        configure(identity=PROVIDER, engine=rego_engine)
        invalidate_policy_cache()

        @kest_verified(policy="kest/allow")
        def rego_fn(x: int) -> int:
            return x

        # Cold
        t0 = time.perf_counter()
        rego_fn(1)
        rego_cold_ms = (time.perf_counter() - t0) * 1000

        # Warm
        rego_warm_ms = _timeit_ms(lambda: rego_fn(1))
        print(
            f"  @kest_verified (Rego)    : cold={rego_cold_ms:.3f} ms, "
            f"warm={rego_warm_ms:.4f} ms  (+{rego_warm_ms - baseline_ms:.4f} ms overhead)"
        )
        results["rego_cold_ms"] = rego_cold_ms
        results["rego_warm_ms"] = rego_warm_ms
    except Exception as e:
        print(f"  Rego: skipped ({e})")

    return results


# ---------------------------------------------------------------------------
# L3: Policy engine throughput under threading
# ---------------------------------------------------------------------------


def bench_l3_policy_engines():
    print("\n## L3: Policy engine throughput (ops/sec, 4 threads)")
    results = {}
    entry = _make_entry()
    n = 4

    try:
        cedar_engine = CedarLocalEngine(
            policies={'kest::Action::"allow"': "permit(principal, action, resource);"},
            entities=[],
        )

        def cedar_eval():
            cedar_engine.evaluate(entry.entry_id, ["allow"], {})

        cedar_ops = _throughput(cedar_eval, n)
        print(f"  Cedar ops/sec (4 threads): {cedar_ops:>10.1f}")
        results["cedar_ops_per_sec"] = cedar_ops
    except Exception as e:
        print(f"  Cedar: skipped ({e})")

    try:
        REGO = "package kest.allow\ndefault allow := true"
        rego_engine = RegoLocalEngine(policies={"kest/allow": REGO})

        def rego_eval():
            rego_engine.evaluate(entry.entry_id, ["kest/allow"], {})

        # regopy multi-threading causes segfault due to cgo bounds. Skip threaded tests.
        # rego_ops = _throughput(rego_eval, n)
        # print(f"  Rego  ops/sec (4 threads): {rego_ops:>10.1f}")
        # results["rego_ops_per_sec"] = rego_ops
    except Exception as e:
        print(f"  Rego: skipped ({e})")

    # sign comparison baseline
    configure(identity=PROVIDER, engine=MockPolicyEngine())
    sign_ops = _throughput(lambda: sign_entry(entry, PROVIDER), n)
    print(f"  sign_entry ops/sec (4 threads): {sign_ops:>6.1f}")
    results["sign_ops_per_sec"] = sign_ops
    return results


# ---------------------------------------------------------------------------
# L4: Multi-hop simulation
# ---------------------------------------------------------------------------


def bench_l4_multihop():
    print("\n## L4: Multi-hop end-to-end simulation")
    print(f"{'Hops':>6} | {'total (ms)':>12} | {'per-hop (ms)':>14}")
    print("-" * 40)

    results = {}
    for n_hops in [3, 5, 10]:

        def simulate_chain(n=n_hops):
            baggage_store: dict[str, str] = {}
            for _ in range(n):
                incoming = BaggageManager.unpack(lambda k: baggage_store.get(k))
                entry = _make_entry()
                jws_token = sign_entry(entry, PROVIDER)
                incoming.add_signature(jws_token)
                new_baggage = BaggageManager.pack(incoming)
                baggage_store.update(new_baggage)

        total_ms = _timeit_ms(simulate_chain, reps=50)
        per_hop_ms = total_ms / n_hops
        print(f"{n_hops:>6} | {total_ms:>12.3f} | {per_hop_ms:>14.3f}")
        results[n_hops] = {"total_ms": total_ms, "per_hop_ms": per_hop_ms}
    return results


# ---------------------------------------------------------------------------
# L4: Passport merge overhead
# ---------------------------------------------------------------------------


def bench_l4_merge():
    print("\n## L4: Passport.merge overhead (parallel sub-graph convergence)")
    print(f"{'Inputs':>8} | {'merge (ms)':>12}")
    print("-" * 25)

    results = {}
    for n_passports in [2, 5, 10]:
        passports = [_build_passport(5) for _ in range(n_passports)]
        merge_ms = _timeit_ms(lambda ps=passports: Passport.merge(*ps))
        print(f"{n_passports:>8} | {merge_ms:>12.4f}")
        results[n_passports] = merge_ms
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"# Kest System Benchmark — backend={BACKEND}")

    output: dict[str, Any] = {"backend": BACKEND}
    output["L1_baggage"] = bench_l1_baggage()
    output["L2_decorator"] = bench_l2_decorator()
    output["L3_policy"] = bench_l3_policy_engines()
    output["L4_multihop"] = bench_l4_multihop()
    output["L4_merge"] = bench_l4_merge()

    out = f"examples/bench/system_{BACKEND}.json"
    os.makedirs("examples/bench", exist_ok=True)
    with open(out, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults written to {out}")
