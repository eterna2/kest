#!/usr/bin/env bash
# run_all.sh — Run the full Kest benchmark suite for both backends.
# Usage: bash examples/bench/run_all.sh
set -euo pipefail

cd "$(dirname "$0")/../.."  # cd to libs/kest-core/python

echo "=============================="
echo "  Kest Full Benchmark Suite"
echo "=============================="

# --- L0: pyperf micro-benchmarks ---
echo ""
echo "[L0] pyperf micro-benchmarks (Rust backend)..."
KEST_BACKEND=rust uv run python examples/bench/bench_kest_core.py \
  --fast -o examples/bench/rust.json

echo ""
echo "[L0] pyperf micro-benchmarks (Python backend)..."
KEST_BACKEND=python uv run python examples/bench/bench_kest_core.py \
  --fast -o examples/bench/python.json

echo ""
echo "[L0] pyperf comparison table:"
uv run python -m pyperf compare_to \
  examples/bench/rust.json examples/bench/python.json --table \
  | tee examples/bench/summary.txt

# --- L0: GIL-aware throughput ---
echo ""
echo "[L0] Threading throughput (Rust backend)..."
KEST_BACKEND=rust uv run python examples/bench/bench_throughput.py

echo ""
echo "[L0] Threading throughput (Python backend)..."
KEST_BACKEND=python uv run python examples/bench/bench_throughput.py

# --- L1–L4: System benchmarks ---
echo ""
echo "[L1–L4] System benchmarks (Rust backend)..."
KEST_BACKEND=rust uv run python examples/bench/bench_system.py

echo ""
echo "=============================="
echo "  All benchmarks complete."
echo "  Results in examples/bench/"
echo "=============================="
