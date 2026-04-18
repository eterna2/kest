#!/usr/bin/env bash
# run_all.sh — Run the full Kest benchmark suite for the pure Python backend.
# Usage: bash examples/bench/run_all.sh
set -euo pipefail

cd "$(dirname "$0")/../.."  # cd to libs/kest-core/python

echo "=============================="
echo "  Kest Full Benchmark Suite"
echo "=============================="

# --- L0: pyperf micro-benchmarks ---
echo ""
echo "[L0] pyperf micro-benchmarks (Python backend)..."
uv run python examples/bench/bench_kest_core.py \
  --fast -o examples/bench/python.json

# --- L0: GIL-aware throughput ---
echo ""
echo "[L0] Threading throughput (Python backend)..."
uv run python examples/bench/bench_throughput.py

echo ""
echo "[L0] Decorator throughput (Python backend)..."
uv run python examples/bench/bench_decorator_throughput.py

# --- L1–L4: System benchmarks ---
echo ""
echo "[L1–L4] System benchmarks (Python backend)..."
uv run python examples/bench/bench_system.py

echo ""
echo "=============================="
echo "  All benchmarks complete."
echo "  Results in examples/bench/"
echo "=============================="
