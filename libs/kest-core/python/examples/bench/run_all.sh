#!/bin/bash
set -e

echo "Running Rust backend benchmarks..."
KEST_BACKEND=rust uv run python examples/bench/bench_kest_core.py -o examples/bench/rust.json

echo "Running Python backend benchmarks..."
KEST_BACKEND=python uv run python examples/bench/bench_kest_core.py -o examples/bench/python.json

echo "Generating comparison table..."
uv run python -m pyperf compare_to examples/bench/rust.json examples/bench/python.json --table > examples/bench/summary.txt
cat examples/bench/summary.txt
