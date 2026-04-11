# Kest Core: Backend Performance Benchmark

## Overview
This document compares the performance of the two available backends:
- **Rust backend** (`KEST_BACKEND=rust`): Compiled PyO3 extension (`_core.abi3.so`).
- **Python backend** (`KEST_BACKEND=python`): Pure-Python fallback (`_core_py.py`).

The Rust backend is the default and recommended for production. The Python backend
enables pure-Python wheel distribution (sdist), easier cross-platform testing,
and debugging without a Rust toolchain.

## Environment
| Field | Value |
|---|---|
| Date | 2026-04-11 |
| OS | Linux |
| Python | 3.11.15 |
| kest version | 0.3.0 |
| Rust toolchain | ~ 1.77.0 |

## Results
| Benchmark | Rust (µs) | Python (µs) | Speedup |
|---|---|---|---|
| `entry_create` | 0.80 | 0.81 | 1.01x slower |
| `sign_entry` | 24.70 | 24.70 | ~1.0x |
| `canonical_json` | 3.89 | 3.98 | 1.02x slower |
| `chain_10` | 276 | 281 | 1.02x slower |
| `chain_100` | 2790 | 2790 | ~1.0x |

> Values are mean ± 1 std-dev over N calibrated iterations (pyperf auto-calibrated).
> Lower is better.

## Interpretation
- **`entry_create`**: Overhead is effectively the same since the Python dataclass is highly optimized.
- **`sign_entry`**: Both use efficient canonicalization (`serde_jcs` vs `rfc8785`), the Python backend uses `rfc8785` which in recent versions performs similarly.
- **`canonical_json`**: `rfc8785` performs within margin of error of the compiled struct path.
- **`chain_10` / `chain_100`**: End-to-end Passport chain construction scales linearly without significant degradation in the pure-python path compared to the hybrid path for these sample sizes.

## Reproducing Results

### Prerequisites
```bash
uv sync --all-extras
python -m pyperf system tune
```

### Running
```bash
moon run kest-core-python:bench
```
Or manually:
```bash
export KEST_BACKEND=rust
python examples/bench/bench_kest_core.py -o examples/bench/rust.json
export KEST_BACKEND=python
python examples/bench/bench_kest_core.py -o examples/bench/python.json
python -m pyperf compare_to examples/bench/rust.json examples/bench/python.json --table
```

## Raw Data
The raw `pyperf` JSON files are committed alongside this document:
- `rust.json` — Rust backend raw results.
- `python.json` — Python backend raw results.

To inspect individual run statistics:
```bash
python -m pyperf stats examples/bench/rust.json
python -m pyperf stats examples/bench/python.json
```
