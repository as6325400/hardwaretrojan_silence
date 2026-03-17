# Hardware Trojan Silence

Automatic hardware trojan detection and patching tool. Given a golden circuit and a trojaned version, the tool learns the trojan's trigger condition via decision tree mining and generates a patched circuit that is functionally equivalent to the golden.

## Algorithm Overview

```
Golden + Trojan .bench
        │
        ▼
  Parse & Align circuits
        │
        ▼
  Groundtruth simulation (GPU/CPU)
  ── collect trigger / non-trigger patterns
        │
        ▼
  Candidate selection
  ── pick gates with high trojan activation rate
        │
        ▼
  Virtual Node generation (iterative)
  ── Phase 1: train decision tree (unlimited depth, force split)
  ── Phase 2: generate pairwise/triple VN from important signals
  ── Phase 3: iterative refinement, mine subclauses, early stop
  ── Insert only used VNs into circuit
        │
        ▼
  Final mining (strict mode)
  ── decision tree + hard-negative mining
  ── strict retry: unlimited depth until zero false positives
  ── rule simplification (remove redundant terms)
        │
        ▼
  Fix strategy selection
  ├─ Try trigger kill (force gate to constant 0/1)
  ├─ Try VN expand kill (decompose virtual AND, kill constituents)
  └─ Payload fix (MaxSAT-guided PO patching with MUX/XOR insertion)
        │
        ▼
  CEC verification (ABC equivalence check)
  ── if fail: extract counter-example, add to triggers, retry (max 5 rounds)
        │
        ▼
  Output patched .bench
```

## Project Structure

```
src/
├── main.cpp                    # Main orchestrator
├── core/
│   ├── circuit.hpp/cpp         # Circuit DAG representation
│   ├── packed_circuit.hpp/cpp  # Bit-parallel simulation (64-bit words)
│   ├── circuit_compare.hpp/cpp # Golden vs trojan alignment
│   ├── batch_simulator.hpp/cpp # Batch pattern simulation
│   ├── gpu_circuit.cu/cuh      # CUDA GPU simulation kernels
├── algorithm/
│   ├── decision_tree.hpp/cpp   # Decision tree (column-major packed matrix)
│   ├── gpu_tree.cu/cuh         # GPU-accelerated tree training
│   ├── miner.hpp/cpp           # Mining loop + hard-negative mining + strict retry
│   ├── virtual_node.hpp/cpp    # Virtual node feature generation (AND/OR/XOR combos)
│   ├── candidate_selector.hpp/cpp # Gate candidate selection by trojan rate
│   ├── pattern_sampler.hpp/cpp # Random pattern generation
│   ├── rule_patch.hpp/cpp      # Rule-based circuit patching (MUX/XOR insertion)
│   ├── trigger_fixer.hpp/cpp   # Trigger kill strategies
│   ├── payload_analysis.hpp/cpp # MaxSAT-guided payload PO identification
│   ├── matching.hpp/cpp        # Pattern matching
│   └── sat_refine.hpp/cpp      # SAT-based refinement (z3)
├── io/
│   ├── bench_parser.hpp/cpp    # ISCAS .bench file parser
│   ├── bench_writer.hpp/cpp    # .bench file writer
│   ├── cli_options.hpp/cpp     # CLI argument parsing (CLI11)
│   ├── eqn_parser.hpp/cpp      # ABC EQN format parser
│   └── parallel_collect_log.hpp/cpp # Groundtruth JSON log parser
└── script/
    ├── show.cpp                # Print circuit area/level
    ├── synthesis.cpp           # ABC-based optimization
    ├── verify_groundtruth.cpp  # Verify groundtruth patterns
    └── packed_cmp.cpp          # Packed circuit comparison
```

## Build

Requires: C++17, OpenMP, z3. Optional: CUDA (auto-detected).

```bash
make -C src -j$(nproc)
```

Outputs go to `bin/` (executables) and `build/` (object files).

CUDA is auto-detected from `nvcc` in PATH or `/usr/local/cuda*/bin/`. When available, circuits with 50K+ gates use GPU-accelerated simulation.

## Usage

### `bin/main` — Trojan Patch

```bash
bin/main <golden.bench> <trojan.bench> <groundtruth.json> [output.bench] [options]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--depth N` | 10 | Max decision tree depth (non-strict phases) |
| `--neg-ratio N` | 50 | Negative-to-positive sample ratio |
| `--mine-rounds N` | 15 | Hard-negative mining iterations |
| `--mine-max N` | 5000 | Max features per mining round |
| `--include-pi` | on | Include primary inputs as features |
| `--force-split` | off | Force tree splits even with low gain |
| `--no-strict` | off | Disable strict retry (skip zero-FP enforcement) |
| `--no-virtual` | off | Disable virtual node generation |

**Example:**

```bash
bin/main benchmarks/c7552.bench \
  trojaned_bench/V0_singleTrigger_singlePayload/c7552/c7552_trojan4.bench \
  groundtruth/V0_singleTrigger_singlePayload/c7552/c7552_trojan4_error_patterns.json \
  out.bench
```

### `bin/show` — Circuit Stats

```bash
bin/show <bench>
# Output: area 3518 delay 43
```

### `bin/synthesis` — ABC Optimization

```bash
bin/synthesis <input.bench> <output.bench> [--flow resyn2|area|delay]
bin/synthesis <input.bench> <output.bench> --list   # list flows
```

## Groundtruth Collection (Docker)

Collect trigger/non-trigger patterns using the `ht-collect` Docker image:

```bash
python3 trojan_collect_batch.py \
  --trojan_root trojaned_bench/V0_singleTrigger_singlePayload \
  --output_root groundtruth/V0_singleTrigger_singlePayload
```

Options: `--start-round`, `--end-round`, `--rounds`, `--dry-run`.

## Batch Testing

Run all test cases and produce a CSV report:

```bash
bash run_v0_tests.sh
```

Output CSV columns: `circuit, trojan, success, gt_verify, vn_rounds, runtime_ms, area_delta, level_delta, cec_rounds`

Success is determined by ABC CEC (equivalence check) of the patched circuit against the golden.

## ABC Setup

Ensure `abc` binary is available in `PATH` or project root:

```bash
export ABC_BIN=/path/to/abc
```

## Dependencies

- **C++17** compiler (g++ or clang++)
- **OpenMP** for CPU parallelism
- **z3** SMT solver library
- **CLI11** (bundled in `extern/`)
- **nlohmann/json** (bundled in `extern/`)
- **CUDA** (optional, for GPU acceleration)
- **ABC** (external, for synthesis and CEC)
