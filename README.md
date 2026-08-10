# Hardware Trojan Silence

Automatic hardware trojan detection and patching tool. Given a golden circuit and a trojaned version, the tool builds an interpretable trigger rule, patches the trojaned netlist, and uses ABC combinational equivalence checking (CEC) to decide whether the result is functionally equivalent to the golden circuit.

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
  ── use all gate nodes; current CLI also includes primary inputs as features
        │
        ▼
  Select rule synthesis method
  ├─ vn-retrain (default)
  │  ├─ shallow DT selects important gates
  │  ├─ signature-ranked pair/triple AND virtual features
  │  ├─ retrain with VNs; materialize only VNs used by the tree
  │  └─ final DT
  ├─ dt
  │  └─ one final DT, without VN or PB optimization
  └─ z3-pb
     ├─ one DT; union gates on raw positive paths
     └─ bounded-DNF 0-1 PB optimization over the finite training matrix
        │
        ▼
  Rule simplification and patch selection
  ├─ verified common-literal cut / single-literal trigger kill
  ├─ merge multi-rule match logic when needed
  └─ payload fix (Z3-guided node selection + rule-controlled patch)
        │
        ▼
  Internal ABC CEC, followed by an independent external ABC CEC in A/B runs
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
│   ├── rule_optimizer.hpp/cpp  # Z3 Optimize bounded-DNF 0-1 PB optimizer
│   ├── virtual_node.hpp/cpp    # Signature-ranked pair/triple AND virtual features
│   ├── candidate_selector.hpp/cpp # Build the all-gate candidate set
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
scripts/
├── compare_rule_methods.py     # Reproducible per-case A/B runner + external CEC
├── test_compare_rule_methods.py
└── test_rule_method_telemetry.sh
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
| `--mine-rounds N` | 15 | Parsed/logged compatibility setting; the current `main` rule-synthesis path fixes mining to one DT round |
| `--mine-max N` | 5000 | Parsed/logged compatibility setting; the current path disables newly mined hard-negative additions |
| `--include-pi` | on | Compatibility flag; primary-input features are already enabled by default |
| `--force-split` | off | Force tree splits even with low gain |
| `--no-strict` | off | Disable strict retry for zero FP on the finite training matrix |
| `--rule-method M` | `vn-retrain` | `vn-retrain`, `dt`, or `z3-pb` |
| `--no-virtual` | off | Legacy alias for `--rule-method dt`; conflicts with an explicit non-`dt` method |
| `--rule-opt-timeout-ms N` | 10000 | Shared Z3-PB wall-clock budget per optimizer call |
| `--rule-opt-max-rounds N` | 100 | Maximum PB CEGIS checks |
| `--rule-opt-cex-batch N` | 5 | Misclassified finite-training signatures added per CEGIS check |
| `--rule-opt-max-clauses N` | 0 | DNF clause cap; `0` derives it from the DT baseline rule count, while an explicit nonzero cap is honored |
| `--rule-opt-max-literals N` | 10 | Literals per DNF clause; `0` uses the largest baseline clause |

`z3-pb` changes rule synthesis only; downstream payload-node optimization and patch application are shared with the other methods. It uses Z3 Optimize as a pseudo-Boolean/MaxSMT backend. Its Boolean formulation is 0-1 ILP-equivalent, but it is not a generic MILP solver and does not construct or expose an LP relaxation, so there is no reported MILP gap. “Optimal” and “verified” telemetry apply only to the bounded candidate set and finite training matrix. Whole-input correctness is established by ABC CEC.

`rule_synth_summary synthesized_*` records the model immediately after rule synthesis. `rule_apply_summary` separately records the post-signature/applied mechanism and its effective rule/literal/depth counts; a verified direct literal cut is identified with `rule_model_used=0` and an effective `1/1/1` condition.

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

## Batch Testing and Rule-Method Reproduction

Run all test cases and produce a CSV report:

```bash
bash run_tests.sh
```

The first nine backward-compatible CSV columns are `circuit, trojan, success, gt_verify, vn_rounds, runtime_ms, area_delta, level_delta, cec_rounds`. Appended columns record the selected strategy, actual DT/training-data build counts, VN counts, synthesis metrics, apply source, and applied/effective rule metrics; see the header in `run_tests.sh` for the complete schema.

Success is determined by ABC CEC (equivalence check) of the patched circuit against the golden.

Run the rule-optimizer and comparison regression tests with:

```bash
make -C src ../bin/script/test_rule_optimizer -j4
bin/script/test_rule_optimizer
python3 scripts/test_compare_rule_methods.py
bash scripts/test_rule_method_telemetry.sh
```

Reproduce the fixed 11 hard cases and 3 controls (large V0 inputs must already be present under the paths in `configs/rule_method_ab_cases.json`):

```bash
python3 scripts/compare_rule_methods.py \
  --profile rebuild11 \
  --output-root validation/rule_method_ab_rebuild11_v2 \
  --jobs 1 --force

python3 scripts/compare_rule_methods.py \
  --profile controls \
  --output-root validation/rule_method_ab_controls_v2 \
  --jobs 1 --force
```

The runner enforces `--jobs 1` because methods for one case can otherwise race on a shared intermediate rule-merge netlist. It pins `ABC_BIN` to the fingerprinted ABC executable, requires the independent external CEC marker and a zero exit status, and rechecks all tool/input identities after each run. `wall_ms` covers execution; the separate `provenance_verification_ms` field records the post-run identity check.

Artifacts include per-method logs, patched netlists, JSON records, aggregate CSV/JSON, pre-run fingerprints with post-run mutation checks, and the external ABC CEC result. The tracked 28-row projection is [`experiments/rule_method_ab_2026-08-11/paired_results.csv`](experiments/rule_method_ab_2026-08-11/paired_results.csv). See [`RULE_METHOD_COMPARISON_REPORT.md`](RULE_METHOD_COMPARISON_REPORT.md) for the v2 comparison and limitations.

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
