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
  ├─ z3-pb
  │  ├─ one DT; union gates on raw positive paths
  │  └─ bounded-DNF 0-1 PB optimization over the finite training matrix
  └─ milp-cover
     ├─ the same DT candidate union; enumerate safe minimal clauses
     ├─ HiGHS weighted set-cover MILP: rules → literals → shared inverters
     └─ optional graph-level feature/fanout/depth tie-break
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
│   ├── set_cover_optimizer.hpp/cpp # HiGHS weighted set-cover MILP
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
├── test_rule_method_telemetry.sh
└── test_literal_patch_cut_cex.sh
```

## Build

Requires: C++17, OpenMP, z3. CUDA and HiGHS are auto-detected. HiGHS is
optional for the other methods but required to run `milp-cover`; set
`HIGHS_ROOT` when it is installed outside the default search paths.

```bash
make -C src -j$(nproc)

# Explicit, reproducible HiGHS selection
make -C src HIGHS_ROOT=/path/to/highs-prefix -j$(nproc)
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
| `--rule-method M` | `vn-retrain` | `vn-retrain`, `dt`, `z3-pb`, or `milp-cover` |
| `--no-virtual` | off | Legacy alias for `--rule-method dt`; conflicts with an explicit non-`dt` method |
| `--rule-opt-timeout-ms N` | 10000 | Shared wall-clock budget per Z3-PB or MILP optimizer call |
| `--rule-opt-max-rounds N` | 100 | Maximum PB CEGIS checks |
| `--rule-opt-cex-batch N` | 5 | Misclassified finite-training signatures added per CEGIS check |
| `--rule-opt-max-clauses N` | 0 | DNF clause cap; `0` derives it from the DT baseline rule count, while an explicit nonzero cap is honored |
| `--rule-opt-max-literals N` | 10 | Literals per DNF clause; `0` uses the largest baseline clause |
| `--rule-cover-max-terms N` | 200000 | Maximum safe clauses enumerated by `milp-cover`; an incomplete pool falls back safely |
| `--rule-cover-third-objective M` | `unique-inverters` | After optimal rule/literal counts, minimize shared expected-zero literal inverters; `none` disables it |
| `--rule-cover-phase3-timeout-ms N` | shared | Optional sub-budget for the shared-inverter stage |
| `--rule-cover-fourth-objective M` | `logic-risk` | Final MILP tie-break: `logic-risk` or `none` |
| `--rule-cover-logic-risk-unique-weight X` | 0.25 | Weight of distinct tapped features in the graph-level proxy |
| `--rule-cover-logic-risk-fanout-weight X` | 0.25 | Weight of base-fanout load stress in the proxy |
| `--rule-cover-logic-risk-timing-weight X` | 0.50 | Weight of unit-level balanced-DNF depth in the proxy |
| `--rule-cover-phase4-timeout-ms N` | shared | Optional sub-budget for the logic-risk stage |
| `--rule-formal-refine` | off | Query SAT for rule false negatives/positives and feed counterexamples back |
| `--rule-formal-timeout-ms N` | 10000 | Shared soft wall-clock budget per rule-miter check |
| `--rule-formal-max-rounds N` | 5 | Maximum SAT feedback rebuilds |
| `--rule-formal-cex-batch N` | 5 | Counterexamples returned per check, from 1 to 5 |

`z3-pb` changes rule synthesis only; downstream payload-node optimization and patch application are shared with the other methods. It uses Z3 Optimize as a pseudo-Boolean/MaxSMT backend. Its Boolean formulation is 0-1 ILP-equivalent, but it is not a generic MILP solver and does not construct or expose an LP relaxation, so there is no reported MILP gap. “Optimal” and “verified” telemetry apply only to the bounded candidate set and finite training matrix. Whole-input correctness is established by ABC CEC.

`milp-cover` starts from the same raw-DT candidate union. For each positive
signature it enumerates bounded inclusion-minimal clauses that reject every
known negative, then solves a true binary set-cover model with HiGHS. Separate
LP/MIP stages minimize rule count, literal count, shared inverter count, and
optionally a graph-level logic-risk proxy. The last stage is not physical STA:
fanout and delay are structural surrogates, so final area/level must still be
measured from the emitted netlist.

With `--rule-formal-refine`, both optimizer methods additionally query
`E & !R` and `!E & R`, where `E` is the golden/trojan PO-mismatch predicate
and `R` is the learned DNF. SAT witnesses become hard positive/negative
samples. Direct literal cuts also preserve accumulated safe counterexamples;
final correctness remains the independent patched-netlist ABC CEC result.

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
make -C src HIGHS_ROOT=/path/to/highs-prefix \
  ../bin/script/test_rule_optimizer \
  ../bin/script/test_set_cover_optimizer \
  ../bin/script/test_rule_miter -j4
bin/script/test_rule_optimizer
bin/script/test_set_cover_optimizer
bin/script/test_rule_miter
python3 scripts/test_compare_rule_methods.py
bash scripts/test_rule_method_telemetry.sh
bash scripts/test_literal_patch_cut_cex.sh
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

python3 scripts/compare_rule_methods.py \
  --profile all \
  --method z3-pb --method milp-cover \
  --highs-library /path/to/libhighs.so \
  --rule-formal-refine \
  --rule-cover-fourth-objective logic-risk \
  --output-root validation/rule_method_milp_p4_formal \
  --jobs 1 --force
```

The runner enforces `--jobs 1` because methods for one case can otherwise race on a shared intermediate rule-merge netlist. It pins `ABC_BIN` to the fingerprinted ABC executable, requires the independent external CEC marker and a zero exit status, and rechecks all tool/input identities after each run. `wall_ms` covers execution; the separate `provenance_verification_ms` field records the post-run identity check.

Artifacts include per-method logs, patched netlists, JSON records, aggregate CSV/JSON, pre-run fingerprints with post-run mutation checks, and the external ABC CEC result. See [`RULE_METHOD_COMPARISON_REPORT.md`](RULE_METHOD_COMPARISON_REPORT.md) for the VN/Z3 baseline and [`MILP_RULE_COVER_REPORT.md`](MILP_RULE_COVER_REPORT.md) for the HiGHS set-cover, SAT feedback, cost-objective implementation, final comparison, and limitations.

## ABC Setup

Ensure `abc` binary is available in `PATH` or project root:

```bash
export ABC_BIN=/path/to/abc
```

## Dependencies

- **C++17** compiler (g++ or clang++)
- **OpenMP** for CPU parallelism
- **z3** SMT solver library
- **HiGHS** (optional globally, required by `milp-cover`; tested with 1.11.0)
- **CLI11** (bundled in `extern/`)
- **nlohmann/json** (bundled in `extern/`)
- **CUDA** (optional, for GPU acceleration)
- **ABC** (external, for synthesis and CEC)
