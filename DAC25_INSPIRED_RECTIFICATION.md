# DAC25-inspired rectification-signal validation

This branch implements and evaluates a **DAC'25-inspired** functional-ECO
baseline. It is not a reproduction of the authors' implementation: the paper
and source artifact are not publicly available. The implementation is limited
to the algorithmic information available in the
[DAC presentation abstract](https://62dac.conference-program.com/presentation/?id=RESEARCH1943&sess=sess129)
and the associated
[NTU thesis metadata](https://tdr.lib.ntu.edu.tw/handle/123456789/92142?mode=full),
then uses the open-source ABC `runeco` backend to synthesize and verify patches.

## Implemented flow

For a Golden circuit `G`, Trojan circuit `F`, and candidate target set `S`, the
selector validates the exact rectifiability condition

```text
forall primary inputs x, exists replacement target values u_S:
    F_cut(x, u_S) = G(x)
```

The implementation negates this condition and eliminates the small target
vector by exact Shannon expansion:

```text
Bad_S(x) = AND over every assignment a to u_S of
           OR over POs (F_cut(x, a) XOR G(x))
```

`SAT(Bad_S)` produces an input on which no target assignment can repair the
circuit, so `S` is infeasible. `UNSAT(Bad_S)` proves that a replacement
function exists. A selected target is one shared free Boolean observed by all
of its original fanouts; fanouts are not relaxed independently.

The concrete pipeline is:

1. Align PIs and POs by name and obtain an exact Golden/Trojan mismatch
   witness.
2. Build target candidates from mismatching-PO fanin cones, same-name
   structural-difference frontiers, distance, and intervention scores.
3. Retain at most 32 candidates and enumerate target sets by cardinality, with
   at most two targets per set.
4. Validate sets with the SAT condition above under a shared 30-second selector
   deadline; retain at most four feasible sets.
5. Send each retained set to ABC `runeco`, normalize every successful trial by
   the same `strash; write_bench -l` flow, and rank by normalized gate count,
   level, and deterministic tie breakers.
6. Restore the original BENCH PI/PO interface and require an independent ABC
   CEC against the Golden circuit.

The candidate cap means “minimum target count” is only within the retained
candidate universe, not a global minimum over every gate. Planner timeout,
infeasibility, backend failure, and missing output never silently fall back to
the legacy repair method.

This method is a separate repair dimension:

```bash
bin/main golden.bench trojan.bench groundtruth.json patched.bench \
  --rule-method z3-pb \
  --repair-method dac25-inspired \
  --dac25-selector-timeout-ms 30000 \
  --dac25-candidate-limit 32 \
  --dac25-max-targets 2 \
  --dac25-max-sets 4 \
  --dac25-runeco-timeout-s 60 \
  --dac25-abc-bin /absolute/path/to/abc
```

The positional ground-truth file remains required by the common CLI and is
fingerprinted by the runner, but the DAC25-inspired early repair path does not
read it. The method instead uses the complete Golden/Trojan functional
specification. Z3-PB starts from the error-pattern file and, when formal
refinement is enabled, also queries the complete circuit pair through its
formal miter. The different repair flow and initial supervision mean the
result below is an end-to-end system comparison, not a selector-only ablation.

## Full V0 result

The fixed cohort is the same 482 runnable cases used by the published
Z3-PB+formal result. The remaining 20 scheduled cases have empty ground-truth
pattern sets and are excluded from both methods. Both arms use a 300-second
outer timeout and the same pinned ABC for final CEC.

| Method | PASS | Rate | Wilson 95% | Non-PASS |
|---|---:|---:|---:|---|
| Z3-PB + formal refinement | 480/482 | 99.59% | 98.50–99.89% | 2 TIMEOUT |
| DAC25-inspired | 463/482 | 96.06% | 93.93–97.46% | 18 NO_PATCH, 1 TIMEOUT |

Relative to Z3-PB, DAC has two gains (`c5315_trojan24` and
`c5315_trojan81`) and 19 regressions. The paired McNemar exact two-sided
p-value is 0.000221252. Every one of the 480 Z3 PASS artifacts and 463 DAC PASS
artifacts passed an additional independent replay with the pinned ABC.

Per circuit:

| Circuit | Cases | Z3 PASS | DAC PASS |
|---|---:|---:|---:|
| aes | 1 | 1 | 0 |
| c2670 | 100 | 100 | 100 |
| c3540 | 100 | 100 | 100 |
| c5315 | 100 | 98 | 97 |
| c6288 | 1 | 1 | 0 |
| c7552 | 84 | 84 | 70 |
| c880 | 96 | 96 | 96 |

A declared sensitivity check raised only the selector deadline from 30 to 120
seconds on `c5315_trojan78` and `c7552_trojan53`. Both still returned no patch,
so the full run retained the predeclared 30-second selector budget.

The full invocation was:

```bash
python3 scripts/compare_rule_methods.py \
  --repo-root . --manifest <V0-manifest.json> --profile runnable \
  --method dac25-inspired --bin ./bin/main \
  --abc <pinned-abc> --dac25-abc-bin <pinned-abc> \
  --dac25-selector-timeout-ms 30000 \
  --dac25-candidate-limit 32 --dac25-max-targets 2 \
  --dac25-max-sets 4 --dac25-runeco-timeout-s 60 \
  --show ./bin/script/show \
  --output-root validation/dac25_inspired_v0_full_2026-08-12-v2/run \
  --timeout 300 --abc-timeout 60 --jobs 1
```

## Runtime and structural QoR

There are 461 cases for which both methods pass. On that paired cohort:

- Wall-time sums are 5530.743 s for Z3 and 4824.092 s for DAC; a few very slow
  Z3 cases make the DAC sum 12.78% lower.
- The median and geometric-mean per-case Z3/DAC ratios are 0.328 and 0.424.
  Thus DAC is about 3.05x slower at the median and 2.36x slower geometrically;
  DAC is faster on only 94/461 individual cases.

For a representation-consistent hardware comparison, every Golden, Trojan,
and repaired netlist was independently read and strashed by the same ABC.
Only paired CEC-PASS cases enter the table:

| Metric | DAC wins | Ties | Z3 wins | Aggregate Z3 | Aggregate DAC |
|---|---:|---:|---:|---:|---:|
| Patched AIG AND nodes | 90 | 328 | 43 | 476165 | 475615 |
| Patched AIG levels | 32 | 354 | 75 | ΔvsTrojan −717 | ΔvsTrojan −810 |

DAC has 550 fewer aggregate AIG nodes, a 0.116% reduction. Relative to the
common Trojan circuits, the aggregate AIG-node changes are −3093 for Z3 and
−3643 for DAC; both medians are −5. Negative deltas are expected because
repair can remove or simplify Trojan logic.

“Level” here is a topological AIG logic-depth proxy. It is not cell delay in
nanoseconds. A physical timing claim would require both methods to use the
same Liberty library, technology mapping, constraints, and STA flow.

Detailed results are in
[`experiments/dac25_vs_z3_formal_2026-08-12`](experiments/dac25_vs_z3_formal_2026-08-12/):

- `DAC25_VS_Z3_FORMAL_REPORT.md`
- `dac25_vs_z3_formal_cases.csv`
- `dac25_vs_z3_formal_by_circuit.csv`
- `dac25_vs_z3_formal_summary.csv`
- `DAC25_VS_Z3_FORMAL_SHA256SUMS`

The comparison is regenerated by `scripts/analyze_dac25_vs_z3_formal.py`.
The raw benchmark artifacts remain under ignored `validation/` directories;
their result-file hashes and the pinned ABC identity are recorded in the
report.

```bash
python3 scripts/analyze_dac25_vs_z3_formal.py \
  --z3-results <z3-run>/results.csv --z3-root <z3-run> \
  --dac-results <dac-run>/results.csv --dac-root <dac-run> \
  --abc <pinned-abc> \
  --output-dir experiments/dac25_vs_z3_formal_2026-08-12 \
  --workers 4 --abc-timeout 60 --require-cases 482
```

## Interpretation and limitations

- Z3-PB learns a trigger DNF from error-pattern supervision and uses
  SAT-refinement/CEC feedback. DAC25-inspired rectification chooses general ECO
  cut signals from the complete Golden/Trojan specification and delegates
  Skolem-function synthesis to `runeco`. They operate at different repair
  layers.
- The DAC selector currently searches sets of at most two targets in a
  32-candidate retained pool. Most of its 18 `NO_PATCH` cases exhaust the
  selector deadline without finding a feasible set; they are part of method
  quality, not infrastructure errors.
- No emitted DAC patch failed CEC. The lower success rate comes from failure to
  produce a patch plus the AES outer timeout.
- A future selector-only comparison should feed both target selectors into the
  same patch generator and give both the same target universe. The present
  result is intentionally an end-to-end repair-system comparison.

## V4 multi-Trojan diagnostic result

The same fixed `smoke_extended` V4 cohort used for the Z3-PB formal-refinement
smoke experiment was also run through the DAC25-inspired flow. It contains 13
cases spanning one, two, three, and five independent Trojans, trigger sizes
three and five, shared-trigger cases, and AES/mem_ctrl cases. The selector
configuration was fixed before the run: 32 retained candidates, at most two
targets, four feasible sets, a 30-second selector budget, a 60-second `runeco`
budget, and a 300-second outer timeout.

| Method | PASS | Other outcomes |
|---|---:|---|
| Z3-PB + formal refinement | 3/13 | 4 CEC_FAIL, 4 NO_PATCH, 2 TIMEOUT |
| DAC25-inspired | 2/13 | 9 NO_PATCH, 2 TIMEOUT |

DAC has no gains and one regression relative to Z3-PB + formal: the disjoint
`c880` N=2, trigger-size-3 case passes with Z3-PB but produces no feasible DAC
target set within the retained pool and two-target bound. Both DAC PASS cases
are N=1 cases. All five recorded PASS artifacts were independently replayed
with the same pinned ABC and passed CEC.

Only two cases pass in both methods. After reading and strashing every input
and patch with the same ABC, both methods produce exactly 327 AIG AND nodes at
24 levels on each case. Thus DAC has no structural QoR advantage in this
sample. The paired wall-time sums are 0.825 seconds for Z3-PB + formal and
4.227 seconds for DAC, making DAC about 5.12x slower on these two cases.

This 13-case cohort is a diagnostic sample, not a statistically powered
success-rate benchmark. In particular, `max-targets=2` is a declared method
bound and can limit N=3/N=5 repairs. The full V4 stratified experiment should
retain this configuration or declare a separate scalability arm rather than
tune the cap after observing these results.

Detailed paired results, normalized AIG metrics, provenance hashes, and the
generated report are in
[`experiments/v4_dac25_vs_z3_formal_smoke_2026-08-12`](experiments/v4_dac25_vs_z3_formal_smoke_2026-08-12/).
