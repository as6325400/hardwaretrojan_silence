# DAC25-inspired rectification vs Z3-PB + formal refinement

This is an end-to-end comparison on 13 Golden/Trojan pairs (V4 smoke_extended multi-Trojan diagnostic cohort). The DAC arm is a public-information, **DAC'25-inspired** reimplementation, not the authors' unavailable implementation. Z3-PB starts from error-pattern supervision and then queries the complete circuit pair through its formal miter; DAC selects ECO cuts directly from the complete pair and does not read the ground-truth pattern file. This remains an end-to-end comparison, not a same-oracle selector-only ablation.

## Correctness

| Method | PASS | Rate | Wilson 95% | Other statuses |
|---|---:|---:|---:|---|
| Z3-PB + formal | 3/13 | 23.08% | 8.18–50.26% | `{'CEC_FAIL': 4, 'NO_PATCH': 4, 'PASS': 3, 'TIMEOUT': 2}` |
| DAC25-inspired | 2/13 | 15.38% | 4.33–42.23% | `{'NO_PATCH': 9, 'PASS': 2, 'TIMEOUT': 2}` |

Wilson intervals describe the observed cohort only; no population-level inference is made unless the cohort's sampling design supports it.

DAC has 0 gains and 1 regression relative to Z3-PB (McNemar exact two-sided p=1).
Gains: none.
Regressions: `c880_n2_t3_o000_s2004_6c8940cd (NO_PATCH)`.
Independent replay with the pinned ABC proved all 3 recorded Z3 PASS artifacts and all 2 recorded DAC PASS artifacts equivalent.

## Paired end-to-end runtime

The paired cohort contains 2 cases that PASS in both methods. Of these, 2 have positive finite wall-time values for both methods. Their sums are 0.825s (Z3) and 4.227s (DAC), Z3/DAC=0.195. The per-case median and geometric-mean Z3/DAC ratios are 0.195 and 0.195; DAC is faster on 0/2 comparable cases. Tool-reported runtime is comparable on 2 paired-PASS cases; the aggregate Z3/DAC ratio is 0.159.

## Common AIG structural QoR

Every input and patch was independently read and strashed by the same pinned ABC. `and` is the AIG AND-node count and `lev` is topological AIG logic level. It is **not** mapped cell area or physical delay in ns. Only the paired CEC-PASS cohort is compared.

| Metric | DAC wins | Ties | Z3 wins | Z3 aggregate | DAC aggregate |
|---|---:|---:|---:|---:|---:|
| Patched AIG nodes | 0 | 2 | 0 | 654 | 654 |
| Patched AIG levels | 0 | 2 | 0 | ΔvsTrojan sum 0 | ΔvsTrojan sum 0 |

AIG-node deltas versus the common Trojan sum to -12 for Z3 and -12 for DAC; medians are -6.000 and -6.000. The aggregate patched-node ratio Z3/DAC is 1.000000.

## Reproducibility

- ABC SHA-256: `627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3`
- Z3 binary SHA-256: `2bebfa7eadefbcbda545d255dbd26bfa2da85a7adeb0097bffd9d36a61668b41`
- DAC binary SHA-256: `ddaced4a3d969f341ec69da7fa2475a1ea3bdc7310513972a2f30e621048da2c`
- Z3 recorded source commit: `2d7dcc8cd9cfefe7aa60f07e3cc97ef09b89c0b3` (dirty=True)
- DAC source commit: `d77339e5ef9a3bad2d8f2a4a693f585404e9002b` (dirty=False)
- Manifest SHA-256: `a85a6a75260a9ff659d91ec4bc50a432e1343979418e94a24c581448fbacee82`
- DAC run-context SHA-256: `b3d8846b984a41b2690b2ae94fefe279cd37838252d36cf6cb316ed1d6c77495`
- Z3 result CSV SHA-256: `f51a3ce49b84b984da10caf19198601e422cfd2307ffd9c46afac3da2da0ecd0`
- DAC result CSV SHA-256: `844e4d1e67706ab512851c03eb8060d1bf2223c5c356b17fce28402d8dbb2fb0`
- Artifact identity audit: Z3 47 refs / 6316762 bytes; DAC 32 refs / 51441 bytes; zero mismatches
- Detailed cases: `dac25_vs_z3_formal_cases.csv`
- Per-circuit table: `dac25_vs_z3_formal_by_circuit.csv`
- Machine-readable summary: `dac25_vs_z3_formal_summary.csv`
