# DAC25-inspired rectification vs Z3-PB + formal refinement

This is an end-to-end comparison on the same 482 runnable V0 Golden/Trojan pairs. The DAC arm is a public-information, **DAC'25-inspired** reimplementation, not the authors' unavailable implementation. Z3-PB uses error-pattern supervision; DAC uses the complete Golden/Trojan specification, so this is not a same-oracle selector-only ablation.

## Correctness

| Method | PASS | Rate | Wilson 95% | Other statuses |
|---|---:|---:|---:|---|
| Z3-PB + formal | 480/482 | 99.59% | 98.50–99.89% | `{'PASS': 480, 'TIMEOUT': 2}` |
| DAC25-inspired | 463/482 | 96.06% | 93.93–97.46% | `{'NO_PATCH': 18, 'PASS': 463, 'TIMEOUT': 1}` |

DAC has 2 gains and 19 regressions relative to Z3-PB (McNemar exact two-sided p=0.000221252).
Gains: `c5315_trojan24`, `c5315_trojan81`.
Regressions: `aes_trojan1 (TIMEOUT)`, `c5315_trojan76 (NO_PATCH)`, `c5315_trojan78 (NO_PATCH)`, `c5315_trojan89 (NO_PATCH)`, `c6288_trojan0 (NO_PATCH)`, `c7552_trojan50 (NO_PATCH)`, `c7552_trojan51 (NO_PATCH)`, `c7552_trojan52 (NO_PATCH)`, `c7552_trojan53 (NO_PATCH)`, `c7552_trojan63 (NO_PATCH)`, `c7552_trojan69 (NO_PATCH)`, `c7552_trojan71 (NO_PATCH)`, `c7552_trojan75 (NO_PATCH)`, `c7552_trojan76 (NO_PATCH)`, `c7552_trojan78 (NO_PATCH)`, `c7552_trojan81 (NO_PATCH)`, `c7552_trojan91 (NO_PATCH)`, `c7552_trojan92 (NO_PATCH)`, `c7552_trojan93 (NO_PATCH)`.
Independent replay with the pinned ABC proved all 480 recorded Z3 PASS artifacts and all 463 recorded DAC PASS artifacts equivalent.

## Paired end-to-end runtime

The paired cohort contains 461 cases that PASS in both methods. Wall-time sums are 5530.743s (Z3) and 4824.092s (DAC), Z3/DAC=1.146. The per-case median and geometric-mean Z3/DAC ratios are 0.328 and 0.424; DAC is faster on 94/461 cases. The sum is influenced by a small number of very slow Z3 cases, while the median/geometric mean describe the typical case.

## Common AIG structural QoR

Every input and patch was independently read and strashed by the same pinned ABC. `and` is the AIG AND-node count and `lev` is topological AIG logic level. It is **not** mapped cell area or physical delay in ns. Only the paired CEC-PASS cohort is compared.

| Metric | DAC wins | Ties | Z3 wins | Z3 aggregate | DAC aggregate |
|---|---:|---:|---:|---:|---:|
| Patched AIG nodes | 90 | 328 | 43 | 476165 | 475615 |
| Patched AIG levels | 32 | 354 | 75 | ΔvsTrojan sum -717 | ΔvsTrojan sum -810 |

AIG-node deltas versus the common Trojan sum to -3093 for Z3 and -3643 for DAC; medians are -5 and -5. The aggregate patched-node ratio Z3/DAC is 1.001156.

## Reproducibility

- ABC SHA-256: `627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3`
- Z3 binary SHA-256: `2bebfa7eadefbcbda545d255dbd26bfa2da85a7adeb0097bffd9d36a61668b41`
- DAC binary SHA-256: `ddaced4a3d969f341ec69da7fa2475a1ea3bdc7310513972a2f30e621048da2c`
- DAC source commit: `a9bb3312833a36bb280007a59df32aa838393c80` (dirty=False)
- Manifest SHA-256: `84897ac441b355029ec0fced4ec2bef213b1a7600fd68abcab2725ecb7848301`
- DAC run-context SHA-256: `6008b0ac47fbb6d51319591ff23264b5e861b8c0a798942b2cacf3f796f9d2d1`
- Z3 result CSV SHA-256: `0ad5f97c18ad8d657d0dc14f885ff643a71a043e3c55be5bf93e8334975c28d1`
- DAC result CSV SHA-256: `3d00120755a60cefefe678a5a5e021ccf6bbf0b650f8d423ec3cfd84005c261a`
- Artifact identity audit: Z3 2405 refs / 43696688 bytes; DAC 2353 refs / 29060863 bytes; zero mismatches
- Detailed cases: `dac25_vs_z3_formal_cases.csv`
- Per-circuit table: `dac25_vs_z3_formal_by_circuit.csv`
- Machine-readable summary: `dac25_vs_z3_formal_summary.csv`
