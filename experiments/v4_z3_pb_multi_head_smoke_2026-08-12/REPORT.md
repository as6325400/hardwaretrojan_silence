# V4 13-case Z3-PB multi-head comparison

Correctness is counted only when the runner status is `PASS` and the external ABC CEC result is equivalent. Ground-truth simulation is reported as telemetry, not used as the correctness authority.

## Outcome

- Scalar Z3-PB + formal: **3/13 PASS**
- Multi-head Z3-PB + formal: **9/13 PASS**
- Net change: **+6 PASS** (6 gains, 0 regressions)
- This is a deliberately selected diagnostic cohort, not a random sample or a V4 population success-rate estimate.
- The scalar arm is the prior frozen binary and the multi-head arm is the new frozen binary. Status transitions answer the requested before/after comparison; runtime is descriptive, not a same-binary policy ablation.
- This is a bundled multi-head configuration, not a composition-only ablation: each head uses up to 20 SAT-driven rebuilds, an effective negative ratio of 5, all physical gates when the circuit has at most 20,000 nodes (otherwise the raw DT union), and up to 5 whole-patch CEC feedback rounds.

## Status transitions

| Transition | Cases |
|---|---:|
| `CEC_FAIL->PASS` | 2 |
| `CEC_FAIL->TIMEOUT` | 2 |
| `NO_PATCH->PASS` | 4 |
| `PASS->PASS` | 3 |
| `TIMEOUT->CEC_FAIL` | 2 |

## Per-case results

| Case | Scalar | Multi-head | Wall scalar / multi (ms) | AND delta scalar / multi | Level delta scalar / multi | Heads proved/final |
|---|---|---|---:|---:|---:|---:|
| `aes_n2_t5_o000_s9000_7aac57e8` | `TIMEOUT` | `CEC_FAIL` | 300168.91 / 190712.63 | — / 10 | — / 1 | 0/2 |
| `aes_n3_t5_o000_s9000_7aac57e8` | `TIMEOUT` | `CEC_FAIL` | 300167.72 / 293889.00 | — / 13 | — / 1 | 0/3 |
| `c7552_n5_t5_o000_s9503_209d2aa4` | `NO_PATCH` | `PASS` | 70161.01 / 43106.60 | — / 31 | — / 0 | 5/5 |
| `c880_n1_t3_o000_s2007_6c8940cd` | `PASS` | `PASS` | 413.08 / 558.16 | -1 / 4 | 0 / 0 | 1/1 |
| `c880_n1_t5_o000_s2001_6c8940cd` | `PASS` | `PASS` | 412.10 / 2783.18 | -1 / 9 | 0 / 1 | 1/1 |
| `c880_n2_t3_o000_s2004_6c8940cd` | `PASS` | `PASS` | 7092.69 / 2184.17 | 24 / 10 | 3 / 0 | 2/2 |
| `c880_n2_t3_o500_s6004_6c8940cd` | `NO_PATCH` | `PASS` | 35561.98 / 3434.80 | — / 20 | — / 1 | 3/3 |
| `c880_n2_t5_o000_s2006_6c8940cd` | `NO_PATCH` | `PASS` | 4113.53 / 7298.88 | — / 12 | — / 1 | 2/2 |
| `c880_n3_t3_o000_s2004_6c8940cd` | `CEC_FAIL` | `PASS` | 43522.34 / 49410.44 | 195 / 25 | 12 / 0 | 3/3 |
| `c880_n3_t5_o000_s2001_6c8940cd` | `NO_PATCH` | `PASS` | 45326.51 / 49063.37 | — / 19 | — / 1 | 3/3 |
| `c880_n3_t5_o500_s6004_6c8940cd` | `CEC_FAIL` | `PASS` | 72877.72 / 191147.86 | 260 / 40 | 13 / 1 | 3/3 |
| `mem_ctrl_n2_t5_o000_s2003_bef1125c` | `CEC_FAIL` | `TIMEOUT` | 267615.38 / 300116.70 | 6 / — | 0 / — | —/— |
| `mem_ctrl_n3_t5_o000_s2003_bef1125c` | `CEC_FAIL` | `TIMEOUT` | 285546.96 / 300116.12 | 6 / — | 0 / — | —/— |

## Paired runtime and QoR

- All 13 cases total wall time: scalar 1432979.93 ms, multi-head 1433821.91 ms.
- Both-PASS subset: 3 cases; multi/scalar wall-time geometric mean 1.411×.
- Both-PASS QoR subset: 3 cases; mean actual AND delta vs Trojan scalar/multi = 7.33 / 7.67; mean level delta = 1.00 / 0.33.

## Multi-head telemetry

- Passing cases with every final head SAT-proved: 9 / 9.
- Cases reaching discovery/patch: 13 / 11.
- Final/proved heads summed across cases: 28.00 / 23.00.
- Head rule events / scoped SAT-driven refinement rebuild events: 331.00 / 266.00.
- Head-local CEX events returned/inserted and solver checks: 1360.00 / 1340.00 / 1484.00.
- Unique global-corpus CEX insertions after deduplication: 1348.00.
- Internal CEC feedback rounds / labels added / new heads: 15.00 / 40.00 / 2.00.

## Provenance

- Manifest SHA-256: `a85a6a75260a9ff659d91ec4bc50a432e1343979418e94a24c581448fbacee82`
- Scalar binary SHA-256: `2bebfa7eadefbcbda545d255dbd26bfa2da85a7adeb0097bffd9d36a61668b41`
- Multi-head binary SHA-256: `534b5eb47e069e0a947efd5d2a8daa1b3605ebc0c85d950f1d7814d9f605342f`
- ABC SHA-256: `627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3`
- `show` SHA-256: `4517349556e40cf3468dc37802a4ceb8430df53c0447a2e36cf889f4fd9a4082`
- Validated benchmark inputs: 13 exact cases.
- Formal config: timeout 10000 ms, 5 scalar refinement rounds, 5 CEX/check; multi-head refinement limit 20, effective head negative ratio 5, all-gate threshold 20,000 nodes, and at most 5 whole-patch CEC feedback rounds.

`actual_*_and` columns are the runner's ABC `show` area metric (AIG AND count); QoR comparisons are restricted to cases where both arms PASS.
