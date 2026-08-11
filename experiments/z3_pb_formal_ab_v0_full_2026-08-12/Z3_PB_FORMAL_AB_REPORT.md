# Z3-PB formal-refinement A/B/C

- Common cases: 482
- B/C binary SHA-256: `2bebfa7eadefbcbda545d255dbd26bfa2da85a7adeb0097bffd9d36a61668b41`
- ABC SHA-256: `627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3`
- Formal CEX added: 440 (FN 51, FP 389) across 53 cases and 86 refinement retries
- Final miter status: `{'counterexamples': 1, 'proved': 164, 'skipped': 317}`

## Arm outcomes

| Arm | PASS | rate | Wilson 95% | status counts |
|---|---:|---:|---:|---|
| A_original | 470/482 | 97.51% | 95.70–98.57% | `{'CEC_FAIL': 4, 'PASS': 470, 'TIMEOUT': 8}` |
| B_backport_off | 476/482 | 98.76% | 97.31–99.43% | `{'CEC_FAIL': 4, 'NO_PATCH': 1, 'PASS': 476, 'TIMEOUT': 1}` |
| C_formal_on | 480/482 | 99.59% | 98.50–99.89% | `{'PASS': 480, 'TIMEOUT': 2}` |

## Paired comparisons

| Comparison | old PASS | new PASS | gains | regressions | runtime geo old/new (both PASS) | DT all | CEC all |
|---|---:|---:|---:|---:|---:|---:|---:|
| A_original_to_B_backport_off | 470 | 476 | 9 | 3 | 1.021 | 545→555 | 57→52 |
| B_backport_off_to_C_formal_on | 476 | 480 | 4 | 0 | 0.874 | 555→598 | 52→6 |
| A_original_to_C_formal_on | 470 | 480 | 11 | 1 | 0.895 | 545→598 | 57→6 |

## Clean B→C status changes

Gains: `c5315/c5315_trojan55`, `c5315/c5315_trojan78`, `c7552/c7552_trojan18`, `c880/c880_trojan26`.
Regressions: none.

B versus C isolates the formal flag on the same binary. External ABC CEC is the success authority; a skipped rule miter is not an E↔R proof. Runtime ratios and runtime sums use only cases that PASS in both arms; the DT/CEC columns explicitly sum the full 482-case cohort.

## Input identities

- A results: `749eccd7163ab210249e251f27d3f3df2190faba86e396855f8902666c297429`
- B results: `38ec2c439415d2f20b898f81d5ca268d20e585a4106028e88415e36edf89517a`
- C results: `0ad5f97c18ad8d657d0dc14f885ff643a71a043e3c55be5bf93e8334975c28d1`
