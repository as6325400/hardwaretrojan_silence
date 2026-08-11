# Z3-PB V0 full benchmark

- Branch commit: `4722754`
- Scheduled / runnable / empty GT: 502 / 482 / 20
- Z3-PB PASS: 470/482 (97.51%, Wilson 95% 95.70–98.57%)
- Formal refinement: `0`

## Exact-key paired comparison

| Version | N | old PASS | Z3-PB PASS | Δ pp | gains | regressions | runtime geo old/new |
|---|---:|---:|---:|---:|---:|---:|---:|
| v0 | 482 | 362 | 470 | 22.41 | 109 | 1 | 2.106 |
| v1 | 482 | 432 | 470 | 7.88 | 39 | 1 | 2.443 |
| v2 | 482 | 436 | 470 | 7.05 | 35 | 1 | 2.382 |
| v3 | 482 | 427 | 470 | 8.92 | 43 | 0 | 2.561 |
| v4 | 246 | 229 | 242 | 5.28 | 13 | 0 | 1.969 |
| v5 | 226 | 217 | 224 | 3.10 | 7 | 0 | 1.675 |

V4/V5 are interrupted prefixes, so their rows use only exact available keys. Runtime ratios use pairs that PASS in both snapshots. Historical area/level values are internal reported metrics rather than independently replayed final-netlist metrics.

## Artifact hashes

- Input results: `749eccd7163ab210249e251f27d3f3df2190faba86e396855f8902666c297429`
- Manifest: `84897ac441b355029ec0fced4ec2bef213b1a7600fd68abcab2725ecb7848301`
- Legacy projection: `a8f0fda2733baf5a32384a941883ebbbe624acd801e2ff8c9b009ea95be86f6e`
