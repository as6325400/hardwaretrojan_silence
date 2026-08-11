# Z3-PB + SAT Formal Refinement：完整 V0 實驗報告

## 結論摘要

本實驗把 `E(x) ↔ R(x)` SAT counterexample refinement 整合到 `z3-pb`，並在 V0 有效母體 482 cases 上完成三組 sequential、external-CEC-verified 實驗。

| Arm | 設定 | PASS | 成功率 | Wilson 95% CI | 其他結果 |
|---|---|---:|---:|---:|---|
| A | 原始 Z3-PB | 470/482 | 97.51% | 95.70–98.57% | TIMEOUT 8、CEC_FAIL 4 |
| B | 新 binary，formal OFF | 476/482 | 98.76% | 97.31–99.43% | CEC_FAIL 4、NO_PATCH 1、TIMEOUT 1 |
| C | 同一支新 binary，formal ON | **480/482** | **99.59%** | **98.50–99.89%** | TIMEOUT 2 |

最重要的因果比較是 B→C，因為兩組使用完全相同的 binary、ABC、inputs、timeout 與 runner，唯一差異是 formal flag：

- PASS `476 → 480`，增加 4 案（+0.83 percentage points）。
- 4 gains、0 PASS regressions；McNemar exact two-sided `p=0.125`。
- 四個被救回的案例是 `c5315_trojan55`、`c5315_trojan78`、`c7552_trojan18`、`c880_trojan26`。
- 其餘 non-PASS transition 為 `c5315_trojan24` 的 NO_PATCH→TIMEOUT，以及 `c5315_trojan81` 的 TIMEOUT→TIMEOUT；兩者都沒有被計為 PASS regression。
- internal CEC rounds `52 → 6`（全 482 cases，減少 88.5%）。
- 最終 0 個 CEC_FAIL，只剩 `c5315_trojan24` 與 `c5315_trojan81` 兩個 300 秒 TIMEOUT。

A→C 的 `470 → 480` 是實務上的最終提升，但它包含 formal 以外的 explicit-negative、trace replay 與 CEC-feedback correctness fixes，不能全部歸因 SAT refinement。

## 方法

對同一組 primary-input assignment `x`：

```text
E(x) = OR_po (Golden_po(x) XOR Trojan_po(x))
R(x) = Z3-PB 合成的 DNF trigger rule

漏報 query = E(x) AND NOT R(x)
誤報 query = NOT E(x) AND R(x)
```

SAT 找到漏報時，把該 PI pattern 回灌成 positive；找到誤報時，回灌成 protected negative。每次最多取 5 筆，累積後重新建立 DT candidate union 與 Z3-PB rule，最多 5 輪。兩個 query 都 UNSAT 才能證明該 conditional rule 在完整 PI 空間滿足 `E↔R`。

這個 proof 與 patch correctness 是不同層次：

- `E↔R` 只說 rule 是否精確描述原 Trojan 的 observable-error region。
- 最終 patched netlist 是否等價於 Golden，仍以獨立 external ABC CEC 為唯一 PASS authority。
- verified direct literal cut 會 bypass conditional DNF，因此 miter 明確記為 `skipped`，不可宣稱已取得 `E↔R` proof。

## Benchmark protocol

- Manifest：502 scheduled cases，其中 20 筆 ground-truth pattern 為空，故 runnable 母體為 482。
- Circuit 分布：AES 1、c2670 100、c3540 100、c5315 100、c6288 1、c7552 84、c880 96。
- 所有 runnable cases 都使用 `depth=10`、`neg-ratio=50`、main timeout 300 秒、external ABC timeout 60 秒、`jobs=1`。
- Formal C 使用 `timeout=10000 ms`、`max_rounds=5`、`cex_batch=5`。
- B/C frozen binary SHA-256：`2bebfa7eadefbcbda545d255dbd26bfa2da85a7adeb0097bffd9d36a61668b41`。
- ABC SHA-256：`627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3`。
- Manifest SHA-256：`84897ac441b355029ec0fced4ec2bef213b1a7600fd68abcab2725ecb7848301`。
- Feature branch：`z3-pb-formal-refinement`；核心 commits 為 `9f93e91`（rule miter）與 `fbf4817`（回灌整合）。

## Clean formal ablation：B → C

### Correctness

| Circuit | N | B PASS | C PASS | gains | regressions |
|---|---:|---:|---:|---:|---:|
| aes | 1 | 1 | 1 | 0 | 0 |
| c2670 | 100 | 100 | 100 | 0 | 0 |
| c3540 | 100 | 100 | 100 | 0 | 0 |
| c5315 | 100 | 96 | 98 | 2 | 0 |
| c6288 | 1 | 1 | 1 | 0 | 0 |
| c7552 | 84 | 83 | 84 | 1 | 0 |
| c880 | 96 | 95 | 96 | 1 | 0 |
| **Total** | **482** | **476** | **480** | **4** | **0** |

### Runtime trade-off

Runtime 只在 B、C 都 PASS 的 476 個 paired cases 上比較，避免把 timeout/failed run 的缺值混入：

| Metric | B formal OFF | C formal ON | 解讀 |
|---|---:|---:|---|
| runtime sum | 5392.824 s | 5552.563 s | C +2.96% |
| wall sum | 5477.301 s | 5637.889 s | C +2.93% |
| runtime ratio geometric mean（B/C） | — | 0.874 | typical case C 約慢 14.4% |
| wall ratio geometric mean（B/C） | — | 0.888 | typical case C 約慢 12.6% |
| DT builds（paired subset） | 531 | 580 | formal feedback 會 rebuild |
| internal CEC rounds（paired subset） | 32 | 4 | 減少 87.5% |

Formal 的主要價值是提高成功率並把昂貴的 post-patch CEC retry 提前轉成 rule-level counterexamples；它不是無條件的 runtime optimization。

B 的 hard-14 subset 先執行，接著跑 C 全集，再回頭完成 B 的其餘 468 案；三段皆為 `jobs=1` 且沒有執行重疊。雖然 B/C 的 tool/input identities 相同，runtime 仍可能受到執行順序與系統 cache 影響，因此效能數字應視為 paired empirical measurement，不是隔離到硬體 noise 的 microbenchmark。

### Formal telemetry

- 53 cases 接受過 SAT feedback，共加入 440 個 CEX：51 FN、389 FP。
- 573 個 miter events：164 `proved`、88 `counterexamples`、321 `skipped`；miter checks 共 839 次。
- 86 次 rule refinement retry。
- rule-miter 總時間 88.583 秒，其中 solver 77.863 秒。
- 最後狀態：164 `proved`、317 `skipped`、1 `counterexamples`。
- 317 個 skipped 全是 direct `literal_patch_cut`；164 個 proved 全是 `stats_literal` conditional rules。

四個 clean gains 共用了 40 個 SAT CEX：

| Case | FN / FP | B→C | DT builds | CEC rounds |
|---|---:|---|---:|---:|
| c5315_trojan55 | 3 / 2 | CEC_FAIL→PASS | 5→3 | 5→1 |
| c5315_trojan78 | 3 / 2 | CEC_FAIL→PASS | 5→3 | 5→1 |
| c7552_trojan18 | 3 / 17 | CEC_FAIL→PASS | 5→5 | 5→0 |
| c880_trojan26 | 6 / 4 | CEC_FAIL→PASS | 5→3 | 5→0 |

四案的最終 repair 都走 direct cut，因此成功結論來自 external ABC CEC，而不是宣稱 final DNF miter proved。

## 對歷史 v0–v5

### 原始 Z3-PB（A）

| Historical version | exact-key N | old PASS | A PASS | Δ pp | gains / regressions | runtime geo old/A |
|---|---:|---:|---:|---:|---:|---:|
| v0 | 482 | 362 | 470 | +22.41 | 109 / 1 | 2.106 |
| v1 | 482 | 432 | 470 | +7.88 | 39 / 1 | 2.443 |
| v2 | 482 | 436 | 470 | +7.05 | 35 / 1 | 2.382 |
| v3 | 482 | 427 | 470 | +8.92 | 43 / 0 | 2.561 |
| v4 | 246 | 229 | 242 | +5.28 | 13 / 0 | 1.969 |
| v5 | 226 | 217 | 224 | +3.10 | 7 / 0 | 1.675 |

### Z3-PB + formal refinement（C）

| Historical version | exact-key N | old PASS | C PASS | Δ pp | gains / regressions | runtime geo old/C |
|---|---:|---:|---:|---:|---:|---:|
| v0 | 482 | 362 | 480 | +24.48 | 119 / 1 | 1.864 |
| v1 | 482 | 432 | 480 | +9.96 | 49 / 1 | 2.156 |
| v2 | 482 | 436 | 480 | +9.13 | 45 / 1 | 2.091 |
| v3 | 482 | 427 | 480 | +11.00 | 53 / 0 | 2.235 |
| v4 | 246 | 229 | 245 | +6.50 | 16 / 0 | 1.710 |
| v5 | 226 | 217 | 225 | +3.54 | 8 / 0 | 1.434 |

v4、v5 是中斷的 lexicographic prefixes，不能把它們的 246/226-case raw rate 當成完整 482-case rate；上表只做 exact-key pairing。歷史 CSV 的 binary/input provenance 也弱於本次 run，因此 historical runtime 屬 snapshot comparison。所有 runtime ratio 只使用雙方都 PASS 且 runtime 有值的 pairs。

## Artifacts

- 純 Z3-PB 的 482-row legacy-compatible CSV：[`results_z3_pb_v0_full.csv`](experiments/z3_pb_v0_vs_v0_v5_2026-08-12/results_z3_pb_v0_full.csv)
- 純 Z3-PB 對 v0–v5 的逐案 CSV：[`z3_pb_vs_v0_v5_cases.csv`](experiments/z3_pb_v0_vs_v0_v5_2026-08-12/z3_pb_vs_v0_v5_cases.csv)
- 純 Z3-PB 對 v0–v5 的摘要 CSV：[`z3_pb_vs_v0_v5_summary.csv`](experiments/z3_pb_v0_vs_v0_v5_2026-08-12/z3_pb_vs_v0_v5_summary.csv)
- Formal A/B/C 的 482-row paired CSV：[`z3_pb_formal_ab_cases.csv`](experiments/z3_pb_formal_ab_v0_full_2026-08-12/z3_pb_formal_ab_cases.csv)
- Formal A/B/C 摘要：[`z3_pb_formal_ab_summary.csv`](experiments/z3_pb_formal_ab_v0_full_2026-08-12/z3_pb_formal_ab_summary.csv)
- Formal per-circuit 摘要：[`z3_pb_formal_ab_by_circuit.csv`](experiments/z3_pb_formal_ab_v0_full_2026-08-12/z3_pb_formal_ab_by_circuit.csv)

完整 raw logs、patched benches 與 per-run JSON records 保留在 validation output roots，不納入 Git；tracked CSV 是可攜式投影。三組 run 的 PASS 都由 external ABC CEC marker 加 return code 0 決定。

## Independent QA

- A/B/C 各 482 unique keys，與 manifest runnable set完全相同；aggregate CSV、summary 與 per-case records 可互相逐 byte/逐物件重建。
- 全量驗證 A/B/C 共 7,196 個 artifact references 的 size 與 SHA-256，0 mismatch；971 個唯一輸入共 36,031,709,775 bytes 重新雜湊，0 mismatch。
- 重新獨立執行 external ABC CEC 共 1,436 個 final patched artifacts：A 470 equivalent、B 476、C 480，與已記錄結果 0 mismatch。
- B/C 的 binary、ABC、runner、show、manifest 與非 formal 參數相同；B 的 482 commands 都沒有 formal flags，C 的 482 commands 都是 10,000 ms / 5 rounds / batch 5。
- A 使用較舊 binary/schema，且其 run record 記為 git dirty；因此 A→C 只作 practical/historical comparison，formal feature 的因果結論只引用 clean B→C。
