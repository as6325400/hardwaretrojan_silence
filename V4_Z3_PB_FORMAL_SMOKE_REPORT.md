# Z3-PB + SAT Formal Refinement：V4 Multi-Trojan Smoke

## 結論

V4 已接進原本的 Z3-PB rule-repair runner，且用同一支 binary 完成 formal OFF/ON 的 13-case paired smoke。這批案例刻意涵蓋 1、2、3、5 個 Trojan、trigger size 3/5、disjoint/shared trigger、small/medium/large-OOD circuit。

| 設定 | PASS | CEC_FAIL | NO_PATCH | TIMEOUT |
|---|---:|---:|---:|---:|
| Z3-PB，formal OFF | 2/13 | 8 | 1 | 2 |
| Z3-PB，formal ON | **3/13** | 4 | 4 | 2 |

Formal refinement 造成 1 個 `CEC_FAIL → PASS`、0 個 PASS regression。它確實能修正部分不精確 rule，但目前 multi-Trojan 的主要限制不是缺少反例，而是既有 repair 表達能力、候選／patch selection 與 large-circuit scaling：

- N=1：2/2 PASS；兩案最後都是 externally CEC-verified direct cut，rule miter 因 bypass DNF 而正確記為 `skipped`。
- N=2：formal OFF 0/5，ON 1/5；唯一 gain 為 `c880_n2_t3_o000_s2004`，ON 最後取得 `E↔R` proof 並通過 external ABC CEC。
- N=3：兩邊都是 0/5。
- N=5：兩邊都是 0/1，結果為 `NO_PATCH`。
- shared trigger：兩邊都是 0/2。
- medium `mem_ctrl` N=2/N=3：兩邊均為 CEC_FAIL；ON 的 rule miter 達 10 秒 soft budget，沒有取得反例或 proof。
- large-OOD `aes` N=2/N=3：OFF/ON 都在 300 秒 main timeout；這發生在 formal feedback 能改善結果之前。

因此這份 smoke 不支持「目前 Z3-PB+formal 已可泛化修復 multi-Trojan」的說法。較準確的結論是：SAT feedback 對 rule correctness 有局部增益，但 V4 暴露了 single-payload-oriented repair flow 與 feature/training-matrix scalability 的明顯缺口。

## 實驗設定

- Dataset：V4 `735` scheduled、`689` GT-ready、`46` rejected。
- Smoke selection：每個指定 stratum 依 `combined.bench + groundtruth.json` byte size 取最小案例；這是快速工程 smoke，不是隨機樣本，也不是成功率估計。
- 共同參數：depth 10、negative ratio 50、mine rounds 15、mine max 5000、main timeout 300 秒、external ABC timeout 60 秒、jobs 1。
- Formal ON：rule-miter timeout 10,000 ms、max rounds 5、CEG batch 5。
- PASS authority：獨立 external ABC CEC；finite GT verify 或 main return code 均不能取代它。
- 同一 binary SHA-256：`2bebfa7eadefbcbda545d255dbd26bfa2da85a7adeb0097bffd9d36a61668b41`。
- 同一 ABC SHA-256：`627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3`。
- Manifest SHA-256：`a85a6a75260a9ff659d91ec4bc50a432e1343979418e94a24c581448fbacee82`。

目前 loader 只使用 V4 `groundtruth.json` 中的 positive `pi_order/pattern_bits`，與原方法保持一致。它不讀 `negative_patterns.json`、instance mask 或 Trojan metadata，因此 formal OFF/ON 比較沒有額外 oracle leakage。

## Formal telemetry

Formal ON 共：

- 加入 240 個 circuit-derived counterexamples：144 FN、96 FP。
- 執行 254 次 miter checks。
- miter wall telemetry 合計 111.868 秒。
- 最終 miter status：proved 1、skipped 2、counterexamples 6、timeout 2；另兩個 AES case 在進入可用 miter telemetry 前 main timeout。

唯一 gain `c880_n2_t3_o000_s2004` 累積加入 35 個反例（21 FN、14 FP），最後 rule miter `proved`，external ABC CEC 也 PASS。這是 SAT feedback 工作原理的正面實例；其他 N≥2 案即使累積 30–50 筆反例，仍未得到可用 patch。

## Runtime trade-off

13 案 wall time 總和：

| 設定 | wall sum |
|---|---:|
| formal OFF | 758.231 s |
| formal ON | 1432.980 s |

這個總和包含四個 AES timeout（每個 arm 各兩個），不可解讀為 typical slowdown。唯一公平的 both-PASS cohort 只有兩個 N=1 cases，OFF/ON wall sum 分別 0.829/0.825 秒，樣本太小，不能得出 runtime 優勢。對失敗的 small multi-Trojan，formal 常將約 1–5 秒 run 延長至 4–73 秒；medium cases 延長至約 268–286 秒。

## 可重現工具與結果

- Manifest generator：[`scripts/generate_v4_rule_benchmark_manifest.py`](scripts/generate_v4_rule_benchmark_manifest.py)
- Immutable hardlink materializer：[`scripts/materialize_v4_benchmark_inputs.py`](scripts/materialize_v4_benchmark_inputs.py)
- Paired analyzer：[`scripts/analyze_v4_z3_pb_formal.py`](scripts/analyze_v4_z3_pb_formal.py)
- 13-row projection：[`experiments/v4_z3_pb_formal_smoke_2026-08-12/paired_results.csv`](experiments/v4_z3_pb_formal_smoke_2026-08-12/paired_results.csv)
- Strata：[`experiments/v4_z3_pb_formal_smoke_2026-08-12/strata.csv`](experiments/v4_z3_pb_formal_smoke_2026-08-12/strata.csv)
- Aggregate JSON：[`experiments/v4_z3_pb_formal_smoke_2026-08-12/summary.json`](experiments/v4_z3_pb_formal_smoke_2026-08-12/summary.json)
- Frozen source manifest、四份 raw result CSV 與四份 run context：[`experiments/v4_z3_pb_formal_smoke_2026-08-12/raw`](experiments/v4_z3_pb_formal_smoke_2026-08-12/raw/)
- Artifact checksums：[`experiments/v4_z3_pb_formal_smoke_2026-08-12/SHA256SUMS`](experiments/v4_z3_pb_formal_smoke_2026-08-12/SHA256SUMS)

下一個正式實驗應使用 V4 `core_final` 的 scheduled denominator 480、GT-ready denominator 440，並把 generation rejection 與 repair failure 分開。現在這 13 案只用來驗證整合與辨識瓶頸，不應當作論文 headline success rate。
