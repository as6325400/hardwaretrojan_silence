# Weighted set-cover MILP 與 SAT feedback 實作報告

## 結論

本實作從 `z3-pb-rule-synthesis` 分支的 `4722754` 開始，並另建、推送 `weighted-set-cover-milp` 分支。舊的試作名稱 `lp-set-cover` 已從 remote 移除；新名稱比較精確，因為主問題是 binary weighted set cover，LP 用來提供完整枚舉 master 的 relaxation lower bound / dual telemetry，真正的整數解由 HiGHS MILP 取得。

正式 14-case paired run 的結果：

| 指標 | `z3-pb` | `milp-cover` | 觀察 |
|---|---:|---:|---|
| External ABC CEC | 14 / 14 PASS | 14 / 14 PASS | 28 個 patched benches 全部 equivalent |
| Hard 11 | 11 / 11 PASS | 11 / 11 PASS | 舊 P0 均為 8 / 11 |
| Hard runtime 合計 | 101.767 s | 97.675 s | MILP 少 4.02% |
| Hard wall 合計 | 103.675 s | 99.934 s | MILP 少 3.61% |
| Hard synthesis 合計 | 56.938 s | 55.167 s | MILP 少 3.11% |
| Hard optimizer solver | 504.569 ms | 436.917 ms | MILP 少 13.41% |
| Hard DT builds | 25 | 24 | MILP 少 1 次 |
| All-14 runtime 合計 | 103.124 s | 99.124 s | MILP 少 3.88% |
| All-14 wall 合計 | 105.391 s | 101.740 s | MILP 少 3.46% |
| All-14 optimizer solver | 532.954 ms | 445.852 ms | MILP 少 16.34% |

新 method 在 runtime 上有小幅度改善，但沒有證據顯示它在這批 cases 產生更小的最終 patch：14 / 14 paired patched benches 的 SHA-256 都完全相同。除 `c2670_trojan0` 使用 single-literal model 外，其餘 13 cases 最後都走 verified direct literal cut，所以中間 DNF 的差異沒有進入最終 netlist。

最明顯的成功來自 SAT/CEC feedback 與 direct-cut 安全性修正，而不是單純更換 master solver。舊 P0 中兩法都是 8 / 11 hard PASS；最終版把 `c5315_trojan55`、`c5315_trojan78`、`c7552_trojan73` 轉為 PASS，且沒有狀態退化。其中 `55/78` 各有一輪 formal FN/FP feedback；`73` 沒有 formal 或 CEC retry，因此這個跨 commit 轉移不能全部歸因於 SAT feedback。

## 方法

### 1. 共同的 DT candidate discovery

`z3-pb` 與 `milp-cover` 在每個 rule-build attempt 都只建立一棵 initial DT，在 greedy rule simplification 之前取所有 positive paths 出現過的 feature union。Formal/CEC feedback 進入新 attempt 時仍會 rebuild。兩法共用：

- 同一個 packed feature matrix 和 labels；
- 同一個 raw DT candidate union；
- 同一個 clause/literal cap；
- pattern-signature 去重；
- 最後逐 signature 與逐 packed row 的 0 FP / 0 FN verification。

兩法的 raw candidate universe 相同；但 P4 啟用時，`milp-cover` 會保留 training matrix 上等真值、卻有不同 fanout/arrival 的 physical-node alternatives，而 `z3-pb` 可以合併等真值 candidates。因此主要比較仍是 DNF formulation，但 P4 另外多了保留結構 alternatives 的差異。

### 2. Prime-clause pool

對 positive signature `p` 與 negative signature `n`：

```
D(p,n) = {j | p[j] != n[j]}
```

若 conjunction 要 cover `p` 又排除每個 `n`，所選 features 必須 hit 每個 `D(p,n)`。程式枚舉 literal cap 內的 inclusion-minimal hitting sets；一個不是 minimal 的 safe term 一定有一個更小的 safe subset，後者的 positive coverage 不會變少，所以完整 minimal pool 仍包含相同 candidate universe 下的 lexicographic optimum。

枚舉採 deterministic ordering，並有以下上限：200,000 terms、2,000,000 DFS states、256 recursion depth，且和 LP/MIP 共用總 deadline。任一 cap/timeout 導致 pool incomplete 時回退 DT baseline，不把 restricted solution 誤報為 global optimum。

### 3. HiGHS weighted set-cover master

每條 safe term `t` 有一個 binary `y_t`：

```
for every positive p:
    sum(y_t for t covering p) >= 1

sum_t y_t <= clause_cap
```

所有 pool terms 在進 master 前已證明不 cover known negatives。為了不用脆弱的 big-M 權重，solver 依序進行：

1. LP1 計算完整枚舉 master 的 LP-relaxation lower bound，MIP1 最小化 rule 數 `R`。
2. 固定 `R=R*`，LP2/MIP2 最小化 literal 數 `L`。
3. 固定 `R*/L*`，LP3/MIP3 最小化 unique negative-literal inverter 數 `I`。
4. 固定 `R*/L*/I*`，LP4/MIP4 最小化 graph-level logic-risk proxy。

HiGHS 設定為單執行緒、固定 seed、zero MIP gap。28 / 28 正式 MILP calls 的四階段都是 `Optimal`，沒有 timeout、unavailable 或 fallback。

### 4. Shared-gate / area / fanout / timing cost

當 `R` 和 `L` 固定，目前 direct DNF builder 的 AND+OR gate 數是 `L-1`，因此可因解而改變的直接 gate 成本主要是 expected-zero literals 共用的 inverter cache。LP3/MIP3 將每個 feature 的 shared inverter 建成 exact OR variable；正式 28 calls 的 inverter count 合計從 30 降到 19，共 8 calls 有改善。

LP4/MIP4 在前三個 optimum 已固定後，使用：

- unique tapped features；
- `log1p(base_fanout)` 加權的新增 load；
- 由 DAG arrival level 和 balanced DNF 估計的 unit-delay depth。

正式權重為 0.25 / 0.25 / 0.50。這是結構/routing/timing proxy，不是 physical routing 或 STA。一般 shared subcube factoring 也沒有納入 MILP；目前的實體 shared-gate 目標是 inverter reuse。

### 5. SAT counterexample feedback

可選 `--rule-formal-refine` 建立：

```
E(x) = OR_po(Golden_po(x) XOR Trojan_po(x))
R(x) = learned DNF

FN query: E(x) AND NOT R(x)
FP query: NOT E(x) AND R(x)
```

PI/PO 依名稱對齊，每個 SAT model 再用 scalar simulation 驗證。每次最多回灌 5 個 FN/FP witnesses；兩方向都 UNSAT 才是 rule proof。timeout/unknown 不會當成 proof。

目前 feedback 回到外層，會重建 DT 和 optimizer；還沒有將原 candidate union 持久化成完全 incremental 的 fixed-candidate CEGIS。最後若改用 direct literal cut，conditional rule miter 就不再是該 patch 的 proof，所以最終正確性一律以獨立 external ABC CEC 為準。

### 6. Safe-counterexample-protected direct cut

實驗曝露一個實際漏洞：`c7552_trojan82` 的 conditional rule 經過 SAT feedback 後，downstream 卻一直重複選擇 `new_n792=0` 的 unconditional cut。GT verify PASS，但 ABC CEC 找到 safe false-positive；舊流程沒有用該 hard negative 否決 direct cut，所以相同 CEX 重複到五輪耗盡。

`8f46745` 修正後，每個 direct-cut trial 除了所有 trigger patterns，也必須在累積的 protected non-trigger patterns 上保持 golden output。原 cut 在第二次 build 被明確拒絕，最後選 `new_n2613=0`，內部與外部 CEC 都 PASS。

## 實驗結果

### P0：只替換 DNF master，尚未加 formal feedback / cost objectives

| Hard-11 指標 | `z3-pb` | `milp-cover` |
|---|---:|---:|
| CEC PASS | 8 / 11 | 8 / 11 |
| Runtime | 214.871 s | 207.945 s |
| Synthesis | 109.500 s | 104.731 s |
| Optimizer solver | 1,586.331 ms | 24.580 ms |
| DT builds | 34 | 33 |
| CEC retries | 26 | 25 |

這是最能單獨看出 master formulation 差異的版本：HiGHS clause-pool master 大幅減少 solver time，但 solver 在整體 synthesis 中並非主瓶頸，所以 end-to-end 只改善約 3.2%，且成功率沒變。

### 最終版：MILP + SAT feedback + cost objectives + safe cut

| Hard-11 指標 | `z3-pb` | `milp-cover` | Z3 / MILP |
|---|---:|---:|---:|
| CEC PASS | 11 / 11 | 11 / 11 | — |
| Runtime | 101.767 s | 97.675 s | 1.0419x |
| Wall | 103.675 s | 99.934 s | 1.0374x |
| Synthesis | 56.938 s | 55.167 s | 1.0321x |
| Optimizer solver | 504.569 ms | 436.917 ms | 1.1548x |
| DT builds | 25 | 24 | — |
| CEC retries | 4 | 4 | — |
| Formal feedback rounds | 10 | 9 | — |
| Added CEX (FN / FP) | 50 (21 / 29) | 45 (18 / 27) | — |

Hard runtime 的 paired median `Z3/MILP` 為 1.0413x，geometric mean 為 1.1066x；MILP 在 10 / 11 cases 的 runtime 較快。controls 只有 3 案，固定開銷佔比較高：兩法都 3 / 3 PASS，但 MILP runtime 反而多 6.75%，不應從小樣本推廣。

14-case 合計中，MILP runtime / wall / synthesis 分別少 3.88% / 3.46% / 3.00%，solver time 少 16.34%。兩法的 final effective R/L/D 都是 `14/14/14`，actual area/level 也逐 case 相同。

Hard cases 的最後 patch 全部是 direct literal cut，所以最後 conditional-rule miter 都是 skipped，不得宣稱 SAT-proved。只有 control `c2670_trojan0` 的兩筆 model 最後完成 FN/FP 雙向 UNSAT proof；全部 28 runs 的 correctness 仍來自 external ABC CEC。

### Cost-objective 消融

28 個 MILP calls 的 term-pool totals 為 generated / unique / final / alternatives = `1381 / 310 / 279 / 85`；單次最大只有 `880 / 167 / 155 / 54`。第四階段的 descriptive totals：

| Proxy | MIP3 solution | MIP4 solution |
|---|---:|---:|
| Unique features | 96 | 95 |
| Feature loads | 100 | 100 |
| Fanout stress | 35.5856 | 35.7701 |
| Match depth | 581 | 581 |
| Weighted objective | 15.3251 | 15.2960 |

只有 `c880_trojan3` 的第二次 build（1 / 28 calls）改變 MIP3 tie：unique features `7→6`，fanout stress `2.8928→3.0773`，weighted objective `0.6981→0.6690`。它最後走 direct cut，所以對 patched bench 沒有影響。

額外關掉 P4、保留 P3 + SAT 的 14-case MILP run 也是 14 / 14 PASS，且 14 / 14 patched SHA 與 P4 run 相同。單次 runtime 會受排程和 cache 影響，所以不把 P4 run 較快當成效能結論。

### 為什麼現在不做 column generation / branch-and-price

正式 cohort 的最大 final pool 是 155 terms，最大 generated pool 是 880，遠低於 200,000 cap；28 calls 全部 optimal，也沒有 term-generation timeout。在這個量級下，column generation 會增加 pricing 問題、dual 管理和 restricted-master 完整性的實作風險，但沒有量到必要性。

因此本分支刻意停在 exhaustive clause pool + HiGHS MILP。只有未來大型/multi-Trojan cases 出現 pool cap、term-generation timeout 或 memory 成為主瓶頸，才應進 column generation；完整 branch-and-price 應是再後一階段，不應在沒有 profiling 證據時先增加系統複雜度。

## 重現

建置與測試：

```bash
make -C src HIGHS_ROOT=/home/as6325400/.local/or-tools \
  ../bin/main ../bin/script/show \
  ../bin/script/test_cli_options \
  ../bin/script/test_rule_optimizer \
  ../bin/script/test_set_cover_optimizer \
  ../bin/script/test_rule_miter -j4

bin/script/test_cli_options
bin/script/test_rule_optimizer
bin/script/test_set_cover_optimizer
bin/script/test_rule_miter
python3 -m unittest scripts.test_compare_rule_methods
bash scripts/test_rule_method_telemetry.sh
bash scripts/test_literal_patch_cut_cex.sh
```

正式 paired run：

```bash
python3 scripts/compare_rule_methods.py \
  --profile all \
  --method z3-pb --method milp-cover \
  --highs-library /home/as6325400/.local/or-tools/lib/libhighs.so.1.11.0 \
  --rule-cover-fourth-objective logic-risk \
  --rule-cover-logic-risk-unique-weight 0.25 \
  --rule-cover-logic-risk-fanout-weight 0.25 \
  --rule-cover-logic-risk-timing-weight 0.50 \
  --rule-formal-refine --rule-formal-timeout-ms 10000 \
  --rule-formal-max-rounds 5 --rule-formal-cex-batch 5 \
  --abc-timeout 60 --jobs 1 --force \
  --output-root validation/rule_method_milp_p4_formal
```

正式 raw artifacts 來自 clean commit `8f46745269d86c3b3370fe68a5c1fd25280b56b4`；runner schema 為 `rule-method-ab-run/3`。可追蹤的小型 28-row 投影見 [`experiments/rule_method_milp_p4_formal_2026-08-11/paired_results.csv`](experiments/rule_method_milp_p4_formal_2026-08-11/paired_results.csv)。

## Artifact identities

| Artifact | SHA-256 |
|---|---|
| `bin/main` | `468a2a16c63cbcc36961a642f640dc950003583f238b8811f90ea84fcf1e6d48` |
| `abc` | `627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3` |
| `libhighs.so.1.11.0` | `1586e1655fbbf2bf45c7243829e4b85ed3d79ae5d1376ba7aca7041d806274c5` |
| runner | `bb85251ea9cf7bfcbe98f140a5f3a1395ee3f3a7810ccb154c1b041bcf40a614` |
| case manifest | `b84e0248ad8dc37dc210051d4b165394b9d4fa1e2f415ee2cc620c8ad13c380e` |
| `run_context.json` | `1744ee3cbdd33b7302400943411f89bcadd9bb61d47d848ddaefaedebdfbc21c` |
| `summary.json` | `789d53e00ab4007ac75fce756877609d35589ffe111e874f1475558cde70bb7c` |
| `results.csv` | `83a5a3683fddb1ed319de84d10661720cb841c95cdc672b4afee7f5177299b06` |
| tracked 28-row projection | `bc7acf23c5e6b00e21da670ceb73df00fdc921eaee32b9088a1728153604e46b` |
| records manifest | `8553fbea8f99400d3fc60396b879f73288af5921358c4d203176d5b345e87d3a` |
| raw manifest | `c7c43fafd7649a4b07e44758ce0a7536981967d24dc7dc8523c4879d2f2cf461` |
| patched manifest | `8126ff5f03512215096e6c4ee87c06506ea973c9a211d0585b9ce327a2787e65` |

28 records、140 artifacts、224 provenance references、57 rule-build attempts 都已獨立重算。External ABC 對 28 個 durable patched benches 重播全是 return code 0 且 `Networks are equivalent`；14 / 14 paired Z3/MILP patched SHA 相同。

## Commit 鏈

| Commit | 內容 |
|---|---|
| `4722754` | `z3-pb-rule-synthesis` 基底 |
| `1df6e8a` | HiGHS prime-clause weighted set-cover P0 |
| `a76913a` | A/B runner 的 HiGHS linkage fingerprint |
| `0b01bbb` | 移除 fake negative padding，修正 explicit CEX append |
| `0d3dcfc`, `48842de` | GPU fallback trace rollback 與 deterministic replay |
| `ea2770c`, `313c654`, `9718977` | shared-inverter 第三目標、deadline 與 telemetry |
| `595e99b` | direct SAT rule miter |
| `bafe34a`, `50f5abc`, `1f1ef34` | logic-risk P4 core、marginal telemetry 與 main integration |
| `a365825` | SAT CEX 回灌 synthesis |
| `f3a5b52` | formal/cost-aware comparison harness |
| `54ee56f` | exact integer aggregate 與 non-additive metric filtering |
| `8f46745` | protected safe CEX 否決不安全 direct cuts |

## 限制與下一步

- 正式 cohort 只有 V0 的 11 hard + 3 controls，沒有 multi-Trojan V4、大型 OOD 或多 seed 重複量測。
- 兩個 optimizers 都受限於單棵 greedy DT 的 candidate union；遺漏的 gate 不會被 solver 發現。
- `optimal/verified` 是 candidate union、bounds 與 finite matrix 上的性質；只有 SAT rule proof 或 patched-netlist CEC 能說明全輸入性質。
- Formal feedback 目前會重建 DT；下一個有價值的 refactor 是持久化 feature matrix / raw candidate union，使 miter CEX 只重解 PB/MILP，候選 projection 出現 label conflict 時才擴 tree。
- P4 是 proxy，且這批實驗只改變 1 / 28 個 intermediate models。若要主張 area/timing 改善，需在更多 multi-rule cases 上做 technology mapping / STA，並讓最終 patch 真正使用 optimized DNF。
- Full shared-subcube cost、column generation 和 branch-and-price 都已刻意延後；應先用大型 cases 證明 term pool 或實體 factoring 是瓶頸。
- Runner 已 fingerprint binary、ABC、HiGHS、show 和 inputs；系統 `libz3.so.4` 目前只有 version telemetry，尚未納入 identity manifest。
