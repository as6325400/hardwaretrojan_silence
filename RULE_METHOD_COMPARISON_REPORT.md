# Rule synthesis 方法比較報告

## 結論摘要

本報告比較目前兩條正式流程：`vn-retrain` 與 `z3-pb`。判定修補是否成功時，以 runner 另外呼叫的 **外部 ABC CEC**（patched circuit 對 golden circuit）為主要依據；`GT verify` 只代表有限 groundtruth patterns 通過，不等同所有輸入皆等價。

在 11 個過去會多次 rebuild decision tree 的 `rebuild11` hard cases 上：

| 指標 | `vn-retrain` | `z3-pb` | 觀察 |
|---|---:|---:|---|
| 外部 ABC CEC PASS | 7 / 11 | 8 / 11 | `z3-pb` 多通過 `c7552_trojan23`，沒有既有 PASS 退化成 FAIL |
| GT verify PASS | 11 / 11 | 11 / 11 | 也顯示 GT PASS 不能取代 CEC |
| main 回報 runtime 合計 | 553.997 s | 188.582 s | `z3-pb` 合計約快 2.94 倍 |
| paired runtime ratio 中位數 | — | — | `vn-retrain / z3-pb = 2.64x` |
| 兩法皆 CEC PASS 的 7 cases，paired 幾何平均 | — | — | `z3-pb` 約快 2.62 倍 |
| decision-tree builds 合計 | 156 | 34 | 減少 122 次（78.2%） |
| CEC retry rounds 合計 | 32 | 26 | 少 6 輪 |

在 3 個 controls 上，兩法都是 3 / 3 external CEC PASS；`z3-pb` 的 runtime 合計為 1.096 s，`vn-retrain` 為 2.222 s，DT builds 則由 10 降為 3。這批資料支持「先建一棵 DT，再對候選 union 做全域 0–1 最佳化」能顯著減少重訓成本；但 11 個 hard cases 仍有 3 個兩法皆 CEC FAIL，因此不能宣稱問題已被全面解決。

## 比較的是什麼

### `vn-retrain`

目前正式 VN 流程不是舊文件所寫的三輪 subclause expansion。每個 synthesis pass 的實作為：

1. 用 base candidates 建一棵淺層 DT，取得重要 gates。
2. 若不是單一 literal，從重要 gates 加上 signature 排名的 base pool（最多 64）生成 pair/triple AND 型 VN；正樣本最多 32、負樣本目標 8–32，signature states 與輸出候選各最多 300。
3. 用這批 on-the-fly VN 重訓一次。
4. 再訓練一次以找出實際被 tree 使用的 VN，只把 used VN materialize 到 circuit。
5. 對更新後的 candidates 做 final DT mining。

因此一般 VN case 每個 CEC attempt 會有 4 次 DT build；phase-1 已是單一 literal 時通常是 2 次。正式 artifact 中多數 VN 最後 `vn_used=0`，但前置重訓成本仍然存在。

### `z3-pb`

`z3-pb` 先建一棵 DT，將 raw positive DT paths 出現過的 feature 做 union，然後在同一份有限 training matrix 上做 bounded DNF 全域重合成。它只取代 rule synthesis 的 VN 重訓；後面的 payload-node Z3/MaxSAT 分析與 patch application 仍是兩種方法共用的 downstream 流程。設：

- `a_k`：第 `k` 條 clause 是否啟用；
- `x[k,j,0]`、`x[k,j,1]`：clause `k` 是否選 feature `j` 的 0/1 polarity；
- `m[s,k]`：pattern signature `s` 是否符合 clause `k`。

主要 0–1 constraints 為：同一 feature 在同一 clause 不可同時選兩種 polarity；被選 literal 必須屬於 active clause；active clause 至少一個 literal且不超過 literal cap；positive signature 至少符合一條 active clause；negative signature 不得符合任何 active clause。目標採 lexicographic optimization：

1. 最小化 active clauses 數量；
2. 再最小化 selected literals 數量。

solver 是 **Z3 Optimize 的 pseudo-Boolean / MaxSMT backend**。這個 Boolean 模型可視為 0–1 ILP-equivalent formulation，但它不是 generic MILP solver，也不建立或公開 LP relaxation，因此沒有可報告的 MILP optimality gap。文件中的 `optimal=1` 僅表示在指定 candidate union、clause/literal bounds 與有限 training signatures 下，該 PB 目標已求得最優解。

為避免一開始加入所有 constraints，實作以 deterministic stratified seeds 起始，解完後掃描完整的有限 signature table，每輪最多加入 5 個真正分類錯誤的 signatures，再重解；預設最多 100 checks、每次 optimizer call 共用 10,000 ms wall-clock budget。找到對完整 training matrix 為 0 FP / 0 FN 的模型才接受，否則保留 DT baseline。

這裡的「完整掃描」仍只是**目前有限 training matrix**，不是遍歷全部 `2^|PI|` 輸入。candidate feature 也只來自單棵 raw DT 的 positive paths，且相同 training signature 的 features 會去重。兩個 feature 在 training rows 上相同，不代表在未觀察輸入上等價；最終是否涵蓋全部輸入仍由外部 ABC CEC 判定。

## 11 個 hard cases

`synth R/L` 是最後一個 CEC attempt 的 `rule_synth_summary` 所記錄之 synthesis-stage rule/literal 數；這個 telemetry 在後續 signature minimization、literal patch cut、rule-match merge 與實際 patch application **之前**輸出，因此不能解讀成最後真正 applied patch logic 的 R/L。現有 artifacts 沒有跨所有 patch branches 統一的 applied-rule-count 欄位，故不以不完整的 raw-log推估值補表。`DT` 是該 case 所有 CEC attempts 的 DT build 合計。runtime 採程式輸出的 `[TIMING] TOTAL`，ratio 為 `vn-retrain / z3-pb`。`CEC_FAIL` 即外部 ABC 判定不等價。

paired CSV 仍忠實保留每筆 run 的 actual area/level 欄位，但 CEC_FAIL netlist 並非正確 patch；本報告只在 external CEC PASS 的 paired cases 上解讀結構差異。

| Case | `vn-retrain`: ABC / retry / runtime / DT / synth R-L | `z3-pb`: ABC / retry / runtime / DT / synth R-L | ratio |
|---|---|---|---:|
| `c5315_trojan28` | PASS / 1 / 2.437 s / 8 / 1-5 | PASS / 1 / 0.822 s / 2 / 1-5 | 2.96x |
| `c5315_trojan34` | PASS / 1 / 3.598 s / 8 / 1-4 | PASS / 1 / 1.361 s / 2 / 1-4 | 2.64x |
| `c5315_trojan55` | CEC_FAIL / 5 / 154.805 s / 20 / 2-9 | CEC_FAIL / 5 / 62.312 s / 5 / 3-14 | 2.48x |
| `c5315_trojan78` | CEC_FAIL / 5 / 183.982 s / 20 / 3-14 | CEC_FAIL / 5 / 85.224 s / 5 / 3-13 | 2.16x |
| `c7552_trojan23` | CEC_FAIL / 5 / 102.893 s / 20 / 2-5 | PASS / 0 / 5.632 s / 1 / 1-2 | 18.27x |
| `c7552_trojan53` | PASS / 1 / 3.320 s / 8 / 1-2 | PASS / 1 / 1.199 s / 2 / 1-2 | 2.77x |
| `c7552_trojan73` | CEC_FAIL / 5 / 94.313 s / 20 / 2-5 | CEC_FAIL / 5 / 28.698 s / 5 / 2-5 | 3.29x |
| `c7552_trojan82` | PASS / 1 / 3.197 s / 8 / 2-3 | PASS / 1 / 1.255 s / 2 / 2-3 | 2.55x |
| `c880_trojan26` | PASS / 4 / 1.845 s / 20 / 1-2 | PASS / 4 / 0.763 s / 5 / 1-2 | 2.42x |
| `c880_trojan3` | PASS / 3 / 2.756 s / 16 / 2-7 | PASS / 2 / 0.902 s / 3 / 2-6 | 3.06x |
| `c880_trojan7` | PASS / 1 / 0.850 s / 8 / 1-2 | PASS / 1 / 0.414 s / 2 / 1-2 | 2.05x |

值得單獨記錄的差異：

- `c7552_trojan23`：`z3-pb` 首輪 external CEC PASS，patch 相對 golden 為 area `+6`、level `+0`；`vn-retrain` 五輪後仍 FAIL。
- 在兩法皆 PASS 的 7 cases 中，6 cases 的 area/level delta 相同；`c880_trojan3` 的 `z3-pb` 為 area `+7`、level `+0`，`vn-retrain` 為 `+28`、`+5`，最後一次 synthesis summary 的 literals 也由 7 降為 6。
- hard profile 的 34 次 PB optimizer calls 全部 accepted；Z3 solver time 合計約 1.436 s。不過 `c5315_trojan55` 與 `c5315_trojan78` 各用了約 0.740 s、0.470 s，且最後仍未通過 external CEC，說明 training optimum 不保證全輸入正確。

## 3 個 controls

| Case | `vn-retrain`: ABC / runtime / DT / synth R-L | `z3-pb`: ABC / runtime / DT / synth R-L | ratio |
|---|---|---|---:|
| `c2670_trojan0` | PASS / 0.533 s / 2 / 1-1 | PASS / 0.366 s / 1 / 1-1 | 1.46x |
| `c5315_trojan26` | PASS / 1.260 s / 4 / 1-5 | PASS / 0.472 s / 1 / 1-5 | 2.67x |
| `c880_trojan30` | PASS / 0.429 s / 4 / 1-2 | PASS / 0.258 s / 1 / 1-2 | 1.67x |

三組 controls 的 CEC retry 都是 0，且 paired area/level 與 synthesis-stage R/L 都相同。這代表新方法在這個小型 control set 沒有觀察到 correctness 或結構退化；樣本數只有 3，不能推廣為普遍保證。

## 實驗設定與重現

正式結果是在 commit `96ffd5a51986ccb88fae74504a4c0357b696a09a`、clean worktree、單工作 (`jobs=1`) 下產生。共同參數是 `--depth 10 --neg-ratio 50 --mine-rounds 15 --mine-max 5000`。但目前 `main` 的 rule-synthesis calls 會固定使用 `eval_count=0, mine_rounds=1, mine_max=0`；後兩個 CLI 值目前被解析與記錄，並未驅動這條正式路徑的 hard-negative loop。要重現下列 exact SHA，必須在該 commit 建置，並使用 `run_context.json` 所列同一組 input/tool identities；在較新的 commit 重跑只能視為同 profile 的新實驗，SHA 預期會不同。

先執行單元與整合測試：

```bash
make -C src ../bin/script/test_rule_optimizer -j4
bin/script/test_rule_optimizer
python3 scripts/test_compare_rule_methods.py
bash scripts/test_rule_method_telemetry.sh
```

再重跑正式 profiles：

```bash
python3 scripts/compare_rule_methods.py \
  --profile rebuild11 \
  --output-root validation/rule_method_ab_rebuild11 \
  --jobs 1 --force

python3 scripts/compare_rule_methods.py \
  --profile controls \
  --output-root validation/rule_method_ab_controls \
  --jobs 1 --force
```

runner 會為每個 case/method 保留 stdout、stderr、外部 CEC log、patched bench 與 JSON record，並原子化重建 `results.csv` 與 `summary.json`。正式資料位於：

- `validation/rule_method_ab_rebuild11/`：11 cases × 2 methods，共 22 records。
- `validation/rule_method_ab_controls/`：3 cases × 2 methods，共 6 records。
- 可追蹤的小型投影表 [`experiments/rule_method_ab_2026-08-11/paired_results.csv`](experiments/rule_method_ab_2026-08-11/paired_results.csv)：28 data rows，只保留比較欄位，不含絕對路徑或大型巢狀 JSON；其內容已逐欄對回上述兩個 `results.csv`。

## Commit 鏈

| Commit | 內容 |
|---|---|
| `f61946e` | 保存 v6 signature-minimization baseline |
| `b14b30a` | 將 `vn-retrain` 暴露成可選且可量測的 rule strategy，加入 telemetry |
| `5a919ef` | 新增有限 training matrix 上的 bounded-DNF 0–1 PB optimizer 與 unit tests |
| `edb386c` | 把 `z3-pb` 接進 mining/CLI，加入 CEGIS、fallback 與摘要欄位 |
| `96ffd5a` | 新增固定 manifest、A/B runner、外部 ABC CEC 與可續跑 artifacts |

## Artifact identity / SHA-256

兩個 profiles 的 tool/input context 相同：

- `bin/main`: `0993ea78ed8ec08833373ea50340cae8925eca42f505befe699c62c0a0cea558`
- external `abc`: `627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3`
- `bin/script/show`: `489c546239fb338464a2cbf6abf366d7b4eb475abac6fbde3f281933f6e2a189`
- case manifest: `b84e0248ad8dc37dc210051d4b165394b9d4fa1e2f415ee2cc620c8ad13c380e`
- context key: `85b8beb167e954a39b698dd00c6ca67758d4fe9494b14fe4bdb51ab9f13baded`

聚合檔 SHA-256：

| Profile | `results.csv` | `summary.json` | `run_context.json` |
|---|---|---|---|
| `rebuild11` | `895e17bfafaa30bdd5c443eb1ea98221acde2156a0ea4f4c0ac6cc11332c11b9` | `15fc3b6fd9a4ecda010ca745d52be278116eba9d6d13fc3d2ba61ddad7ad20ad` | `b8f1042c45be07ef2eb0e90e760cad5730da9f40d0110ec06eb8d2e2d401add3` |
| `controls` | `ef9f1b5a25232141efadaa801ed19c94845e235f4f2e6a101aadde3eccfc9ad5` | `765c022f58ec018279bd8f4d1f3a7bd670e9bf5ac6ec5f707e24dc7dea067d70` | `b8f1042c45be07ef2eb0e90e760cad5730da9f40d0110ec06eb8d2e2d401add3` |

小型 paired projection CSV SHA-256：`9150f87a2c0f8f9b2539712445b783cfafec3926cff6bd93e12dab1aff566273`。

`summary.json` 的每筆 record 內另有 `artifact_identities`，逐一記錄 stdout/stderr、external CEC logs 與 patched bench 的 SHA-256。為方便驗整批 raw logs，以下 digest 是在各 profile 目錄內，對 `find raw -type f -print0 | sort -z | xargs -0 sha256sum` 的輸出再做一次 SHA-256：

- `rebuild11/raw`（88 files）：`ccc6c5ab2d47cca37bfd00c6d97a22e7dd46e02544574c8de7527ae8461190b6`
- `controls/raw`（24 files）：`b0a0ba0ead0d7a62c035d0cafb8159686c1495270ec7d3fa7c3b59bd5136a962`

## 限制與下一步

- Cohort 只有 V0 single-trigger/single-payload 的 11 hard + 3 controls；不能代表 multi-Trojan、multi-payload 或更大電路。
- 目前每個 case/method 只有一次正式 run，沒有多 seed/重複試驗與信賴區間；runtime 結果是工程性比較，不是統計結論。
- `z3-pb` 的候選被單棵 greedy DT 的 positive paths 限制；DT 沒看見的 gate，optimizer 無法選到。
- 相同 finite-training signature 的 feature 會被合併，可能掩蓋未觀察輸入上的語意差異。
- bounded DNF 的 clause cap 不會超過目前 baseline rule count，literal cap 預設為 10；這些 bounds 可能讓較佳或必要的模型不可行。
- optimizer timeout、infeasible、unknown、max-rounds 或 verification failure 都會安全回退 DT baseline，但回退不代表 patch 能通過 CEC。
- 三個共同失敗 case 應優先分析 external CEC counterexamples，區分 candidate-union 不完整、DNF bounds 不足、trigger model 錯誤或 payload patch 錯誤，再決定是否加入 top-k trees、候選擴張或跨 CEC round 累積 constraints。
