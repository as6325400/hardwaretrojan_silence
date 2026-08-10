# Rule synthesis 方法比較報告

## 結論摘要

本報告只使用修正後的正式 artifacts：`validation/rule_method_ab_rebuild11_v2` 與 `validation/rule_method_ab_controls_v2`。比較 `vn-retrain` 與 `z3-pb` 時，以 runner 另外啟動的 **external ABC CEC**（patched circuit 對 golden circuit）作 primary correctness result；`GT verify`、finite-training 0 FP/0 FN、`optimizer_verified=1` 都不能取代全輸入 CEC。

11 個過去會多次 rebuild decision tree 的 hard cases 結果如下：

| 指標 | `vn-retrain` | `z3-pb` | 觀察 |
|---|---:|---:|---|
| External ABC CEC PASS | 7 / 11 | 8 / 11 | `z3-pb` 多通過 `c7552_trojan23`，沒有 VN PASS 退化為 FAIL |
| GT verify PASS | 11 / 11 | 11 / 11 | 22 runs 全過 GT，但 7 runs 外部 CEC 仍失敗 |
| Main 回報 runtime 合計 | 586.723 s | 205.769 s | `z3-pb` 合計約快 2.85 倍 |
| Paired runtime ratio 中位數 | — | — | `vn-retrain / z3-pb = 2.67x` |
| 兩法皆 CEC PASS 的 7 cases，paired 幾何平均 | — | — | `z3-pb` 約快 2.60 倍 |
| Decision-tree builds 合計 | 156 | 34 | 少 122 次（78.2%） |
| CEC retry rounds 合計 | 32 | 26 | 少 6 輪（18.8%） |
| 最後 attempt effective R/L/D 合計（全 11 cases） | 18 / 50 / 29 | 16 / 38 / 22 | 含 CEC_FAIL，只作描述性統計 |
| 共同 CEC PASS 7 cases 的 effective R/L/D | 8 / 16 / 13 | 7 / 10 / 10 | 正確 patch 上 PB 的條件總量較小 |

3 個 controls 上兩法皆為 3 / 3 external CEC PASS。`vn-retrain` 與 `z3-pb` 的 runtime 合計分別為 2.207 s、1.131 s，DT builds 為 10、3。這支持「一次 DT 取得 candidate union，再用 0–1 PB 做全域 bounded-DNF 重合成」可減少重訓成本；但 hard cohort 仍有 3 個共同 CEC FAIL，不能宣稱已普遍解決。

## 方法與 telemetry 定義

### `vn-retrain`

現行 VN 流程不是舊版的三輪 subclause expansion。每個 synthesis pass 依序：

1. 在 base candidates 上建 phase-1 DT，取得重要 gates。
2. 以重要 gates 與 signature 排名補成最多 64 個 base gates；最多取 32 positive 與 8–32 negative patterns。
3. 產生帶 polarity 的 pair/triple AND VN，signature states 與輸出候選各最多 300。
4. 用 on-the-fly VN 重訓一次，再訓練一次辨識 used VN。
5. 只 materialize used VN，最後再建 final DT。

一般 VN pass 因此是 4 次 DT build；phase-1 已為單一 literal 時通常是 2 次。v2 hard artifacts 共生成 11,005 個 VN、最後使用 7 個，說明 speculative VN 的主要成本往往在重訓，而非 materialization。

### `z3-pb`

`z3-pb` 先建一棵 DT，將 raw positive DT paths 出現過的 features 做 union，再於同一份有限 training matrix 上求 bounded DNF。設 `a_k` 為 clause active 變數，`x[k,j,0/1]` 為 clause `k` 是否選 feature `j` 的 polarity；signature `s` 是否符合 clause `k` 則以這些變數組成的 match predicate/expression 表示。實作直接建立 expression，沒有另外宣告 `m[s,k]` solver 變數。constraints 要求：

- 同一 clause/feature 至多選一個 polarity；
- selected literal 必須屬於 active clause，active clause 至少一個 literal且不超過 cap；
- positive signature 至少符合一條 active clause；
- negative signature 不得符合任何 active clause。

Z3 Optimize 採 lexicographic objective，先最小化 clauses，再最小化 literals。CEGIS 由 deterministic stratified signatures 起始，每輪掃描完整的**有限 signature table**，加入最多 5 個真正分類錯誤的 signatures；預設每次 optimizer call 共用 10,000 ms、最多 100 checks。

這是 **Z3 Optimize 0–1 pseudo-Boolean formulation**，在此 Boolean model 上可稱 0–1 ILP-equivalent；它不是 generic MILP solver，也不建立或公開 LP relaxation，因此沒有可報告的 MILP optimality gap。`optimal=1` 與 `verified=1` 只表示在 candidate union、DNF bounds 與 finite training matrix 上達成最優且 0 FP/0 FN，不是遍歷全部 `2^|PI|` 輸入。

v2 使用 `--rule-opt-max-clauses 0` 的新預設，表示由當次 DT baseline rule count 推導 cap；明確指定非零值時會照指定值使用，不再被 baseline count 截斷。literal cap 預設仍為 10，設為 0 才改用 baseline 最大 clause 長度。`z3-pb` 只取代 rule synthesis；payload-node Z3/MaxSAT 與 patch application 仍是兩法共用的 downstream 流程。

### Synthesis、applied 與 effective

v2 將先前容易混淆的 rule 大小拆開：

- `rule_synth_summary synthesized_rules/literals/depth`：剛完成 DT/PB synthesis、尚未做 signature minimization 或 literal patch cut 的模型。
- `rule_apply_summary source`：後處理或修補分支，例如 `signature_minimize`、`signature_single_literal`、`stats_literal`、`literal_patch_cut`。
- `applied_*`：後處理完、由 downstream repair 消費的 rule model 大小。single-literal model 可被 direct trigger-kill 消費，multi-literal/rule model 才作為 conditional patch 條件；直接 literal cut 完全 bypass model，因此為 `0/0/0`。
- `effective_*`：跨分支比較用的有效條件大小。verified direct literal cut 雖然 `applied_* = 0/0/0`，仍記為一個有效 predicate/action，即 `1/1/1`。

下表的 `S→E` 是最後一個 CEC attempt 的 `synthesized R/L/D → effective R/L/D`。它不把 CEC_FAIL 的小條件誤當成正確 patch；結構品質只在 external CEC PASS 的結果上解讀。

面積採 runner 對最終 patched bench 重新執行 `show` 得到的 `actual_area_delta_*`。hard profile 的 8 / 22 multi-rule runs（`effective_rules > 1`）中，main 的 `reported_area_delta` 全部低估最終 netlist 面積增量；因此本報告不以該欄作正式面積比較。

## 11 個 hard cases

`DT` 為所有 CEC attempts 的 build 合計；runtime 是 `[TIMING] TOTAL`；ratio 為 `vn-retrain / z3-pb`。source 縮寫：`cut` = `literal_patch_cut`、`sig` = `signature_minimize`、`sig1` = `signature_single_literal`、`skip` = `signature_minimize_skipped`、`stats` = `stats_literal`。

| Case | `vn-retrain`: ABC / retry / runtime / DT / S→E / source | `z3-pb`: ABC / retry / runtime / DT / S→E / source | ratio |
|---|---|---|---:|
| `c5315_trojan28` | PASS / 1 / 2.608 s / 8 / 1-5-5→1-1-1 / cut | PASS / 1 / 0.985 s / 2 / 1-5-5→1-1-1 / cut | 2.65x |
| `c5315_trojan34` | PASS / 1 / 3.753 s / 8 / 1-4-4→1-4-4 / sig | PASS / 1 / 1.359 s / 2 / 1-4-4→1-4-4 / sig | 2.76x |
| `c5315_trojan55` | CEC_FAIL / 5 / 165.676 s / 20 / 2-9-5→2-8-4 / sig | CEC_FAIL / 5 / 76.841 s / 5 / 3-14-6→3-11-4 / sig | 2.16x |
| `c5315_trojan78` | CEC_FAIL / 5 / 201.292 s / 20 / 4-16-6→4-16-6 / skip | CEC_FAIL / 5 / 88.238 s / 5 / 3-13-5→3-11-4 / sig | 2.28x |
| `c7552_trojan23` | CEC_FAIL / 5 / 103.336 s / 20 / 2-5-3→2-5-3 / sig | PASS / 0 / 5.142 s / 1 / 1-2-2→1-1-1 / cut | 20.10x |
| `c7552_trojan53` | PASS / 1 / 3.415 s / 8 / 1-2-2→1-1-1 / sig1 | PASS / 1 / 1.280 s / 2 / 1-2-2→1-1-1 / sig1 | 2.67x |
| `c7552_trojan73` | CEC_FAIL / 5 / 98.256 s / 20 / 2-5-3→2-5-3 / sig | CEC_FAIL / 5 / 28.719 s / 5 / 2-5-3→2-5-3 / sig | 3.42x |
| `c7552_trojan82` | PASS / 1 / 3.087 s / 8 / 2-3-2→1-1-1 / sig1 | PASS / 1 / 1.298 s / 2 / 2-3-2→1-1-1 / sig1 | 2.38x |
| `c880_trojan26` | PASS / 4 / 1.848 s / 20 / 1-2-2→1-1-1 / cut | PASS / 4 / 0.679 s / 5 / 1-2-2→1-1-1 / cut | 2.72x |
| `c880_trojan3` | PASS / 3 / 2.647 s / 16 / 2-7-4→2-7-4 / sig | PASS / 2 / 0.827 s / 3 / 2-6-3→1-1-1 / cut | 3.20x |
| `c880_trojan7` | PASS / 1 / 0.806 s / 8 / 1-2-2→1-1-1 / sig1 | PASS / 1 / 0.400 s / 2 / 1-2-2→1-1-1 / sig1 | 2.01x |

重點案例：

- `c7552_trojan23`：`z3-pb` 首輪 external CEC PASS，最後採 direct literal cut；patch 相對 golden 為 area `+6`、level `+0`。VN 五輪後仍 FAIL。
- 兩法皆 PASS 的 7 cases 中，6 cases 的 effective R/L/D 與 area/level delta 相同。
- `c880_trojan3`：VN 最後使用 effective `2/7/4`，area/level `+28/+5`；PB 從 synthesized `2/6/3` 找到 direct cut，effective `1/1/1`，area/level `+7/+0`。
- hard profile 的 34 次 PB optimizer calls 全部 accepted、optimal 且 finite-matrix verified；solver time 合計 1.449 s。但 `c5315_trojan55`、`c5315_trojan78` 仍 external CEC FAIL，再次證明 training optimum 不是全輸入 correctness。

## 3 個 controls

| Case | `vn-retrain`: ABC / runtime / DT / S→E / source | `z3-pb`: ABC / runtime / DT / S→E / source | ratio |
|---|---|---|---:|
| `c2670_trojan0` | PASS / 0.485 s / 2 / 1-1-1→1-1-1 / stats | PASS / 0.320 s / 1 / 1-1-1→1-1-1 / stats | 1.52x |
| `c5315_trojan26` | PASS / 1.246 s / 4 / 1-5-5→1-1-1 / cut | PASS / 0.496 s / 1 / 1-5-5→1-1-1 / cut | 2.51x |
| `c880_trojan30` | PASS / 0.477 s / 4 / 1-2-2→1-1-1 / cut | PASS / 0.314 s / 1 / 1-2-2→1-1-1 / cut | 1.52x |

三組 controls 的 CEC retry 都是 0，paired effective R/L/D、area/level 與 apply source 皆一致。control set 只有 3 cases，不能推廣為普遍保證。

## Runner provenance 與重現

v2 artifacts 由 commit `5659fdf7b50276d7653a0824c773d34b819fc02c`、clean worktree、runner schema `rule-method-ab-run/2` 產生。runner 有以下保護：

- 強制 `--jobs 1`；其他值在開始寫 artifact 前即拒絕，避免同 case/method 共用中間 `*_rule_merged.bench` 造成競爭。
- 將 internal CEC 的 `ABC_BIN` 固定為 runner 已 fingerprint 的同一支 ABC；external CEC 也要求 equivalence marker 與 return code 0。
- 執行前 fingerprint binary、ABC、show 與每個 input，執行後再驗證 identities。28 records 的 `post_run_identity_changes` 全為空。
- `wall_ms` 是 execution wall time，不含執行後 identity recheck；另以 `provenance_verification_ms` 記錄該成本。hard 22 runs 合計 2.404 s，controls 6 runs 合計 0.416 s。

共同 CLI record 為 `--depth 10 --neg-ratio 50 --mine-rounds 15 --mine-max 5000`。目前 `main` 內部 rule-synthesis calls 仍固定 `eval_count=0, mine_rounds=1, mine_max=0`；後兩個 CLI 值只被解析與記錄，不驅動這條路徑的多輪 hard-negative loop。

先執行測試：

```bash
make -C src ../bin/script/test_rule_optimizer -j4
bin/script/test_rule_optimizer
python3 scripts/test_compare_rule_methods.py
bash scripts/test_rule_method_telemetry.sh
```

再以 runner 強制的單工作重跑：

```bash
python3 scripts/compare_rule_methods.py \
  --profile rebuild11 \
  --output-root validation/rule_method_ab_rebuild11_v2 \
  --jobs 1 --force

python3 scripts/compare_rule_methods.py \
  --profile controls \
  --output-root validation/rule_method_ab_controls_v2 \
  --jobs 1 --force
```

下列 SHA 是本次已保存 artifacts 的 identity。要重現相同實驗設定，應使用 commit `5659fdf` 建出的相同 tools 與 `run_context.json` 所列相同 inputs；但 aggregate/raw artifacts 包含 runtime、timestamp 與 staging 資訊，重跑的 SHA 與時間預期會不同。可追蹤的小型投影表 [`experiments/rule_method_ab_2026-08-11/paired_results.csv`](experiments/rule_method_ab_2026-08-11/paired_results.csv) 有 28 data rows、38 欄，不含絕對路徑或大型 JSON，並保留 provenance、synthesized、applied/effective 與 optimizer/VN 指標。

## Commit 鏈

| Commit | 內容 |
|---|---|
| `f61946e` | 保存 v6 signature-minimization baseline |
| `b14b30a` | 將 `vn-retrain` 暴露成可選且可量測的 rule strategy |
| `5a919ef` | 新增 finite-matrix bounded-DNF 0–1 PB optimizer 與 unit tests |
| `edb386c` | 將 `z3-pb` 接進 mining/CLI，加入 CEGIS 與 fallback |
| `96ffd5a` | 新增固定 manifest、A/B runner、external ABC CEC 與 artifacts |
| `b4f0c4b` | 修正 apply/synth telemetry、default clause cap、ABC pinning、jobs=1 與 post-run provenance verification |
| `5659fdf` | 保存第一版比較文件；本次 v2 run 的 clean commit |
| `86497a6` | 在 v2 run 後補強 applied-rule telemetry 測試；不影響 v2 artifact identity |
| `82d89ac` | 在 v2 run 後讓 V0 batch 匯出 effective-rule 指標；不影響 v2 artifact identity |

## Artifact identity / SHA-256

共同 identities：

- `bin/main`: `dc88da1ca8627e33069bc3fac66fdc042aaff832662df93a5645414db82d0d85`
- external/internal pinned `abc`: `627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3`
- `bin/script/show`: `e31996085bbed77e3817f7be19866d4ac0152932f541b0c76d621db0ac48d388`
- runner: `2e66e7140265b570c6a75995b7271a2d9b99b6701173171820ec9000b6a8d60c`
- case manifest: `b84e0248ad8dc37dc210051d4b165394b9d4fa1e2f415ee2cc620c8ad13c380e`
- `rebuild11_v2` context key: `966fd11678715d9082103b31bd9405e0fc0b155582ddd60890ca690539b677ab`
- `controls_v2` context key: `fb93563641ebe99d84e0260e2c2eef70ab16157c86434d362cbd90f43cc17c74`

聚合檔 SHA-256：

| Profile | `results.csv` | `summary.json` | `run_context.json` |
|---|---|---|---|
| `rebuild11_v2` | `ca8db5669b13c214376348e2cb6f333cf293ba04219cb4c856af7158016092fb` | `2573af51b8b6409c4e021a90c58e3a42d8836cf1c9082d8a5ce50907c8678d4a` | `08ae07567706646a4e25c607a38f66dd2e5b55f2b46bf71f765e506452ca6c65` |
| `controls_v2` | `f96ca61a5887b150b45c26a8bae1dc1d90755e2f70dc2c14591f97ff70911263` | `a9e5f6692e6bfde9caf4b27ab277f71c63492c279b74e6fa413c0f45f21185a6` | `e05d586da99087c508d69e775eb523ca971a5f6f56a6f2e74f777cbd8b90d962` |

Paired projection CSV SHA-256：`18eb40e94b8be12f7b308ccef4173d774a1b23c0b404a19b064453483ae49406`。

每筆 record 的 `artifact_identities` 另存 stdout/stderr、external CEC logs 與 patched bench 的 SHA-256。以下 raw digest 是在各 profile 目錄內，對 `find raw -type f -print0 | sort -z | xargs -0 sha256sum` 的輸出再做 SHA-256：

- `rebuild11_v2/raw`（88 files）：`0e5485343e2cd81caa3c8db01cb9589d994121ee8ff3b7faaaa368789eeb1db6`
- `controls_v2/raw`（24 files）：`0028379b1f27010f79f3a1ab7e6c4f08bc101e047365f4696ddceb5fe3267022`

## 限制與下一步

- Cohort 只有 V0 single-trigger/single-payload 的 11 hard + 3 controls，不能代表 multi-Trojan、multi-payload 或更大電路。
- 每個 case/method 只有一次正式 run，沒有多 seed、重複量測或信賴區間；runtime 是工程性比較，不是統計結論。
- `z3-pb` 候選只來自單棵 greedy DT positive paths；DT 未使用的 gate 不可被 optimizer 選到。
- 相同 finite-training signature 的 features 會去重，但有限 rows 上相同不保證未觀察輸入也等價。
- v2 預設 clause cap 由 baseline rule count 推導；如需檢驗較多 clauses，必須明確設定非零 `--rule-opt-max-clauses` 並另做 A/B。
- timeout、infeasible、unknown、max-rounds 或 finite verification failure 會回退 DT baseline；回退不保證 external CEC PASS。
- 三個共同失敗 cases 應先分析 external CEC counterexamples，區分 candidate-union 不完整、DNF bounds 不足、trigger model 或 payload patch 錯誤，再評估 top-k trees、候選擴張與跨 CEC round constraint 累積。
