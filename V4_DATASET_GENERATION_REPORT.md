# V4 多獨立 Hardware Trojan 測資生成與驗證報告

報告日期：2026-08-10
資料集：`trojaned_bench/V4_multiIndependentTrojan`
正式矩陣：735 scheduled cases

## 1. 目的與交付結論

本工作建立一組可供碩士論文進行多 Trojan 偵測、定位、修補與泛化實驗的組合式 BENCH 測資。V4 的研究單位不是「同一個 payload 的多種 trigger」，而是同一電路中存在多個可分別識別、分別啟動與分別觀測的 Trojan instances。

2026-08-10 final snapshot 已完成：

- 735/735 cases 均有 `case_manifest.json`、`groundtruth.json` 與 `negative_patterns.json`。
- Matrix coverage 為 735/735，missing 0、outside 0。
- 689 cases 通過 GT acceptance，46 cases 明確拒收。
- GT-ready acceptance yield 為 **689/735 = 93.74%**；Wilson 95% confidence interval 為 **91.75%–95.28%**。
- 93.74% 是「GT 生成／acceptance yield」，不是 Trojan 偵測、定位或修補演算法的成功率。
- Rejected cases 保留原 seed、partial artifacts 與逐案原因；未換 seed、未刪除案例、未縮小 scheduled 分母。

Final strict validator 因 scheduled matrix 中存在 46 個 rejected cases 而回傳 exit code 1、狀態 `FAIL`。這是 seed-freeze policy 下的預期結果，不表示資料漏產或驗證程式異常。

## 2. V2／V3 與 independent V4

| Variant | 結構 | 是否為 V4 意義下的多獨立 Trojan |
|---|---|---|
| V2 | 多個 trigger 條件以 OR 控制同一個 payload victim | 否；屬於同一 Trojan 行為的多種啟動條件 |
| V3 | 多 trigger、多 payload，但沿用舊的整體描述 | 否；缺少穩定的 per-instance 身分、individual netlist 與 exact-mask GT 契約 |
| V4 | 每個 `HTi` 有自己的 trigger、victim、XOR payload、instance ID 與 individual netlist | 是 |

每個 V4 case 包含：

- byte-identical `golden.bench`
- 同時插入全部 Trojan 的 `combined.bench`
- 每個 instance 各自插入的 `individual/HTi.bench`
- 描述生成參數、介面、instance、檔案 hash 與 constructive trigger witnesses 的 `case_manifest.json`
- positive exact-mask GT `groundtruth.json`
- all-off near-miss negatives `negative_patterns.json`

## 3. 實驗矩陣與切分

| Phase | 用途 | Circuits | N | Trigger size | Topology | GT profile | Cases |
|---|---|---|---|---|---|---|---:|
| `pilot_dev` | 開發與參數選擇 | c880、c2670、c3540、c5315、c6288、c7552 | 2、3 | 3、5 | disjoint | pilot | 120 |
| `core_final` | in-distribution final | 上述六個 ISCAS、div、mem_ctrl | 1、2、3 | 3、5 | disjoint | release | 480 |
| `heldout_ood` | untouched OOD test | aes、gps、mor1kx | 2、3 | 5 | disjoint | release | 60 |
| `five_trojan_stress` | N=5 complexity stress | c7552、div、mem_ctrl | 5 | 5 | disjoint | pilot | 15 |
| `shared_trigger_challenge` | shared-literal challenge | c880、c2670、c7552 | 2、3 | 3、5 | shared literals | pilot | 60 |
| **合計** |  |  |  |  |  |  | **735** |

Seeds 在各 phase 間互不重疊。`heldout_ood` circuits 不出現在 development phase；模型 threshold、演算法 flag 與 generator 設定不得使用 OOD 結果調整。

GT profile 配額如下：

| Profile | Positive witnesses | Hard negatives |
|---|---|---:|
| pilot | 每個 requested mask 16 | 256 / case |
| release | singleton 64、pair 32、all-on 32 | 512 / case |

N ≤ 3 使用全部非零 exact masks；N=5 stress 使用 5 singleton、10 pair 與 1 all-on，共 16 masks。完整 positive count 因而為 pilot N=2：48、N=3：112、N=5：256；release N=1：64、N=2：160、N=3：320。

## 4. Netlist 與 GT 生成演算法

### 4.1 Netlist generator

Case generator 先解析組合式 BENCH、建立 fanin／fanout 與 topological depth，再依 phase 選取 payload victims 與 trigger literals：

1. 從 primary inputs 選取 AND-trigger literals，記錄 required polarity。
2. `disjoint` topology 不共享 trigger literals；`shared_trigger_literals` 允許 requested overlap 0.5，但每個 instance 至少保留一個 unique PI literal，使 exact masks 仍可建構。
3. Victims 必須彼此不同，並優先形成相同 topological depth 的 antichain；pilot 使用 output-near placement，其餘使用 random placement。
4. 每個 `HTi` 以 XOR-toggle payload 改寫 victim fanouts，分別輸出 individual netlist；所有 rewrites 合併後輸出 combined netlist。
5. Manifest 保存每個 BENCH artifact 的 path、byte size、SHA-256，以及全部 `2^N` trigger masks 的 constructive partial PI assignments。

### 4.2 Positive ground truth

Positive GT 必須同時符合「exact trigger mask」與「至少一個 primary output 可觀測 mismatch」。GT tool 依電路規模採兩類路徑：

- 較小、可編碼的 cone 使用 Z3 exact-mask miter，直接列舉去重 witnesses。
- 大型／非小型電路使用 constructive/formal ATPG 路徑：ABC CEC 先檢查 individual observability，miter／DSAT 取得 formal seed，再以 packed GPU 或 CPU simulation 做局部 expansion。
- 每筆 accepted witness 最後都以 full-PO scalar simulation 重新確認 requested mask、實際 activation mask 與 `golden != combined`。

Mask 字元順序跟隨 `instance_order`；例如 `[HT0, HT1]` 中 `10` 代表只啟動 HT0。GT 會保存 requested／actual mask、active instances、mismatched outputs、sample class 與 witness index。

### 4.3 Hard negatives

Hard negative 採 all-but-one-literal near miss：指定 instance 的 trigger 只錯一個 literal，但所有 instances 實際都保持 inactive。每筆 negative 必須：

- activation mask 與 requested mask 都是全零；
- 不與任何 positive 或先前 negative pattern 重複；
- 記錄 `near_instance` 與 `flipped_literal`；
- 經 full-PO scalar simulation 確認 `golden == combined`。

## 5. Final 實際結果

### 5.1 依 phase

| Phase | Scheduled | GT-ready | Rejected | Ready positives | Ready negatives | Rejected-artifact positives | Rejected-artifact negatives |
|---|---:|---:|---:|---:|---:|---:|---:|
| `pilot_dev` | 120 | 120 | 0 | 9,600 | 30,720 | 0 | 0 |
| `core_final` | 480 | 440 | 40 | 78,432 | 225,280 | 4,224 | 20,480 |
| `heldout_ood` | 60 | 59 | 1 | 14,240 | 30,208 | 64 | 512 |
| `five_trojan_stress` | 15 | 10 | 5 | 2,560 | 2,560 | 512 | 1,280 |
| `shared_trigger_challenge` | 60 | 60 | 0 | 4,800 | 15,360 | 0 | 0 |
| **合計** | **735** | **689** | **46** | **109,632** | **304,128** | **4,800** | **22,272** |

全部 artifacts（含 rejected partial artifacts）合計 114,432 positives 與 326,400 hard negatives。Rejected artifacts 不可放入正式訓練或評估資料。

### 5.2 依 benchmark

| Benchmark | Scheduled | GT-ready | Rejected |
|---|---:|---:|---:|
| aes | 20 | 19 | 1 |
| c2670 | 100 | 99 | 1 |
| c3540 | 80 | 73 | 7 |
| c5315 | 80 | 75 | 5 |
| c6288 | 80 | 80 | 0 |
| c7552 | 105 | 105 | 0 |
| c880 | 100 | 100 | 0 |
| div | 65 | 35 | 30 |
| gps | 20 | 20 | 0 |
| mem_ctrl | 65 | 63 | 2 |
| mor1kx | 20 | 20 | 0 |
| **合計** | **735** | **689** | **46** |

46 個 rejected cases 都有 `INCOMPLETE_GROUNDTRUTH`。細項包含 57 個 missing singleton instance witnesses、141 個 non-sat requested masks（45 `unsat`、96 `unknown`）、141 個 witness-count mismatches 與 46 個 case-level pattern-count mismatches。這些是同一批 rejected cases 的多重原因，不能相加成 case 數。

Validator 共檢查 1,635 Trojan instances、3,105 個 manifest-declared BENCH hashes，errors 431、warnings 0。Acceptance indexes 完成第二次唯讀稽核：重新驗證 2,205 個 JSON artifacts 的 path、size 與 SHA-256，涵蓋 735 個唯一 case IDs，結果 0 problems。

## 6. 拒收政策與論文使用方式

`dataset_index.jsonl` 是 **structural／scheduled index**：它列出全部 735 個 matrix cases 與 manifest 定位資訊，但不代表 GT 已通過。正式資料取樣必須使用：

- `validation/final_gt_ready_index.jsonl`：689 個可用 cases；訓練、validation、test 只從此處取樣。
- `validation/final_rejected_cases.jsonl`：46 個拒收 cases；只供 failure analysis，不得混入正式樣本。

論文應同時報告 scheduled、GT-ready、rejected、rejection reasons 與 acceptance yield。不得只用 689 當分母，也不得把 rejected seed 換成較容易成功的新 seed。

建議的實驗使用方式：

- `pilot_dev`：train／development、參數選擇、pipeline debug；不可當 untouched final result。
- `core_final`：設定凍結後的 in-distribution validation／final evaluation。
- `heldout_ood`：全部設定凍結後的 OOD test；禁止任何回頭調參。
- `shared_trigger_challenge` 與 `five_trojan_stress`：獨立報告的 auxiliary analyses，不混入 primary ID repair-success denominator。
- Split 單位是完整 case。相同 case 的 positives、negatives、individual 與 combined netlists 不可拆到不同 splits，以避免 netlist leakage。

若研究目標是修補演算法，修補成功率必須另外定義，例如「全部 Trojan 都被修補且 ABC CEC 通過」；它與本報告的 93.74% GT acceptance yield 是兩個不同指標。

## 7. 重現與驗證

以下命令從 repository root 執行。

### 7.1 檢查 735-case matrix

```bash
python3 scripts/run_multi_trojan_matrix.py \
  --output-root trojaned_bench/V4_multiIndependentTrojan \
  --dry-run \
  --jobs 8
```

### 7.2 產生或核對 structural cases

```bash
python3 scripts/run_multi_trojan_matrix.py \
  --output-root trojaned_bench/V4_multiIndependentTrojan \
  --skip-existing \
  --jobs 8
```

`--skip-existing` 會由 runner 核對 manifest identity、matrix dimensions 與 BENCH artifact size／SHA-256。不要對已有完整 aggregate 的正式 root 執行 phase-filtered runner，以免 scope 不一致；runner 會在寫檔前拒絕。

### 7.3 代表性 GT 命令

Pilot profile：

```bash
bin/script/generate_multi_gt \
  trojaned_bench/V4_multiIndependentTrojan/c880/c880_n2_t3_o000_s1000_6c8940cd/case_manifest.json \
  --per-mask 16 \
  --hard-negatives 256 \
  --mask-set auto
```

Release profile 的 quota flags 為：

```text
--per-mask 32 --per-singleton 64 --per-pair 32 --per-all 32 --hard-negatives 512
```

大型 case 應明確指定 constructive mode、GT tool budget 與外層 process timeout；命令與 timeout outcome 必須寫入實驗紀錄。

### 7.4 Final strict validation

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/validate_multi_dataset.py \
  --dataset-root trojaned_bench/V4_multiIndependentTrojan \
  --matrix configs/multi_trojan_experiment_matrix.json \
  --repo-root . \
  --strict \
  --require-complete-matrix \
  --min-hard-negatives 256 \
  --summary-json trojaned_bench/V4_multiIndependentTrojan/validation/final_validation_summary.json \
  --summary-markdown trojaned_bench/V4_multiIndependentTrojan/validation/final_validation_summary.md \
  --ready-index trojaned_bench/V4_multiIndependentTrojan/validation/final_gt_ready_index.jsonl \
  --rejected-index trojaned_bench/V4_multiIndependentTrojan/validation/final_rejected_cases.jsonl
```

此 snapshot 的預期 exit code 是 1，因為 validator 忠實保留 46 個 rejected cases。不可加上 `--allow-missing-groundtruth` 將 final acceptance 降級成表面 PASS。

## 8. Trust boundary 與已知限制

- 資料目前只涵蓋組合式 BENCH、PI trigger literals、AND trigger 與 XOR-toggle payload；結論不可直接外推到 sequential state trigger 或其他 payload 類型。
- Victims 必須不同且採相同 depth antichain，但下游 payload cones 是否重聚合為 `unconstrained`；目前不是刻意控制的 payload-overlap 實驗。
- 不支援 cascaded／dependent Trojan instances；shared-trigger challenge 只共享部分 PI literals。
- N=5 stress 的 positive mask set 是 singleton + pair + all-on 共 16 masks，不是全部 31 個非零 subsets。
- Hard negatives 只涵蓋 all-but-one-literal near miss；若論文主張更廣泛的 classifier robustness，仍應加入其他 negative families 或清楚限縮結論。
- Dataset validator 驗證 schema、hash linkage、宣告的 mask semantics、pattern uniqueness、singleton coverage、profile quota 與 negative trigger shape；它**不會用第二套 simulator 重新執行 BENCH**。Positive observability 與 negative equality 的電路層保證來自 GT tool 的 full-PO scalar revalidation。
- GT tool 的 automatic backend 已避免大型 raw circuits 誤走 Z3，但明確 forced Z3 的 total wall-clock 仍不是可強制中止每個 solver call 的硬上限；非小型工作仍需外層 process timeout，並把 timeout／unknown 當成拒收結果。
- div 的拒收比例高於其他 benchmark；跨 benchmark 比較應分層呈現，不可只報整體 93.74%。

## 9. 檔案入口

- 完整規格與操作說明：[V4_MULTI_TROJAN_DATASET.md](V4_MULTI_TROJAN_DATASET.md)
- 實驗矩陣：[configs/multi_trojan_experiment_matrix.json](configs/multi_trojan_experiment_matrix.json)
- Case generator：[generate_multi_trojan_dataset.py](generate_multi_trojan_dataset.py)
- Matrix runner：[scripts/run_multi_trojan_matrix.py](scripts/run_multi_trojan_matrix.py)
- GT generator：[src/script/generate_multi_gt.cpp](src/script/generate_multi_gt.cpp)
- Dataset validator：[scripts/validate_multi_dataset.py](scripts/validate_multi_dataset.py)
- Final Markdown summary：[final_validation_summary.md](trojaned_bench/V4_multiIndependentTrojan/validation/final_validation_summary.md)
- Final machine-readable summary：[final_validation_summary.json](trojaned_bench/V4_multiIndependentTrojan/validation/final_validation_summary.json)
- Final GT-ready index：[final_gt_ready_index.jsonl](trojaned_bench/V4_multiIndependentTrojan/validation/final_gt_ready_index.jsonl)
- Final rejected index：[final_rejected_cases.jsonl](trojaned_bench/V4_multiIndependentTrojan/validation/final_rejected_cases.jsonl)

正式實驗的樣本入口是 `final_gt_ready_index.jsonl`，不是 structural `dataset_index.jsonl`。
