# V4 Multi-Independent-Trojan Dataset 正式使用文件

本文件定義 V4 多獨立 Trojan 資料集的固定範圍、檔案格式、切分方式、產生與驗證流程。狀態快照日期為 2026-08-10；735 個 scheduled cases 的 manifest、ground truth 與 negative artifacts 均已產生並完成 final strict validation。最終 acceptance 為 689 GT-ready、46 rejected；rejected seeds 保留在正式矩陣與報告中，不以換 seed 或刪除案例修飾結果。

資料集的單一事實來源如下：

- 實驗矩陣：[configs/multi_trojan_experiment_matrix.json](configs/multi_trojan_experiment_matrix.json)
- 正式資料根目錄：`trojaned_bench/V4_multiIndependentTrojan`
- Case generator：[generate_multi_trojan_dataset.py](generate_multi_trojan_dataset.py)
- Matrix runner：[scripts/run_multi_trojan_matrix.py](scripts/run_multi_trojan_matrix.py)
- SAT GT generator：[src/script/generate_multi_gt.cpp](src/script/generate_multi_gt.cpp)
- Dataset validator：[scripts/validate_multi_dataset.py](scripts/validate_multi_dataset.py)

## 1. 資料集目的與 V4 定義

V4 的研究單位是「一個電路內含有 N 個可分別識別的 Trojan instance」。每個 `HTi` 都有自己的：

- `instance_id`
- trigger literals 與 trigger net
- victim net
- XOR-toggle payload
- 單獨插入後的 `individual/HTi.bench`

同一個 case 另有 `combined.bench`，同時包含該 case 的全部 `HTi`。因此可以分別驗證單一 Trojan、任意啟動子集合，以及所有 Trojan 同時存在時的可觀測行為。

### 1.1 V2／V3 與 V4 的差異

| Variant | 已有結構 | 是否為 V4 意義下的多獨立 Trojan |
|---|---|---|
| V2 | 多個 trigger 條件以 OR 方式控制同一個 payload victim | 否；它是同一個 Trojan 行為的多種啟動條件 |
| V3 | 多個 trigger 與多個 payload，payload 分配給不同 trigger | 否；舊格式沒有 V4 的 per-instance 身分、單獨 netlist 與 exact-mask GT 契約 |
| V4 | N 個 `HTi`，每個 instance 有獨立 trigger、victim、payload 與 individual netlist | 是 |

V4 目前固定使用組合式 BENCH 電路、PI trigger literals、AND trigger 與 XOR-toggle payload。矩陣內的 victim 必須彼此不同，並採相同拓樸深度的 antichain placement；payload cone 是否在下游重聚合則記為 `unconstrained`。

`shared_trigger_literals` 只允許 instance 共享部分 trigger literals；每個 instance 仍保留至少一個 unique literal，因此 exact activation mask 仍可被建構。它不會把多個 instance 合併成單一 Trojan。

## 2. 735-case 正式矩陣

下表只列出五個 enabled phases；disabled 的 `unsupported_topology_extension` 不屬於 735-case 資料集。

| Phase | 論文 split | Circuits | N | Trigger size | Trigger topology | Victim placement | Seeds | GT profile | Cases |
|---|---|---|---|---|---|---|---|---|---:|
| `pilot_dev` | `development` | c880、c2670、c3540、c5315、c6288、c7552 | 2、3 | 3、5 | disjoint | output-near | 1000–1004 | pilot | 120 |
| `core_final` | `final_in_distribution` | 上述六個 ISCAS + div、mem_ctrl | 1、2、3 | 3、5 | disjoint | random | 2000–2009 | release | 480 |
| `heldout_ood` | `heldout_ood` | aes、gps、mor1kx | 2、3 | 5 | disjoint | random | 9000–9009 | release；pilot preflight 需直接呼叫 GT tool | 60 |
| `five_trojan_stress` | `stress` | c7552、div、mem_ctrl | 5 | 5 | disjoint | random | 9500–9504 | pilot | 15 |
| `shared_trigger_challenge` | `topology_challenge` | c880、c2670、c7552 | 2、3 | 3、5 | shared literals，requested overlap 0.5 | random | 6000–6004 | pilot | 60 |
| **合計** |  |  |  |  |  |  |  |  | **735** |

非小型工作共 190 cases，所有 artifacts 與 final acceptance 均已完成：

- `core_final` 的 div、mem_ctrl：120 cases
- `heldout_ood` 的 aes、gps、mor1kx：60 cases
- `five_trojan_stress` 的 div、mem_ctrl：10 cases

這 190 cases 的 acceptance 為 157 GT-ready、33 rejected：div 35/65 ready、mem_ctrl 63/65 ready，heldout OOD 59/60 ready；完整分層結果見第 9 節。

## 3. Case 目錄與 schema

### 3.1 目錄配置

```text
trojaned_bench/V4_multiIndependentTrojan/
├── dataset_manifest.json
├── dataset_index.jsonl
├── generation_failures.jsonl
├── groundtruth_failures.jsonl
└── <benchmark>/
    └── <case_id>/
        ├── golden.bench
        ├── combined.bench
        ├── individual/
        │   ├── HT0.bench
        │   ├── HT1.bench
        │   └── ...
        ├── case_manifest.json
        ├── groundtruth.json
        └── negative_patterns.json
```

Case ID 格式為：

```text
<benchmark>_n<N>_t<K>_o<overlap_milli>_s<seed>_<golden_sha256前8碼>
```

例如 `c880_n2_t3_o000_s1000_6c8940cd` 表示 c880、2 個 Trojan、每個 trigger 3 literals、無共享 literal、seed 1000。`o500` 表示 requested overlap 0.5。

### 3.2 `case_manifest.json`

Schema：`v4-multi-independent-trojan/1`。

主要欄位：

- `case_id`、`benchmark`
- `paths`／`golden_path`／`combined_path`
- `interfaces.primary_inputs`、`interfaces.primary_outputs`
- `generation`：generator 版本與 hash、seed、N、trigger size、overlap、topology、placement、golden hash
- `files`：所有 BENCH artifacts 的 SHA-256 與 byte size
- `instances[]`：`instance_id`、individual path、victim、trigger、payload 與 rewritten fanouts
- `trigger_witnesses.partial_pi_assignments`：每個 exact mask 的可滿足 partial PI assignment
- `expected_activation`：在均勻獨立 PI 假設下的理論啟動率

`golden.bench` 是來源 benchmark 的 byte-identical copy；`combined.bench` 含全部 instances；每個 `individual/HTi.bench` 只含對應的單一 instance。

### 3.3 Dataset-level index

- `dataset_manifest.json` schema：`v4-multi-trojan-matrix-run/1`
- `dataset_index.jsonl` row schema：`v4-multi-trojan-dataset-index/1`
- index row 保存 phase、split、GT profile、matrix dimensions，以及 case manifest 的 path、SHA-256 與 size
- `generation_failures.jsonl` 與 `groundtruth_failures.jsonl` 保存 runner failure；空檔代表該次 aggregate run 沒有對應 failure

`dataset_index.jsonl` 是 structural／scheduled index，只證明 case 屬於矩陣且 manifest 可被定位，不代表 GT 已通過 acceptance。訓練或評估正式 GT 時必須改用 `validation/final_gt_ready_index.jsonl`；`validation/final_rejected_cases.jsonl` 只供 failure analysis。

## 4. Activation mask convention

Mask 是長度 N 的 binary string，字元位置依 `instance_order`／manifest 的 `instances[]` 順序，左邊第一個字元對應 `HT0`。

以 `instance_order = [HT0, HT1]` 為例：

| Mask | 意義 |
|---|---|
| `00` | 所有 instance 都未啟動 |
| `10` | 只啟動 HT0 |
| `01` | 只啟動 HT1 |
| `11` | HT0、HT1 同時啟動 |

`activation_mask_value` 使用一般二進位整數解讀，因此上例的 `10` 等於 2；HT0 是最高有效位元。

正樣本的 requested mask 集合如下：

- N ≤ 3、`--mask-set auto`：列舉全部非零 exact masks
- N = 5、`--mask-set auto`：5 個 singleton + 10 個 pair + 1 個 all-on，共 16 masks
- 零 mask 不屬於 positive GT；它用於 hard-negative patterns

`case_manifest.json` 的 partial assignments 用來證明 trigger mask 可滿足；`groundtruth.json` 的 positive witness 還額外要求 `golden != combined` 在至少一個 PO 可觀測。兩者不可混為同一種標籤。

## 5. GT 與 negative schema

### 5.1 `groundtruth.json`

Schema：`v4-groundtruth-1`。

主要欄位：

- `case_id`、`benchmark`
- `origin_path`／`trojan_path` 及其 SHA-256
- `pi_order`、`po_order`、`instance_order`
- `patterns[]`
- `mask_results[]`
- `trigger_consistency[]`
- `solver`、`cone_encoding`、`time`
- `complete`

每筆 positive pattern 至少包含：

- `pattern_bits`
- `requested_mask`
- `activation_mask`、`activation_mask_value`
- `active_instances`
- `mismatched_outputs`
- `sample_class`
- `witness_index`

每筆 pattern 必須 exact-match requested mask，且 `mismatched_outputs` 不得為空。相同 case 內的 `pattern_bits` 必須去重。

### 5.2 `negative_patterns.json`

Schema：`v4-hard-negatives-1`。

目前 hard negative 是 all-but-one-literal near miss：指定 instance 的 trigger 只差一個 literal，所有 instance 實際上都未啟動，且 scalar simulation 證明 `golden == combined`。

每筆 negative pattern 具有：

- `activation_mask` 為全零
- `active_instances` 為空
- `mismatched_outputs` 為空
- `label = 0`
- `simulated_equal = true`
- `near_instance` 與 `flipped_literal`

`generation.requested`、`generation.generated`、`pattern_count` 必須相等，且 `generation.complete = true`。

### 5.3 GT profiles

| Profile | Positive target | Hard negatives | 使用 phase |
|---|---|---:|---|
| pilot | 每個 requested mask 16 witnesses | 256 / case | pilot、shared-trigger、five-Trojan stress |
| release | singleton 64、pair 32、all-on 32；其他 subset fallback 32 | 512 / case | core final、heldout OOD |

由此可得 pilot profile 的完整 positive count：N=2 為 48、N=3 為 112、N=5 auto/core 為 256。Release profile 的 N=1、N=2、N=3 完整 positive count分別為 64、160、320。

## 6. 可重現命令

以下命令都從 repository root 執行。正式資料一律明確指定 `--output-root trojaned_bench/V4_multiIndependentTrojan`，不可依賴 generator／runner 的預設輸出目錄。

### 6.1 檢查矩陣，不寫檔

```bash
python3 scripts/run_multi_trojan_matrix.py \
  --output-root trojaned_bench/V4_multiIndependentTrojan \
  --dry-run \
  --jobs 8
```

預期顯示 735 scheduled cases，其中 small 545、non-small 190。

### 6.2 直接產生單一 case

```bash
python3 generate_multi_trojan_dataset.py \
  --input benchmarks/c880.bench \
  --output-root trojaned_bench/V4_multiIndependentTrojan \
  --trojan-count 2 \
  --trigger-size 3 \
  --trigger-overlap 0 \
  --victim-placement output-near \
  --seed 1000 \
  --skip-existing
```

Generator 不會覆寫既有 case；`--skip-existing` 只依 case directory 是否存在決定略過。Matrix runner 會核對既有 manifest 的 schema、case identity、matrix dimensions、trigger topology／overlap、victim placement，以及 manifest 宣告的 BENCH artifact size／SHA-256；更完整的 instance／mask／GT semantic acceptance 仍必須交給 validator。

### 6.3 依 matrix 產生 netlists

以獨立 staging root 產生 pilot phase：

```bash
python3 scripts/run_multi_trojan_matrix.py \
  --phase pilot_dev \
  --output-root outputs/v4_pilot_staging \
  --skip-existing \
  --jobs 8
```

`--phase` 可以重複指定。Runner 只對 `size_class=small` 使用 `--jobs` 平行處理；其餘電路序列執行。每個 case 由單一 subprocess 負責，不會讓兩個 worker 寫入相同 case directory。

`dataset_manifest.json`、`dataset_index.jsonl` 與 failure logs 是本次 selection 的 aggregate snapshot。為避免 phase-only run 把正式 735-case index 縮成單一 phase，若 output root 已有不同 scope 的 aggregate，runner 會在任何 case 寫入前拒絕。正式 root 要重建完整 aggregate 時，不可帶 `--phase`：

```bash
python3 scripts/run_multi_trojan_matrix.py \
  --output-root trojaned_bench/V4_multiIndependentTrojan \
  --skip-existing \
  --jobs 8
```

### 6.4 Matrix runner 產生 GT

在獨立 staging root 產生 shared-trigger phase 與 GT：

```bash
python3 scripts/run_multi_trojan_matrix.py \
  --phase shared_trigger_challenge \
  --output-root outputs/v4_shared_trigger_staging \
  --skip-existing \
  --generate-groundtruth \
  --gt-tool bin/script/generate_multi_gt \
  --jobs 8
```

不要對已有 735-case aggregate 的正式 root 執行 phase-filtered runner；scope guard 會拒絕這種操作，以保護完整 index 與其他 phase 的 failure history。若只需補正式 root 的少數 GT，使用 6.5 的單 case GT 命令；完成後再用上節不帶 `--phase` 的命令重建完整 aggregate。

完整且符合 phase profile 的 GT 會標為 `GT_EXISTING` 並跳過；既有但不完整或 profile 不符的 GT 會失敗，不會自動覆寫。

Runner 的 `GT_EXISTING` 判定會檢查 profile-specific exact witness counts。Dataset validator 負責 schema、artifact/hash linkage、宣告的 mask semantics、pattern uniqueness、singleton coverage、profile quota，以及 hard-negative trigger-shape consistency；它不會重新模擬 BENCH 來獨立證明 positive 的 PO mismatch 或 negative 的 `golden == combined`。電路層級的 observability／equality 保證來自 GT tool 對每筆 accepted pattern 執行的 full-PO scalar revalidation，因此正式 acceptance 必須同時滿足 GT tool 與 validator 兩層檢查。

只有在明確要重建 GT 時才加入：

```text
--force-groundtruth
```

此選項會將 `--force` 傳給 GT tool。GT tool 對每個檔案個別採用 temp + replace；`groundtruth.json` 與 `negative_patterns.json` 這一組 positive／negative artifacts 並非交易式提交。若兩次 replace 之間中斷或第二個檔案寫入失敗，必須把該 case 視為未完成並重新驗證兩個檔案。

### 6.5 直接呼叫 GT generator

下列命令把重建結果放在 `outputs/`，不覆寫正式資料集：

```bash
mkdir -p outputs/v4_gt_rebuild/c880_n2_t3_s1000

bin/script/generate_multi_gt \
  trojaned_bench/V4_multiIndependentTrojan/c880/c880_n2_t3_o000_s1000_6c8940cd/case_manifest.json \
  --output outputs/v4_gt_rebuild/c880_n2_t3_s1000/groundtruth.json \
  --negative-output outputs/v4_gt_rebuild/c880_n2_t3_s1000/negative_patterns.json \
  --per-mask 16 \
  --hard-negatives 256 \
  --mask-set auto
```

Release profile 的參數為：

```text
--per-mask 32 --per-singleton 64 --per-pair 32 --per-all 32 --hard-negatives 512
```

Matrix 內的 `preflight_groundtruth_profile` 目前只記錄實驗政策，runner 尚不會自動切換到該 profile，也不提供 wall-clock／ABC timeout passthrough。`solver-mode=auto` 會在 raw circuit node count 或 sparse encoded node count 任一超過 `--z3-node-threshold` 時選擇 constructive path；顯式 `--solver-mode` 仍會覆寫 auto policy。非小型 case 的正式或 preflight GT 命令必須直接呼叫 GT tool，明確固定並記錄 runtime budget，例如：

```text
--wall-clock-ms 120000 --abc-timeout-ms 5000
```

大型 OOD case 若採不同 budget，也必須在實驗 protocol 凍結後明確寫入命令與報告；不可依賴 GT tool 的 10 秒預設 wall-clock budget。目前 `--wall-clock-ms` 是 constructive path 的總預算；Z3 path 尚未套用 total wall-clock deadline，只受 `--timeout-ms` 的 per-check timeout 約束。若顯式強制 Z3，正式命令還必須加外層 process timeout，例如 `timeout --signal=TERM --kill-after=10s 180s ...`，且將 timeout 視為明確 rejected outcome。

GT tool exit code 0 代表 positive 與 negative generation 都完整；exit code 2 代表有 artifact 被寫出但至少一部分不完整；exit code 1 代表輸入、驗證或 I/O error。非零 exit code 不得當成 GT-ready。

### 6.6 驗證

只驗證 matrix 本身：

```bash
python3 scripts/validate_multi_dataset.py \
  --matrix configs/multi_trojan_experiment_matrix.json \
  --repo-root . \
  --matrix-only \
  --strict
```

驗證單一 pilot case：

```bash
python3 scripts/validate_multi_dataset.py \
  --manifest trojaned_bench/V4_multiIndependentTrojan/c880/c880_n2_t3_o000_s1000_6c8940cd/case_manifest.json \
  --strict \
  --min-hard-negatives 256
```

完整 735-case final validation 命令如下。2026-08-10 snapshot 因 46 個 scheduled cases 被明確拒收而回傳 exit code 1／`FAIL`；這是 seed-freeze policy 下的預期 acceptance 結果，不得以 `--allow-missing-groundtruth`、換 seed 或排除案例包裝成 PASS。

```bash
python3 scripts/validate_multi_dataset.py \
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

Validator 會原子寫入兩份 JSONL acceptance indexes。`final_gt_ready_index.jsonl` 只能供模型訓練／評估取樣；`final_rejected_cases.jsonl` 保存每個 rejected case 的原 seed、partial artifacts、path／size／SHA-256 與逐案錯誤原因。

## 7. Train／validation／test 使用規則

本資料集的 split 單位是完整 case，不是單筆 pattern。同一個 case 的 positive、negative、individual netlists 與 combined netlist 必須留在同一 split，禁止隨機拆散 pattern rows，避免同一 netlist 洩漏到不同 split。

| 論文用途 | Phase | 可做的事 | 禁止事項 |
|---|---|---|---|
| Train／development | `pilot_dev` | pipeline 開發、參數選擇、除錯與消融設計 | 不可宣稱為 untouched final result |
| Validation／in-distribution final | `core_final` | 設定凍結後的 ID 評估；只使用 GT-ready index | 看過結果後更換失敗 seed或回頭調參 |
| Test／OOD | `heldout_ood` | 所有設定凍結後的跨電路 transfer test | 任何 threshold、flag、generator 或演算法調參 |
| Auxiliary challenge | `shared_trigger_challenge` | 評估共享 trigger literals 的退化 | 混入 primary ID success-rate denominator |
| Auxiliary stress | `five_trojan_stress` | 評估 N=5 複雜度 | 混入 primary success-rate denominator |

各 phase 的 seed 範圍互不重疊。`heldout_ood` 的 aes、gps、mor1kx 也不出現在 development phase。

## 8. GT-ready 與拒收政策

Case 只有同時符合下列條件才可進入 GT-ready index：

1. `case_manifest.json` schema、matrix dimensions、placement 與 interface 正確。
2. Manifest-declared BENCH files 全部存在，size 與 SHA-256 相符。
3. `groundtruth.json` 設定 `complete = true`。
4. 每個 requested mask 都是 `status = sat`，並達到 profile 指定的 witness count。
5. 每個 Trojan instance 都至少有一個 unique、PO-observable singleton witness。
6. Positive patterns 無重複，mask、active instances、PI/PO order、circuit hashes 與 trigger consistency 全部相符。
7. `negative_patterns.json` 達到 profile 指定數量，`generation.complete = true`，且 negatives 不可與 positives 重複。
8. Generator／GT tool／validator 沒有 timeout、unknown、I/O、schema 或其他 error。

拒收規則：

- Rejected case 仍保留在 scheduled matrix 與 failure report，不刪除、不改 seed、不用新 seed 補洞。
- Rejected case 不可進入 train／validation／test 的可用資料 index，只能用於 failure analysis。
- 論文必須同時報告 scheduled、GT-ready、rejected 與 rejection reason；不得只報 GT-ready 分母。
- `--allow-missing-groundtruth` 只可用於 generator-stage preflight，不可用於 final release acceptance。

全矩陣正式索引：

- GT-ready：[final_gt_ready_index.jsonl](trojaned_bench/V4_multiIndependentTrojan/validation/final_gt_ready_index.jsonl)
- Rejected：[final_rejected_cases.jsonl](trojaned_bench/V4_multiIndependentTrojan/validation/final_rejected_cases.jsonl)

先前 small-core 階段索引僅保留供 provenance／回歸比較，不是 final 全矩陣入口：

- GT-ready：[core_small_release_gt_ready_index.jsonl](trojaned_bench/V4_multiIndependentTrojan/validation/core_small_release_gt_ready_index.jsonl)
- Rejected：[core_small_release_rejected_cases.jsonl](trojaned_bench/V4_multiIndependentTrojan/validation/core_small_release_rejected_cases.jsonl)

## 9. 已驗證結果與目前狀態

2026-08-10 final snapshot 中，735 個 case directories 均有 `case_manifest.json`、`groundtruth.json` 與 `negative_patterns.json`，且 matrix coverage 為 735/735、missing 0、outside 0。檔案存在不等於 GT-ready；46 個 case 的 GT 明確標為 incomplete 並保留 partial artifacts。GT-ready yield 為 689/735 = **93.74%**，Wilson 95% confidence interval 為 **91.75%–95.28%**。這是 GT 生成／acceptance yield，不是任何 Trojan 偵測、定位或修補演算法的成功率。

| Phase | Scheduled | GT-ready | Rejected | Ready positives | Ready negatives | Rejected-artifact positives | Rejected-artifact negatives |
|---|---:|---:|---:|---:|---:|---:|---:|
| `pilot_dev` | 120 | 120 | 0 | 9,600 | 30,720 | 0 | 0 |
| `core_final` | 480 | 440 | 40 | 78,432 | 225,280 | 4,224 | 20,480 |
| `heldout_ood` | 60 | 59 | 1 | 14,240 | 30,208 | 64 | 512 |
| `five_trojan_stress` | 15 | 10 | 5 | 2,560 | 2,560 | 512 | 1,280 |
| `shared_trigger_challenge` | 60 | 60 | 0 | 4,800 | 15,360 | 0 | 0 |
| **合計** | **735** | **689** | **46** | **109,632** | **304,128** | **4,800** | **22,272** |

全部 artifacts（含 rejected partial data）共有 114,432 positive patterns 與 326,400 hard negatives。Ready 與 rejected-artifact totals 必須分開呈現；後者不可混入可用資料 index。

Rejected cases 的 benchmark 分布如下；未列出的 benchmark 為 0 rejected：

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

46 個 rejected cases 全都有 `INCOMPLETE_GROUNDTRUTH`；總計缺少 57 個 singleton instance witnesses。Profile-aware validator 另外記錄 141 個 non-sat requested masks（45 `unsat`、96 `unknown`）、141 個 witness-count mismatches 與 46 個 case-level pattern-count mismatches。這些是同一批 rejected cases 的細項原因，不可相加成 case 數。

Final strict validator 因上述 46 個拒收案例回傳 exit code 1、狀態 `FAIL`，這是預期結果：它表示完整 scheduled matrix 被忠實驗證，而不是 validation pipeline 失敗。驗證同時確認 1,635 instances、3,105 個 manifest-declared BENCH hashes，且沒有 warning。Acceptance indexes 的第二次獨立 path／size／SHA-256 稽核重新讀取 2,205 個 JSON artifacts、涵蓋全部 735 個 case IDs，結果為 0 problems。

Final 產物：

- 完整 Markdown report：[final_validation_summary.md](trojaned_bench/V4_multiIndependentTrojan/validation/final_validation_summary.md)
- Machine-readable summary：[final_validation_summary.json](trojaned_bench/V4_multiIndependentTrojan/validation/final_validation_summary.json)
- 689-case GT-ready index：[final_gt_ready_index.jsonl](trojaned_bench/V4_multiIndependentTrojan/validation/final_gt_ready_index.jsonl)
- 46-case rejected index：[final_rejected_cases.jsonl](trojaned_bench/V4_multiIndependentTrojan/validation/final_rejected_cases.jsonl)

階段性 pilot／small-core reports 仍留在 `trojaned_bench/V4_multiIndependentTrojan/validation/` 供 provenance 使用；正式論文數字以本節四個 final 產物為準。
