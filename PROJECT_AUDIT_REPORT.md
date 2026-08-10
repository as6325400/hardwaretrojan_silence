# Hardware Trojan Silence 專案稽核報告

- 稽核日期：2026-08-10（Asia/Taipei）
- 稽核範圍：目前工作目錄（working tree），不是只有 Git `HEAD`
- 分支／基準 commit：`virtual_node` / `f05b689`
- 「城市碼」解讀：依專案上下文，本報告將其解讀為「程式碼」，並盤點老舊、未接線、重複與不必要的程式碼／產物。

## 1. 執行摘要

這是一個以 C++17、OpenMP、CUDA、Z3 與 ABC 實作的組合電路硬體木馬偵測／自動修補研究專案。整體方向清楚，電路解析、bit-packed simulation、decision tree、virtual node、MaxSAT payload analysis 與 ABC CEC 都已有實作；目前工作版本也能完整編譯，代表性小型案例可成功修補並通過 CEC。

但目前還不能把它視為穩定、可重現、完整支援 V0–V3 的工具。主要原因如下：

1. **正式 final mining 實際關閉 hard-negative mining。** CLI 雖接受 `--mine-rounds` 與 `--mine-max`，`main` 卻固定成 `eval_count=0, mine_rounds=1, mine_max=0`。README、ALGORITHM 與實際演算法不一致。
2. **CPU CEC retry 的 explicit negative 寫入有矩陣覆寫風險。** positive 數量不是 64 的倍數時，負樣本可能覆寫最後一個 positive word；CUDA 路徑則用假全零 negative 補齊 alignment。
3. **Golden/Trojan 只比 PI/PO 數量，後續卻按位置模擬及比較。** 名稱相同但宣告順序不同時，可能錯標 trigger、錯修 PO。
4. **CEC 或修補失敗最後仍可能 `return 0`。** 外部呼叫者只看 process exit code 會得到假成功。
5. **測資覆蓋嚴重不完整。** 1,990 個 canonical Trojan 中，只有 540 個具有非空 groundtruth，有效覆蓋率 27.1%；V3 完全沒有 groundtruth。
6. **目前沒有單元測試、CI、coverage 或 dataset manifest。** 現有 96.06% 數字只代表 V0 已有非空 groundtruth 的 482 案，不代表全資料集。
7. **約 2,032 行舊演算法模組沒有任何 repo 內 caller，卻被連進每個 executable。** 另有 profiler 輸出、終端 transcript、完全重複檔與過時文件可清理。

建議先處理 P0 正確性問題，再清理 legacy code；否則先刪程式只會讓問題表面變乾淨，無法提高演算法可信度。

## 2. 稽核快照與驗證方式

### 2.1 工作目錄狀態

稽核時已有使用者的未提交內容：

- 已修改：`src/main.cpp`、`run_tests.sh`、`charts/results_chart.{pdf,png}`
- `src/main.cpp` 相對 `HEAD` 約 `+1088/-510` 行
- 未追蹤：`results_v6_signature_min.csv`、`research.tex`、新圖表與產圖腳本等

因此本報告描述的是**目前本機工作版本**。目前結果不等於 commit `f05b689` 可直接重現的結果。

### 2.2 規模

| 項目 | 規模 |
|---|---:|
| C++/CUDA source | 15,114 行 |
| `src/main.cpp` | 2,710 行（約佔 C++/CUDA 18%） |
| Python（含 charts） | 2,701 行 |
| Golden benchmarks | 11 個，約 70 MB |
| `trojaned_bench/` | 約 13 GB |
| `groundtruth/` | 約 53 GB |
| 整個工作目錄 | 約 66 GB |

### 2.3 實際驗證

本次完成：

- 以獨立 `/tmp` 目錄完整重編 CUDA 版本：**成功、無 compiler warning**。
- 產出 `main`、`p1_stats`、`script/{show,show_GT,packed_cmp,synthesis,verify_groundtruth}`。
- `packed_cmp` 對 c880 的 scalar/packed 單一 pattern 比對：**通過**。
- `show benchmarks/c880.bench`：正確讀出 area 383、level 24、60 PI、26 PO。
- 小型端到端案例 `c2670_trojan33`（21 筆 raw groundtruth）：修補成功、ABC CEC PASS，總時間約 0.883 秒。
- 三個 Bash 腳本的語法檢查：通過。
- 673 份 JSON 的檔名對應、PI metadata 與 canonical Trojan 對應盤點：沒有 orphan case。

本次**沒有**重跑完整 V0 502 案，因現有結果估計需約 3.2 小時，且 `run_tests.sh` 會直接覆寫現有 V6 CSV。

## 3. 專案架構

### 3.1 實際資料流

```text
Golden .bench ─┐
               ├─ parse circuit DAG / 僅檢查 PI、PO 數量
Trojan .bench ─┘
                         │
Groundtruth JSON ── 完整 DOM parse ── pattern_bits 去重與 PI 名稱映射
                         │
                         ├─ positive：JSON 內所有合法 pattern
                         └─ negative：隨機 PI 且 golden == trojan
                                     （數量刻意等於 positive）
                         │
                    所有 gate 作 candidate
                         │
               Phase-1 decision tree（Gini）
                         │
             signature VN：pair/triple AND，最多 300
                         │
                 final decision tree / rule 簡化
                         │
      literal patch cut → single-literal kill → MaxSAT payload patch
                         │
               known-groundtruth batch verify
                         │
                     寫出 patched bench
                         │
                     ABC CEC（最多 5 輪）
                         │
              CEX → missed trigger 或 false-positive negative
```

### 3.2 模組責任

| 路徑 | 實際用途 |
|---|---|
| `src/main.cpp` | 主流程、groundtruth stats、CEC wrapper、VN orchestration、literal-cut、signature minimization、patch 策略與 CEC retry |
| `src/core/circuit.*` | 電路 DAG、拓樸排序、單 pattern simulation、area/level |
| `src/core/packed_circuit.*` | 64-bit bit-parallel CPU simulation |
| `src/core/batch_simulator.*` | CPU/GPU batch simulation abstraction |
| `src/core/gpu_circuit.*` | CUDA circuit representation、simulation 與 random PI |
| `src/io/bench_parser.*` / `bench_writer.*` | ISCAS `.bench` I/O |
| `src/io/eqn_parser.*` | ABC EQN parser |
| `src/io/parallel_collect_log.*` | Groundtruth JSON reader |
| `src/io/cli_options.*` | CLI11 options |
| `src/algorithm/decision_tree.*` | Column-major packed CART、Gini split、DNF rule extraction |
| `src/algorithm/miner.*` | Training data、negative sampling、tree/mining loop、strict retry |
| `src/algorithm/virtual_node.*` | Signature-based pair/triple virtual AND features |
| `src/algorithm/payload_analysis.*` | Z3 Optimize / MaxSAT payload gate selection |
| `src/algorithm/rule_patch.*` | Rule 簡化、rule circuit、XOR/MUX patch、known-pattern verify |
| `src/p1_stats.cpp` | Gate activation/statistics 研究工具 |
| `src/script/` | 顯示 stats、packed comparator、groundtruth verifier、ABC synthesis |
| `circuit/circuit.py` | Python 電路、SCOAP、rare-wire 舊／資料生成分析流程 |
| `gen_trojan.py` | V1–V3 Trojan generator |
| `trojan_collect_batch.py` | 呼叫外部 `ht-collect` Docker image 產生 groundtruth |
| `charts/` | CSV 統計與研究圖表 |

### 3.3 架構上的主要問題

- `main.cpp` 同時負責 I/O、資料清理、模型、heuristics、patch 與外部 process，難以單元測試。
- `build_stats_from_groundtruth()` 本身約 450 行；相似邏輯也出現在 `p1_stats.cpp`。
- CPU/GPU 選擇規則分散：`batch_simulator` 與 `main` 各自使用 50,000-node threshold，miner 又有不同策略。
- Makefile 將所有 `core/*.cpp`、`io/*.cpp`、`algorithm/*.cpp` 連入每個 executable。連只顯示 area/level 的 `show` 都依賴 Z3、CUDA，約 1.3 MB。
- Makefile 沒有 header dependency generation；`-march=native` 與 CUDA `--gpu-architecture=native` 使 binary 綁定建置機。
- 實測 Make 在 link 後把 object 視為 intermediate 並刪除，增量 rebuild 效率差。

## 4. 目前實際演算法

### 4.1 Groundtruth 與 sampling

`ParallelCollectLog` 以 `json::parse(input)` 一次把完整 JSON 建成 DOM，再把每個 pattern 搬入 `patterns_`（`src/io/parallel_collect_log.cpp:20-44`）。主流程之後才建立 `unordered_set<string>` 去重，並再轉成 `vector<vector<int>>`（`src/main.cpp:318-359`）。

風險：

- 最大 JSON 單檔約 1.6 GB；DOM、pattern vector、dedup strings 與 int vectors 同時存在，peak RAM 很高。
- JSON 只要 `pattern_bits` 合法就被視為 trigger，主程式不重新驗證 golden != trojan。
- `pi_order` 只要求每個 circuit PI 至少出現，沒有拒絕重複 PI 名稱。
- CEC 新增 positive 後只 append pattern/count，沒有重算 `ones_trigger`、`ones_total`；VN ranking 與 single-literal stats 可能使用過期分子／分母。

初始 non-trigger 數量被設定成與 unique trigger 數量相同（`src/main.cpp:377-379`），所以 `compute_trojan_rate = trigger / total` 在首輪固定為 **0.5**。這不是木馬在自然輸入分布下的 activation rate。

### 4.2 Candidate selection

`candidate_selector` 名稱暗示 ranking/filtering，但現況只是把所有 `GATE` 全部放入候選（`src/algorithm/candidate_selector.cpp:17-27`）。

後果：

- Feature 數基本等於 gate 數；AES 約 491,808 gates，gps 約 577,885 gates。
- `no_filter` CLI 欄位沒有被 main 使用。
- Activation stats 主要只供 VN pool 與 literal heuristic，不是 candidate filter。

### 4.3 Decision tree

- Training matrix：column-major bit-packed，約 `F × ceil(N/64) × 8 bytes`。
- Split objective：**Gini impurity reduction**，不是 ALGORITHM.md 所寫的 information gain。
- 每個 split 使用 binary feature 0/1；positive leaves 轉成 DNF rules。
- Mixed node 到 max depth、沒有可用 feature，或 gain <= 0 時會回傳 **positive leaf**，設計偏向低 false-negative、可能提高 false-positive。
- Strict mode 只在 training false-positive > 0 時啟動；結束後即使仍有 FP 也不會讓 `run_mining()` fail。

### 4.4 Virtual node（目前版本）

實際流程與文件的多輪 subclause mining 不同：

1. Phase-1 tree 找出 rule 用過的 signal。
2. 建 signature base pool，最多 64 signals。
3. 取最多 32 positive、約 8–32 negative；總 signature 最多 64 bits。
4. 每對 signal 枚舉四種正反相 AND。
5. 保留前 300 pair states，再延伸 triple；最多輸出 300 VN。
6. 再訓練一次，將 provisional tree 使用的 VN materialize 到 circuit。

目前不產 OR/XOR VN，沒有文件所述的 iterative subclause/revert，也沒有以 baseline rule/literal/area improvement 作為 materialize gate。Final tree 若不再用某個 VN，可能留下 disconnected VN。

### 4.5 Final mining 的參數實況

CLI 定義：

- `--mine-rounds` 預設 15
- `--mine-max` 預設 5000
- `MiningOptions::eval_count` 預設 1,000,000

但 `src/main.cpp:2292-2300` 寫死：

```cpp
mining_options.eval_count = 0;
mining_options.mine_rounds = 1;
mining_options.mine_max = 0;
```

所以目前 final mining 只訓練一次，不做 random evaluation，也不加入 hard negative。`--mine-rounds` 與 `--mine-max` 只被印出，沒有作用。

目前 CLI 實況：

| 參數 | 現況 |
|---|---|
| `--depth` | 有效 |
| `--neg-ratio` | 有效，但受 2M/memory cap |
| `--force-split` | 有效 |
| `--no-strict` | 有效 |
| `--no-virtual` | 有效 |
| `--mine-rounds` | 無效，final mining 固定 1 |
| `--mine-max` | 無效，final mining 固定 0 |
| `--include-pi` | 預設已是 true，只有正向 flag，實際無法關閉 |
| `--no-filter` / `--all-gates` | 欄位未被 main 使用 |

### 4.6 Patch 策略

目前順序為：

1. **Verified literal patch cut**：找 rules 共通 literal，以 fanout/名稱 cost 排序，最多嘗試 16 個 force-constant 候選；只先驗 known trigger。
2. **Signature minimization / single-literal kill**：用 sampled signatures 簡化 model；若可化成單 literal，將 gate force 為相反值。
3. **MaxSAT payload analysis**：在錯誤 PO fan-in cone 內用 Z3 Optimize 最小化 flip gate 數；逐輪加入 5 個 sample。
4. **Rule-controlled patch**：對選定節點插入 rule-controlled XOR，特定 XOR/XNOR case 可 bypass。
5. **Known-trigger verify + ABC CEC**：失敗 CEX 分類為 missed trigger 或 patch false-positive，最多 5 輪。

MaxSAT 沒有 timeout，objective 只最小化 gate 數，沒有 area、level、fanout cost。其最壞複雜度為指數級，大型 AES/gps/mor1kx 可能長時間卡住或 OOM。

### 4.7 複雜度

| 階段 | 近似成本 |
|---|---|
| Packed simulation | `O((P/64) × (V+E))` |
| Feature matrix memory | `O(F×N/8)` bytes |
| Decision tree | 近似 `O(T×F×N/64)`；T 可能隨 depth 快速增長 |
| VN pairs | `O(B²)`，目前 B <= 64 |
| VN triples | `O(S×B)`，目前 S <= 300 |
| Exact signature hitting set | <=22 literals 時最壞 `O(2^L)`；較大時改 greedy |
| Z3 MaxSAT | 最壞指數，且目前無 timeout |
| ABC CEC | SAT/CEC 最壞指數；主程式最多 5 輪 |

## 5. 測資盤點

### 5.1 Golden benchmarks

| Circuit | Area(gates) | Level | PI | PO |
|---|---:|---:|---:|---:|
| aes | 491,808 | 30 | 7,105 | 6,976 |
| c2670 | 1,193 | 32 | 233 | 140 |
| c3540 | 1,669 | 47 | 50 | 22 |
| c5315 | 2,307 | 49 | 178 | 123 |
| c6288 | 2,416 | 124 | 32 | 32 |
| c7552 | 3,512 | 43 | 207 | 108 |
| c880 | 383 | 24 | 60 | 26 |
| div | 101,826 | 8,708 | 128 | 128 |
| gps | 577,885 | 62 | 10,297 | 10,287 |
| mem_ctrl | 83,948 | 198 | 1,204 | 1,231 |
| mor1kx | 373,799 | 119 | 30,015 | 30,087 |

這組資料同時包含小型 ISCAS 與大型合成電路，但 groundtruth 幾乎集中在小型 ISCAS；大電路的支援成績沒有被系統性測試。

### 5.2 Canonical Trojan 與 groundtruth 覆蓋

| Variant | Canonical Trojan | JSON | 非空可用 JSON | 有效覆蓋率 |
|---|---:|---:|---:|---:|
| V0 single-trigger/single-payload | 1,000 | 502 | 482 | 48.2% |
| V1 single-trigger/multi-payload | 330 | 169 | 57 | 17.3% |
| V2 multi-trigger/single-payload | 330 | 2 | 1 | 0.3% |
| V3 multi-trigger/multi-payload | 330 | 0 | 0 | 0% |
| **合計** | **1,990** | **673** | **540** | **27.1%** |

Groundtruth raw entries 與 JSON 大小：

| Variant | Raw `pattern_count` 合計 | 非空/空檔 | JSON 大小 |
|---|---:|---:|---:|
| V0 | 159,710,395 | 482 / 20 | 33.50 GiB |
| V1 | 110,608,294 | 57 / 112 | 15.02 GiB |
| V2 | 2 | 1 / 1 | < 1 MiB |

Raw `pattern_count` 不是 unique PI pattern 數。同一 PI pattern 若影響多個 output，JSON 可能重複；例如 `c880_trojan65` raw 172 筆，unique pattern 126 筆。主程式會去重，但要先把完整 JSON 載入 RAM。

### 5.3 每個 variant 的缺口

V0：

- `c2670/c3540/c5315`：各 100 案且非空。
- `c7552`：100 JSON，16 個 zero-pattern。
- `c880`：100 JSON，4 個 zero-pattern。
- `aes` 只有 trojan1；`c6288` 只有 trojan0。
- `div/gps/mem_ctrl/mor1kx`：完全沒有 groundtruth。

V1：

- 非空：c2670=3、c3540=0、c5315=16、c6288=11、c7552=7、c880=20。
- aes/div/gps/mem_ctrl/mor1kx 沒有 JSON。
- skipped log 顯示多個 case 在 collector 的 180 秒 timeout。

V2/V3：

- V2 只有 c880 trojan0（非空）與 trojan10（空）。
- V3 沒有任何 groundtruth。

### 5.4 資料生成與可重現性

- V1–V3 由 `gen_trojan.py` 產生：每 circuit/variant 30 案、trigger size 5、V1=4 payload、V2=3 triggers、V3=3 triggers/6 payload。
- Generator 使用 Python `random` 與 NumPy random，但沒有固定 seed，也沒有 CLI/config snapshot，不能生成相同資料。
- Generator 只產 V1–V3；V0 沒有 generator 或完整 trigger/victim metadata。
- Groundtruth 依賴外部 Docker image `ht-collect`，repo 沒有 Dockerfile、image digest、版本或 source。
- Collector `SUBDIR_ALLOWLIST = ["c880"]`，目前預設只收 c880，與 README 所述掃整個 root 不一致。
- Collector 會遞迴包含 `_patched/_strash/_rule_merged` 等衍生 `.bench`，可能污染資料集。
- 673/673 JSON 的 `origin_path`、`trojan_path` 都是舊機器或 container 絕對路徑，不能直接使用。
- V0 的 `round` 是 Trojan ID；V1/V2 的 `round` 固定 1，欄位語意不一致。
- `benchmarks/`、`trojaned_bench/`、`groundtruth/` 都被 `.gitignore` 排除，沒有 manifest、hash、license 或下載位置。

### 5.5 一致性正面結果

- 673/673 `pi_order` 均可對到目前 golden benchmark 的 PI 名稱／數量。
- Groundtruth filename 都可對到 canonical Trojan，沒有 orphan JSON。
- 540 個非空 JSON 的代表性 pattern 長度與 PI 數一致；代表性 verifier 案例確實造成 mismatch。
- V1–V3 canonical `.bench`/`.txt` metadata 配對齊全。

## 6. 測試與目前成績

### 6.1 現有測試設施

| 檔案 | 用途 | 限制 |
|---|---|---|
| `run_tests.sh` | V0 全批 end-to-end + ABC CEC | 只跑已有 V0 JSON；直接覆寫 V6 CSV |
| `run_v0_sample.sh` | V0 隨機抽樣 | 只掃 `c*`、未固定 shuf seed、可抽到衍生 bench |
| `script/verify_groundtruth` | 驗 JSON pattern | zero pattern 會 vacuous PASS；V1/V2 basename 多版本 ambiguous |
| `script/packed_cmp` | scalar vs packed | 固定只測 1 pattern，沒有 64/65-bit boundary |
| `fast_verify.sh` | ABC cleanup 統計 | 沒 assertion，不是 regression test |
| `show_GT` | 顯示 JSON summary | zero-pattern JSON 仍讀第 0 筆而拋錯 |

專案沒有：

- `tests/` 目錄
- GoogleTest / Catch2 / CTest / pytest
- Makefile `test` target
- CI workflow
- coverage、sanitizer、CPU/GPU parity suite
- malformed-input tests

### 6.2 V6 結果

`results_v6_signature_min.csv` 有 502 筆，正好對應 V0 的 502 份 JSON：

| Status | 數量 |
|---|---:|
| PASS | 463 |
| CEC_FAIL | 5 |
| TIMEOUT | 14 |
| SKIP_NO_PATTERNS | 20 |

- Runnable case 成功率：`463 / 482 = 96.06%`
- 以所有 CSV row 計：`463 / 502 = 92.23%`
- 這不是全 1,990 case 的成功率；以全部 canonical cases 為分母，目前可證明 PASS 的比例是 `463 / 1990 = 23.27%`。

分 circuit：

| Circuit | PASS | CEC_FAIL | TIMEOUT | SKIP empty |
|---|---:|---:|---:|---:|
| aes | 1 | 0 | 0 | 0 |
| c2670 | 100 | 0 | 0 | 0 |
| c3540 | 100 | 0 | 0 | 0 |
| c5315 | 84 | 2 | 14 | 0 |
| c6288 | 1 | 0 | 0 | 0 |
| c7552 | 81 | 3 | 0 | 16 |
| c880 | 96 | 0 | 0 | 4 |

V6 CSV 缺少 commit hash、working-tree diff、CLI、ABC version、seed、CPU/GPU/driver、dataset hashes；而且檔案目前未納入 Git，因此無法嚴格重現。

## 7. 問題清單與優先級

### P0：先修正，否則會影響正確性／論文結論

#### P0-1 PI/PO alignment 只比數量

- 證據：`src/core/circuit_compare.cpp:3-19`
- 後續按位置送 PI bits、按位置 XOR PO：`src/main.cpp:656-661`、`src/algorithm/miner.cpp:1034-1036`、`src/core/batch_simulator.cpp:243-279`
- 影響：相同 signal 集合但不同 declaration order 時，trigger label 與 patch PO 都可能錯。
- 建議：以名稱建立 golden↔trojan PI/PO permutation，拒絕缺名、重名與集合不一致。

#### P0-2 CPU explicit-negative matrix corruption

- `write_word_block()` 明確要求 `row_count` 64-aligned，並以 assignment 寫整個 word：`src/algorithm/miner.cpp:236-251`。
- CPU CEC negative 路徑沒有 padding 就直接呼叫：`:921-950`。
- 影響：positive 數不是 64 倍數時，最後 positive word 被覆寫，feature row 與 label row 位移。
- CUDA 路徑雖 padding，但 `pad_to_word_aligned()` 插入 1–63 個不存在的全零 negative：`:367-376,649-652`。
- 建議：統一改用支援任意 bit offset 的 append，不得製造假樣本。

#### P0-3 Hard-negative mining 被關閉且 CLI 無效

- 證據：`src/main.cpp:2292-2300`
- Mining loop 只有 `eval_count > 0` 且非最後輪才有機會挖 hard negatives：`src/algorithm/miner.cpp:1406-1449`
- 影響：README/ALGORITHM 宣稱的 1M evaluation、15 rounds、zero-FP enforcement 未實際執行。
- 建議：讓 CLI 真正傳入，將 false-positive target 與「自然 trojan rate」拆開，結果檔記錄實際 effective options。

#### P0-4 失敗仍回傳 0，CEC wrapper 不可靠

- 無 fix、五輪 CEC 失敗或 CEX parse 失敗，最後仍 `return 0`：`src/main.cpp:2655-2709`。
- `pclose()` status 被忽略，只比對固定英文：`:102-106`。
- ABC path 由 golden path 硬推，不使用 README 的 `ABC_BIN`：`:68-88`。
- shell command 沒安全 quoting；帶空白或 shell 字元的路徑會失敗／有 injection 風險。
- 建議：定義明確 exit code；CEC fail 刪除或標記 failed artifact；使用 `fork/exec` 或安全 argument API；解析 ABC return status。

### P1：高風險

#### P1-1 CUDA strict replay 可能把錯的 pattern 標 negative

初次 GPU negative 由 seed 42 的 GPU RNG 產生，但 trace 只保存 selection mask；strict replay 改用 host MT19937 seed 1337 套相同 mask，沒有重新比較 golden/trojan。可能把不同、甚至真正 trigger 的 pattern 標成 negative。證據：`src/algorithm/miner.cpp:700-829`。

#### P1-2 `trojan_rate` 固定 0.5，語意與停止條件錯置

初始正負樣本刻意等量，所以 rate 固定 0.5；mining loop 卻把它當可接受 false-positive rate。若重新開啟 HNM，可能 FP <= 50% 就停止。證據：`src/main.cpp:377-379`、`src/algorithm/pattern_sampler.cpp:3-8`、`src/algorithm/miner.cpp:1423-1446`。

#### P1-3 Strict 不保證 zero-FP

Strict 只看 training FP，不看 eval FP；即使 strict 後仍 FP，`run_mining` 仍 true。Mixed/depth-limit leaf 又固定 positive，模型偏向 false-positive。證據：`src/algorithm/miner.cpp:1561-1596`、`src/algorithm/decision_tree.cpp:96-98,246-247`。

#### P1-4 Groundtruth 與 CEC 新資料未完整更新 stats

- 主程式不驗證 JSON positive 真的造成 mismatch。
- CEC positive/negative append 後沒有重算 gate activation stats。
- 影響 VN pool、literal stats 與 ranking。
- 建議：讀入時 batch verify；以單一可重算 dataset/state 物件管理 CEX。

#### P1-5 MaxSAT / GPU 缺 timeout 與健全錯誤處理

- MaxSAT 無 timeout，成本函式不含 area/level/fanout。
- 多處 raw `cudaMalloc/cudaMemcpy` 未檢查 return code；exception fallback 可能保留部分 data/device allocation。
- VRAM 計算不足時仍至少配置 64 blocks。
- 建議：Z3 timeout、lexicographic cost、CUDA RAII/error wrapper、可測的 CPU fallback。

#### P1-6 測資與結果不可重現

- 只 27.1% canonical cases 有非空 GT。
- 資料未版控，無 manifest/hash/license/source。
- generator 無 seed，collector image 無 digest。
- V6 是未追蹤檔，main 是未提交版本。

### P2：維護性與工具問題

- `main.cpp` 過大；應拆 `groundtruth_loader`、`cec_runner`、`vn_pipeline`、`signature_minimizer`、`patch_planner`。
- JSON 改 streaming/SAX 或 binary cache，避免 1.6 GB DOM。
- Makefile 改成明確 library/target dependency，不讓所有工具連完整演算法。
- 增加 `.d` header dependencies；提供 portable build profile，不預設 `-march=native`。
- Collector 移除 c880 hard-coded allowlist，排除 derived benches，單案失敗繼續並支援 resume。
- `run_v0_sample.sh`：固定 seed、支援 variant/all circuits、修 ABC failure branch 的 `append_row` 參數不足。
- Zero-pattern verifier 應回傳 SKIP/非零，不應 vacuous PASS。
- 補 64/65/127/128 pattern boundary、PI/PO reorder、CPU/GPU parity、CEC negative retry、各 patch strategy 測試。

## 8. 老舊／不必要程式碼與檔案

### 8.1 高信心 legacy code 候選

以下 public function 在 repo 內只有 declaration/definition，沒有 caller；移除前仍應確認沒有 repo 外部程式直接 link：

| 候選 | 約行數 | 判斷依據 | 建議 |
|---|---:|---|---|
| `src/algorithm/sat_refine.{cpp,hpp}` | 1,417 | `collect_rule_counterexamples()` 無 caller；main 只剩「SAT refinement loop」舊註解 | 先移到 legacy branch，再從 Makefile 移除 |
| `src/algorithm/trigger_fixer.{cpp,hpp}` | 485 | `apply_rule_fix()` 無 caller；目前走 `rule_patch + payload_analysis` | 封存後移除 include/build |
| `src/algorithm/matching.{cpp,hpp}` | 130 | `apply_pattern_fix()` 無 caller；`show.cpp` include 但沒使用 | 可優先移除 |
| `find_used_virtual_gate_indices()` | 單一 API | main 自行重做 VN used-set | 刪 declaration/definition或改 main 共用 |
| `evaluate_fix_candidate()` | 單一 API | 無 caller | 移除 |
| `pi_values_to_bits()` | 單一 API | 無 caller | 移除 |
| `eval_rules_packed()` | 單一 API | 無 caller | 確認無外部 API 後移除 |
| `used_vn_indices` local vector | 數行 | 收集後未使用（`main.cpp:2264-2268`） | 直接清理 |

上述三個完整 legacy module 合計約 **2,032 行**。因 Makefile glob 所有 `algorithm/*.cpp`，它們目前仍被編譯、連到每個工具並增加 binary/dependency burden。

### 8.2 無效／過時介面

- `--mine-rounds`、`--mine-max`：表面存在、實際被 hard-code 覆蓋。
- `--no-filter` / `--all-gates`：`no_filter` 欄位沒有被 main 使用。
- `--include-pi`：預設 true 又只有 enable flag，無法 disable。
- `find_used_virtual_gate_indices()` 已被 main 內嵌邏輯取代。
- `rule_patch.cpp` 仍保留「caller 應展開 VN kill」錯誤訊息，但目前沒有 VN expand caller；README/ALGORITHM 所述 VN expand kill 已不存在。

### 8.3 可直接清理的 generated／重複產物

| 檔案 | 現況 | 建議 |
|---|---|---|
| `gmon.out` | 362 KB profiler binary output，已被 Git 追蹤 | 從 repo 移除並加入 `.gitignore` |
| `test.txt` | 31 KB 舊 terminal transcript，內容已顯示舊參數／舊流程 | 移至研究 log archive 或刪除 |
| `golden_circuit` | 與 `golden_circuit.dot` byte-for-byte 相同 | 刪除無副檔名副本 |
| `.claude/settings.local.json` | 個人機器的本地工具權限 | 從 Git 移除、加入 ignore；只保留團隊共用範本時另命名 |
| `bin/script/bench_compiled` | ignored unmanaged binary，Makefile 沒對應 source/target | 刪除本地 binary；若仍需使用，先補 source/build target |

### 8.4 先歸檔／確認後清理

| 候選 | 問題 | 建議 |
|---|---|---|
| `compile.md` | 描述 partitioned CUDA code generator，與目前 runtime patcher 架構不同 | 移至 `docs/archive/` 或刪除 |
| `results_v1_add_cec_round_old.csv` | 名稱已明確標 old | 移至 `results/archive/` |
| `results_v4_*`, `results_v5_*` | 僅 246/226 rows，為中斷批次 | 標註 incomplete 並歸檔，勿與完整結果並列 |
| `outputs/v1_fix_results*.tsv` | 舊 schema、含 patched bench 再被當測例的污染 | 歸檔後以新 runner 重建 |
| `groundtruth/V0_singleTrigger_singlePayload.tar.gz` | 4.29 GiB，與已展開 V0 目錄重複佔空間 | 驗 hash／外部備份後只保留 archive 或 extracted 其中一份 |
| `_patched/_strash/_rule_merged` benches | 227/42/59 個衍生檔，約 51 MiB，混在 canonical fixture root | 搬到 `outputs/`，避免 collector/sample runner 誤收 |
| `flow.xml`, `circuit_example.xml`, `*.dot` | 文件／簡報素材，不是 runtime | 移到 `docs/diagrams/`，避免根目錄混雜 |
| `profiling.md` | 有價值，但含個人 WSL 絕對路徑與 2026-03-02 單次數據 | 保留並改成可重現 benchmark note |

### 8.5 文件漂移

- README 寫 `bin/show`、`bin/synthesis`；實際是 `bin/script/show`、`bin/script/synthesis`。
- README 寫不存在的 `run_v0_tests.sh`；實際是 `run_tests.sh`。
- ALGORITHM 寫 information gain；實作是 Gini。
- ALGORITHM 寫 1M hard-negative、15 rounds；目前 final mining 是 0 eval、1 round。
- ALGORITHM 寫 iterative subclause VN、OR/XOR VN、VN expand kill；目前是 signature pair/triple AND，無 expand kill。
- README 提到 `ABC_BIN`；main 的 CEC wrapper不讀它。

## 9. 建議執行順序

### 第一階段：P0 正確性（先做）

1. 實作 PI/PO 名稱 permutation 與嚴格 interface validation。
2. 修正 arbitrary-offset column-major append，新增 1/63/64/65 positive + CEC negative tests。
3. 恢復／重新設計 hard-negative mining，移除無效 CLI；將 FP target 設為獨立參數。
4. CEC/無 patch/round exhausted 使用非零 exit code；安全執行 ABC 並檢查 status。
5. 加入最小 regression suite，先鎖住上述四項行為。

### 第二階段：資料與可重現性

1. 建立 `datasets/manifest.csv` 或 JSON：variant、case ID、來源/license、generator commit、seed/config、golden/trojan/GT SHA-256、pattern_count、expected status。
2. 明確決定宣稱的支援範圍；若宣稱 V0–V3，至少補 V1–V3 的代表性、分層 groundtruth。
3. 固定 generator seed；collector image 用 digest；記錄 ABC/CUDA/Z3 version。
4. Runner 將 commit、dirty diff hash、CLI、seed、host/GPU、dataset hash 寫入 results metadata。
5. 將 canonical fixtures、derived outputs 與 archived results 分開。

### 第三階段：架構與 legacy 清理

1. 把 `main.cpp` 拆成可測 module。
2. 用 target-specific library/object list 取代 Makefile wildcard 全連結。
3. 對無 caller module 建立 legacy tag/branch，移除後做 full build + smoke + V0 regression。
4. 改 streaming JSON / packed binary cache。
5. 同步 README、ALGORITHM、research.tex 與實際 effective parameters。

### 第四階段：演算法品質

1. 修 CUDA strict replay，保存真正 PI bits 或重新分類，不重用不同 RNG 的 mask。
2. Strict unresolved FP 應 fail，不應默默產出 patch。
3. CEC CEX 加入後完整重算 stats；groundtruth 讀入時先驗真。
4. MaxSAT 加 timeout、area/level/fanout objective，並驗證 conditional patch 與 solver objective 一致。
5. VN materialize 前比較 baseline vs candidate 的 rule/literal/area，final patch 前移除 unused VN。

## 10. 稽核期間資料變動說明

稽核時曾以 `python3 gen_trojan.py --help` 檢查 CLI；該腳本沒有 help/argument parser，而是直接進入 generation。程序已立即停止，但以下 **26 個 ignored、未受 Git 管理的 generated files 已被重新產生**：

- V1 AES：`aes_trojan0..4.{bench,txt}`（10 檔）
- V2 AES：`aes_trojan0..3.{bench,txt}`（8 檔）
- V3 AES：`aes_trojan0..3.{bench,txt}`（8 檔）

影響判斷：

- 沒有任何受 Git 管理的 source/doc 被此操作覆寫。
- 這些 AES V1/V2/V3 case 目前沒有對應 groundtruth，不影響現行 V0 502-case runner 或 V6 CSV。
- 因 generator 沒有 seed，原內容無法由 Git 或 generator 精確重建。
- 若需要保留原始研究資料，應從外部備份還原這 26 檔；若沒有備份，建議先為 generator 加 seed/manifest，再一次性重建完整 AES V1–V3，而不是混用新舊樣本。

## 11. 最終判斷

目前專案的研究原型價值高，且 V0 已有不錯的局部結果；但「build 成功」和「V0 子集 96.06%」尚不足以支持全資料集、全 variant 或 zero-FP 的結論。最優先應修正 alignment、training matrix append、HNM effective options 與 exit/CEC contract，再建立可重現 dataset manifest 與 regression tests。

Legacy code 可以清，但應排在正確性修復之後。高信心可先處理的是 `matching.*`、無 caller helper、`gmon.out`、`test.txt`、重複 `golden_circuit` 與本地 `.claude/settings.local.json`；`sat_refine.*`、`trigger_fixer.*` 則建議先在 legacy branch 封存，再由完整 regression 證明移除不改變結果。
