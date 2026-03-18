# 演算法架構說明

## 問題定義

**輸入：**
- Golden 電路（黑盒子，只能觀察輸入輸出行為）
- Trojan 電路（完整 gate-level netlist，已知被植入木馬）
- Error patterns（若干筆 PI 輸入，會導致 Trojan 電路的輸出與 Golden 不同）

**目標：**
產生一個修補後的電路，使其與 Golden 功能完全等價，且面積（area）和延遲（level）的增加盡可能小。

**核心思路：**
將每筆 error pattern 模擬後，把電路中每個 gate 的值當作 feature，用 decision tree 學出 trigger 的觸發條件（rules）。再根據這些 rules，透過插入 MUX/XOR 的方式修補受影響的 primary output。

---

## 整體流程

```
                        ┌──────────────────────┐
                        │   Parse & Align      │
                        │   Golden + Trojan    │
                        └──────────┬───────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │     CEC Retry Loop          │
                    │     (最多 5 輪)              │
                    │                              │
  ┌─────────────────▼─────────────────────────┐   │
  │  1. Groundtruth 模擬                       │   │
  │     ─ 載入 error patterns                  │   │
  │     ─ 模擬 golden + trojan                 │   │
  │     ─ 分類 trigger / non-trigger patterns  │   │
  └─────────────────┬─────────────────────────┘   │
                    │                              │
  ┌─────────────────▼─────────────────────────┐   │
  │  2. Candidate Selection                    │   │
  │     ─ 挑出所有 gate 作為 feature 候選       │   │
  └─────────────────┬─────────────────────────┘   │
                    │                              │
  ┌─────────────────▼─────────────────────────┐   │
  │  3. Virtual Node 生成（迭代式）             │   │
  │     ─ Phase 1: 快速 tree → 找重要 signal   │   │
  │     ─ Phase 2: 組合產生 VN candidate       │   │
  │     ─ Phase 3: 迭代訓練，挖 subclause     │   │
  │     ─ Phase 4: 只插入有用的 VN 到電路      │   │
  └─────────────────┬─────────────────────────┘   │
                    │                              │
  ┌─────────────────▼─────────────────────────┐   │
  │  4. Final Mining（Strict Mode）            │   │
  │     ─ Decision Tree 訓練                   │   │
  │     ─ Hard-negative mining                 │   │
  │     ─ Strict retry（無限深度 + 全 PI）     │   │
  │     ─ Rule 簡化                            │   │
  └─────────────────┬─────────────────────────┘   │
                    │                              │
  ┌─────────────────▼─────────────────────────┐   │
  │  5. 修補策略                               │   │
  │     ─ Trigger Kill                         │   │
  │     ─ VN Expand Kill                       │   │
  │     ─ Payload Fix（MaxSAT + MUX 插入）     │   │
  └─────────────────┬─────────────────────────┘   │
                    │                              │
  ┌─────────────────▼─────────────────────────┐   │
  │  6. CEC 驗證（ABC 等價性檢查）             │   │
  │     ─ PASS → 輸出修補電路，結束            │   │
  │     ─ FAIL → 取 counter-example            │   │
  │              加入 trigger patterns，重跑    │   │
  └─────────────────┬─────────────────────────┘   │
                    │                              │
                    └──────────────────────────────┘
```

---

## 各階段詳細說明

### 1. Groundtruth 模擬

從 JSON 格式的 groundtruth log 中讀取 error patterns（PI 輸入值）。這些 patterns 是已知會讓 trojan 電路輸出與 golden 不同的輸入。

- 將每筆 pattern 的 PI 值對應到電路的 PI 節點
- 去除重複 pattern
- 若是 CEC retry 的第二輪以後，會將前幾輪 CEC 產生的 counter-example 也加入 trigger patterns

**輸出：** `trigger_patterns`（vector of PI values）、`notrigger_patterns`、trojan activation rate

### 2. Candidate Selection

從模擬結果中選出所有 gate 節點作為 decision tree 的 feature 候選。

- 包含所有 GATE 類型節點
- 可選擇是否包含 Primary Input（`--include-pi`）
- 過濾掉先前 rule merge 產生的 `rule_opt_gate_*` 節點，避免汙染

**輸出：** `candidate_indices`（gate index 列表）

### 3. Virtual Node 生成（迭代式多階段）

Virtual Node（VN）的目標是**壓縮 trigger 條件的表達**。如果 trigger 需要多個 gate 同時滿足特定值（例如 `A=1 AND B=1 AND C=0`），decision tree 需要多層 split 才能表達。VN 把這些組合預先計算成單一 feature（例如 `vn_A_AND_B = A AND B`），讓 tree 用一次 split 就能表達。

#### Phase 1：快速訓練，找出重要 signal

```
設定：max_depth=10, strict_retry=false, mine_rounds=1
輸入：base_for_vn（所有非 VN 的 candidate gate）
輸出：important_signals（Phase 1 rules 中用到的 gate index）
```

用一棵淺層 decision tree 快速辨識哪些 gate 與 trigger 有關。這些 gate 就是後續生成 VN 的素材。

#### Phase 2a：組合產生 VN candidate

從 `important_signals` 中取所有 pairwise（兩兩組合）和 triple（三個組合）：

```
對每對 (A, B)，產生：
  - A AND B
  - A AND (NOT B)
  - (NOT A) AND B
  → 3 個 VN candidate per pair

對每個三元組 (A, B, C)（當 signal 數 ≤ 12 時）：
  → 3 個 VN candidate per triple

典型數量：56 個 signal → C(56,2)×3 = 4,620 個 pairwise VN
```

#### Phase 2b：Subclause Mining

從 Phase 1 的 rules 中挖掘頻繁出現的子條款（長度 3-4 的 literal 組合）：

```
例如：若多條 rule 都包含 (A=1, B=0, C=1)
→ 產生 VN: A AND (NOT B) AND C
→ 加入 all_vn_defs（最多 500 個）
```

這些 subclause-based VN 比盲目的 pairwise 更有針對性，因為它們直接來自 tree 發現的 pattern。

#### Phase 3：迭代精煉（最多 3 輪）

```
每輪：
  1. 用 base_for_vn + 所有 VN（on-the-fly 計算）訓練 decision tree
     設定：max_depth=10, strict_retry=false
  2. 比較 rule 數量：
     - 若 rule 數沒有減少 → revert 本輪新增的 VN，停止迭代
     - 若有減少 → 記錄為 best，繼續
  3. 從本輪 rules 挖 subclause（長度 2-4），加入 VN candidate
     - 跳過 VN-on-VN 組合（避免巢狀爆炸）
  4. 若沒有新 subclause → 收斂，停止

追蹤 best_vn_defs：保留 rule 數最少的那輪 VN 集合
```

**注意：** VN 迭代期間電路不會被修改。VN 特徵是 on-the-fly 從模擬值計算的。

#### Phase 4：插入有用的 VN

```
1. 用 best_vn_defs 做最後一次訓練
2. 找出 rules 中實際用到的 VN index
3. 只把 used VN 插入電路（add_virtual_gates_to_circuit）
4. 將新 VN gate 加入 candidate_indices
```

例如：24,044 個 VN candidate 中可能只有 7 個被實際使用。只插入這 7 個，避免電路膨脹。

### 4. Final Mining

使用完整的 decision tree mining pipeline 找出最終的 trigger rules。

#### 訓練資料建構

```
正樣本（Positive）：trigger patterns 的模擬結果
  - 每筆 pattern 模擬 trojan 電路，取各 candidate gate 的值作為 feature vector
  - Label = 1（trigger 被觸發）

負樣本（Negative）：
  - 隨機產生 PI 輸入，模擬 golden + trojan
  - 只保留 golden == trojan 的 pattern（non-trigger）
  - 數量 = pos × neg_ratio（預設 50 倍）
  - Label = 0

特徵矩陣格式：column-major bit-packed（PackedFeatureMatrix）
  - data[feature * packed_rows + word] 的每個 bit 代表一筆 sample 的值
  - 支援 64-bit word 平行運算
```

#### Decision Tree 訓練

```
演算法：標準 CART（Classification and Regression Tree）
  - 每個節點選最佳 split feature（最大 information gain）
  - 產生 binary split：feature = 0 或 feature = 1
  - 葉節點為 positive class 時，收集從 root 到 leaf 的所有 split 條件
    → 形成一條 rule（多個 literal 的 AND）

輸出：
  - rules: [{(feature_i, polarity_i), ...}, ...]
  - 每條 rule 是一組 AND 條件
  - 所有 rules 之間是 OR 關係
  - 即 trigger 條件 = rule_1 OR rule_2 OR ... OR rule_N
```

#### Hard-Negative Mining（迭代式）

目標：降低 false positive rate，確保 rules 不會誤判 non-trigger pattern 為 trigger。

```
重複最多 mine_rounds 輪（預設 15）：
  1. 隨機產生大量 PI pattern（預設 eval_count = 1,000,000）
  2. 模擬 golden + trojan，找出 non-trigger pattern
  3. 對每個 non-trigger pattern，用當前 rules 判斷
  4. 若 rules 誤判為 trigger → 這是 hard negative
  5. 將 hard negatives 加入訓練資料（每輪最多 mine_max = 5,000）
  6. 重新訓練 decision tree

停止條件：
  - 達到最大輪數
  - 某輪找不到新的 hard negative
  - 已達成 0 false positive
```

#### Strict Retry

若 hard-negative mining 後仍有 false positive（`train_false_pos > 0`），啟動 strict mode：

```
設定：
  - force_split = true（強制 tree 繼續分裂，即使 gain 很低）
  - max_depth = 無限制（max_depth = feature 數量）
  - 加入所有 Primary Input 作為額外 feature
  - 重新建構訓練資料 + 重跑 mining loop

目的：確保 0 false positive
代價：可能產生很多 rules（tree 很深很寬）
```

#### Rule 簡化

```
simplify_rules：
  - 移除被其他 rule 包含（更一般化）的冗餘 rule
  - 移除 rule 中矛盾的 term（同一 feature 同時要求 0 和 1）
```

### 5. 修補策略

找到 trigger rules 後，需要實際修補電路。依序嘗試三種策略：

#### 策略 A：Trigger Kill（最簡單）

```
嘗試：找到一個 gate，使得把它 force 成常數 0 或 1 後，
      所有 trigger pattern 都不再觸發。

條件：rules 中有某個 literal 出現在所有 rules 裡
      → 這個 gate 是 trigger 的必要條件
      → 強制它永遠不滿足 trigger 條件

驗證：修補後模擬所有 trigger pattern，
      確認輸出與 golden 一致

優點：幾乎零面積開銷（只是斷開一條線）
缺點：只在單一 trigger point 的簡單案例有效
```

#### 策略 B：VN Expand Kill

```
前提：Trigger Kill 找到的 gate 是一個 virtual AND node
      → 不能直接 kill（VN 是組合出來的，不是原本電路的 gate）

做法：展開 VN 的組成 signal，逐一嘗試 kill
      例如 VN = A AND (NOT B)
      → 嘗試 force A=0
      → 嘗試 force B=1
      → 若其中一個通過 verify → 採用

追蹤 NOT 反相：若 VN 的 input 經過 NOT gate，
      需要反轉 kill value（NOT(x)=0 → x=1）
```

#### 策略 C：Payload Fix（MaxSAT + MUX 插入）

最通用但面積開銷最大的策略。當 Trigger Kill 和 VN Expand Kill 都失敗時使用。

整體目標：找出 trojan 電路中哪些 gate 在 trigger 觸發時輸出了錯誤值，然後對這些 gate 插入修補邏輯（MUX），在 trigger 觸發時強制輸出正確值。

##### 5.C.1 建立 Forbidden Mask

修補不能改動 trigger detection 用到的 gate，否則會破壞 trigger 偵測。

```
1. 找出 trigger rules 中用到的所有 feature gate
   例如 rule: gate_100=1 AND gate_200=0
   → feature gates = {gate_100, gate_200}

2. 對每個 feature gate，追蹤其 fanin cone（所有上游 gate）
   gate_50 → gate_80 → gate_100
   → 全部標記為 forbidden

3. 例外：如果某個 feature gate 本身不會 feed 其他 feature gate，
   則允許它作為 candidate（因為翻轉它不影響其他 rule 判斷）

結果：forbidden_mask[node] = 1 表示該 gate 不可修改
```

##### 5.C.2 Candidate Gate 選取

不是所有 gate 都需要考慮翻轉。只挑跟「錯誤 PO」有關的 gate：

```
步驟：
1. 取當前 sample patterns，模擬 trojan 電路
2. 比對每個 PO 的 trojan 輸出 vs golden 輸出
3. 找出輸出錯誤的 PO（trojan ≠ golden）
4. 對每個錯誤 PO，追溯其 fanin cone（影響該 PO 的所有 gate）
5. 取所有錯誤 PO 的 fanin cone 聯集
6. 從聯集中移除 forbidden gate 和非 GATE 類型節點

例如：
  PO_3 輸出錯誤 → fanin cone 包含 {gate_10, gate_20, gate_30, ...}
  PO_7 輸出錯誤 → fanin cone 包含 {gate_20, gate_40, gate_50, ...}
  聯集 = {gate_10, gate_20, gate_30, gate_40, gate_50, ...}
  移除 forbidden → candidate_nodes = {gate_20, gate_30, gate_50, ...}

直覺：只有在錯誤 PO 的 fanin cone 裡的 gate 才可能是 payload 的位置。
翻轉不在 cone 裡的 gate 不可能修正該 PO 的輸出。
```

##### 5.C.3 MaxSAT 建模（Z3 Optimize）

這是核心。用 Z3 的 Optimize（加權 MaxSAT）找出「翻轉最少的 gate 就能讓 trojan 輸出正確」。

---

**什麼是 SAT / MaxSAT？**

```
SAT（布林可滿足性問題）：
  給一組布林約束（CNF 公式），問：存不存在一組變數賦值，讓所有約束都為 true？
  例如：(x OR y) AND (NOT x OR z) → x=true, y=true, z=true 是一組解

MaxSAT（最大可滿足性問題）：
  約束分為兩類：
    硬約束（hard clause）：必須滿足
    軟約束（soft clause）：盡量滿足，每個有權重 w

  目標：在滿足所有硬約束的前提下，最大化被滿足的軟約束的權重和
  等價地：最小化被違反的軟約束的權重和

  Partial MaxSAT：所有軟約束權重 = 1 → 最小化違反數量
  Weighted MaxSAT：軟約束有不同權重
```

**Z3 Optimize 如何求解 MaxSAT？**

```
Z3 的 Optimize 不是直接用傳統 MaxSAT solver，而是用以下策略：

1. 先找到一個可行解（滿足所有硬約束的任意解）
2. 計算當前目標值 cost_0
3. 加入新的硬約束：cost < cost_0
4. 重新求解，若有解則 cost_1 < cost_0
5. 重複步驟 3-4，逐步壓低目標值
6. 當無法再壓低時（UNSAT），上一輪的解就是最優解

本質上是「迭代收緊上界」：
  第 1 次求解 → cost = 5（翻轉了 5 個 gate）
  加入 cost < 5 → 第 2 次求解 → cost = 3
  加入 cost < 3 → 第 3 次求解 → cost = 2
  加入 cost < 2 → 第 4 次求解 → UNSAT（不可能只翻 1 個）
  → 最優解 = 2

Z3 內部還會用更高效的演算法（如 MaxRes、OLL 等），
但概念上等價於上述流程。
```

---

**At-Most-K Encoding：如何把「最多翻轉 K 個」變成純 SAT 約束？**

Z3 Optimize 內部每次要測試「cost ≤ K 是否有解」時，需要把 `flip_A + flip_B + ... ≤ K`
這個**計數約束**轉換成純布林 CNF 子句。這就是 At-Most-K Encoding 的工作。

```
問題：
  有 N 個布林變數 x_1, x_2, ..., x_N
  約束：最多 K 個為 true

  例如 N=4, K=2：
    x_1=T, x_2=T, x_3=F, x_4=F → 2 ≤ 2 ✓
    x_1=T, x_2=T, x_3=T, x_4=F → 3 > 2 ✗
```

**方法 1：Pairwise Encoding（最直覺，只適用 K=1）**

```
At-Most-1：任兩個變數不能同時為 true

變數：flip_A, flip_B, flip_C
約束：
  ¬flip_A ∨ ¬flip_B    （A 和 B 不能同時 true）
  ¬flip_A ∨ ¬flip_C    （A 和 C 不能同時 true）
  ¬flip_B ∨ ¬flip_C    （B 和 C 不能同時 true）

需要 C(N,2) 個子句。N=100 → 4,950 個子句。
K>1 時此方法無法直接使用。
```

**方法 2：Sequential Counter（Sinz 2005，通用方法）**

核心思想：用輔助變數 `s_{i,j}` 建立一個「計數器」，
`s_{i,j} = true` 表示「x_1 到 x_i 中，至少有 j 個為 true」。

```
完整範例：At-Most-2，變數 x_1, x_2, x_3, x_4

輔助變數（計數器狀態）：
  s_{1,1}, s_{1,2}    ← 掃過 x_1 後，至少 1/2 個為 true？
  s_{2,1}, s_{2,2}    ← 掃過 x_1,x_2 後
  s_{3,1}, s_{3,2}    ← 掃過 x_1,x_2,x_3 後
  s_{4,1}, s_{4,2}    ← 掃過全部後

共 N×K = 4×2 = 8 個輔助變數
```

```
初始化（i=1，只看 x_1）：
  ¬x_1 ∨ s_{1,1}      「x_1=true → 至少 1 個 true」
  ¬s_{1,2}             「只看 x_1 時，不可能有 2 個 true」

傳播（i=2，加入 x_2）：
  ¬s_{1,1} ∨ s_{2,1}                「之前至少 1 個 → 現在至少 1 個」
  ¬x_2 ∨ s_{2,1}                    「x_2=true → 現在至少 1 個」
  ¬x_2 ∨ ¬s_{1,1} ∨ s_{2,2}        「x_2=true 且之前≥1 → 現在≥2」
  ¬s_{1,2} ∨ s_{2,2}                「之前≥2 → 現在≥2」
  ★ ¬x_2 ∨ ¬s_{1,2}                 「如果之前已經 ≥2，x_2 必須 false」

傳播（i=3，加入 x_3）：
  ¬s_{2,1} ∨ s_{3,1}
  ¬x_3 ∨ s_{3,1}
  ¬x_3 ∨ ¬s_{2,1} ∨ s_{3,2}
  ¬s_{2,2} ∨ s_{3,2}
  ★ ¬x_3 ∨ ¬s_{2,2}                 「如果前 2 個已經 ≥2，x_3 必須 false」

傳播（i=4，加入 x_4）：
  ¬s_{3,1} ∨ s_{4,1}
  ¬x_4 ∨ s_{4,1}
  ¬x_4 ∨ ¬s_{3,1} ∨ s_{4,2}
  ¬s_{3,2} ∨ s_{4,2}
  ★ ¬x_4 ∨ ¬s_{3,2}                 「如果前 3 個已經 ≥2，x_4 必須 false」
```

```
★ 標記的子句是關鍵 — 它們強制執行 At-Most-K：

  ¬x_i ∨ ¬s_{i-1,K}

  翻譯：「如果前 i-1 個變數中已經有 K 個為 true，
         那第 i 個變數必須為 false。」

  這個約束沿著計數器傳播，保證整體不超過 K 個 true。
```

**手動 trace 驗證：**

```
嘗試 x_1=T, x_2=T, x_3=T, x_4=F（3 個 true，違反 At-Most-2）

計數器推導：
  x_1=T → s_{1,1}=T（至少 1 個）  s_{1,2}=F（只有 1 個）

  x_2=T：
    s_{2,1}=T（至少 1 個）
    x_2=T 且 s_{1,1}=T → s_{2,2}=T（至少 2 個）✓

  x_3=T：
    檢查 ★ 子句：¬x_3 ∨ ¬s_{2,2}
    → ¬T ∨ ¬T
    → F ∨ F
    → F ❌ 衝突！

  SAT solver 發現衝突 → 回溯 → x_3 不能為 T
  → 保證最多 2 個為 true ✓
```

```
嘗試 x_1=T, x_2=F, x_3=T, x_4=F（2 個 true，滿足 At-Most-2）

計數器推導：
  x_1=T → s_{1,1}=T  s_{1,2}=F

  x_2=F：
    s_{2,1}=T（從 s_{1,1} 傳播）
    s_{2,2}=F（x_2=F 且 s_{1,2}=F）
    ★ 子句：¬F ∨ ¬F = T ✓ （不衝突）

  x_3=T：
    s_{3,1}=T
    x_3=T 且 s_{2,1}=T → s_{3,2}=T（現在有 2 個）
    ★ 子句：¬T ∨ ¬F = T ∨ T = T ✓ （不衝突，因為 s_{2,2}=F）

  x_4=F：
    ★ 子句：¬F ∨ ¬T = T ✓

  全部子句滿足 ✓
```

**複雜度比較：**

```
                        輔助變數      子句數
Pairwise（K=1 only）    0            C(N,2) = O(N²)
Sequential Counter       N×K          O(N×K)
Totalizer                O(N×log²N)   O(N×log²N)
Cardinality Network      O(N×log²N)   O(N×log²N)

Sequential Counter 最常用：線性複雜度，實作簡單。
N=100, K=5 → 500 個輔助變數，~2000 個子句 → 對 SAT solver 幾乎無負擔。
```

**在我們的 Payload Fix 中的應用：**

```
Z3 Optimize 的 minimize(Σ flip_i) 內部流程：

1. 先用 SAT solver 找一組可行解 → cost = K₀（例如 5）

2. 加入 At-Most-(K₀-1) 約束（用 Sequential Counter 編碼）：
   「flip_1 + flip_2 + ... + flip_N ≤ 4」
   → 轉成 ~N×4 個 CNF 子句

3. 重新求解 → 若 SAT，得到 cost = K₁ < K₀

4. 替換約束為 At-Most-(K₁-1)，重新求解

5. 直到 UNSAT → 上一輪的 K 就是最小值

核心優化（Core-Guided）：
  Z3 不是每次都重新求解整個問題。
  它會分析 UNSAT core（導致不可滿足的最小子句子集），
  只放鬆 core 中的軟約束，避免無謂的搜索。
  這讓 N=300 個 flip 變數 + 5 筆 pattern 的問題在毫秒級解完。
```

**完整範例：從電路到 Z3 約束**

用一個小電路完整 trace 整個建模過程：

```
電路結構：
  PI: x, y
  gate_A = AND(x, y)
  gate_B = NOT(gate_A)
  gate_C = OR(x, gate_B)
  PO_0 = gate_B        ← 這是某個 primary output
  PO_1 = gate_C        ← 這是另一個 primary output

Trigger pattern: x=1, y=1

模擬 trojan：                    模擬 golden：
  gate_A = AND(1,1) = 1           （假設 golden 的 PO 輸出）
  gate_B = NOT(1)   = 0           golden_PO_0 = 1
  gate_C = OR(1,0)  = 1           golden_PO_1 = 1
  PO_0 = 0 ← 跟 golden 不同！❌
  PO_1 = 1 ← 跟 golden 一樣  ✓

問題：PO_0 輸出錯誤。該翻轉哪個 gate 來修正？
```

**第一步：建立 flip 決策變數**

```
candidate gates = {gate_A, gate_B, gate_C}（假設都不是 forbidden）

決策變數：
  flip_A ∈ {true, false}    — 是否翻轉 gate_A 的輸出
  flip_B ∈ {true, false}    — 是否翻轉 gate_B 的輸出
  flip_C ∈ {true, false}    — 是否翻轉 gate_C 的輸出

這三個變數是 Z3 要幫我們決定的。
```

**第二步：建立電路約束（硬約束）**

```
對 pattern (x=1, y=1)，建立一組電路節點變數：
  var_x, var_y, var_A, var_B, var_C

約束 1: PI 值固定
  var_x == true      （x=1）
  var_y == true      （y=1）

約束 2: gate 邏輯 + XOR flip
  var_A == (var_x AND var_y) XOR flip_A
  var_B == NOT(var_A)        XOR flip_B
  var_C == (var_x OR var_B)  XOR flip_C

  展開 XOR flip 的意思：
    如果 flip_A = false → var_A = AND(var_x, var_y)       （原始邏輯）
    如果 flip_A = true  → var_A = NOT(AND(var_x, var_y))  （翻轉輸出）

約束 3: PO 必須等於 golden（硬約束）
  var_B == true      （golden_PO_0 = 1）
  var_C == true      （golden_PO_1 = 1）
```

**第三步：建立優化目標（軟約束）**

```
minimize: ite(flip_A, 1, 0) + ite(flip_B, 1, 0) + ite(flip_C, 1, 0)

即：翻轉的 gate 越少越好
```

**第四步：Z3 求解過程**

```
Z3 需要找一組 (flip_A, flip_B, flip_C) 的賦值，使得：
  ① 所有電路約束滿足（硬約束）
  ② 翻轉數量最少（軟約束）

讓我們手動驗證幾種可能：

─────────────────────────────────────────────────
方案 1: flip_A=F, flip_B=F, flip_C=F（不翻轉任何 gate）
  var_x=1, var_y=1
  var_A = AND(1,1) XOR F = 1
  var_B = NOT(1)   XOR F = 0
  var_C = OR(1,0)  XOR F = 1
  檢查: var_B==true? 0≠1 ❌ → 違反硬約束！不可行。

─────────────────────────────────────────────────
方案 2: flip_A=F, flip_B=T, flip_C=F（只翻轉 gate_B）
  var_x=1, var_y=1
  var_A = AND(1,1) XOR F = 1
  var_B = NOT(1)   XOR T = 0 XOR 1 = 1    ← gate_B 被翻轉了！
  var_C = OR(1,1)  XOR F = 1              ← 注意 var_B=1 傳播到這裡
  檢查: var_B==true? 1==1 ✓
        var_C==true? 1==1 ✓
  cost = 0+1+0 = 1 → 可行！

─────────────────────────────────────────────────
方案 3: flip_A=T, flip_B=F, flip_C=F（只翻轉 gate_A）
  var_x=1, var_y=1
  var_A = AND(1,1) XOR T = 1 XOR 1 = 0    ← gate_A 被翻轉了！
  var_B = NOT(0)   XOR F = 1              ← gate_A 的翻轉傳播到 gate_B
  var_C = OR(1,1)  XOR F = 1
  檢查: var_B==true? 1==1 ✓
        var_C==true? 1==1 ✓
  cost = 1+0+0 = 1 → 可行！

─────────────────────────────────────────────────
兩個方案 cost 都是 1，Z3 會回傳其中一個（例如方案 2）。
最終結果：fix_nodes = {gate_B}
```

**關鍵觀察：翻轉一個 gate 會自動傳播**

```
方案 3 展示了重要特性：

  翻轉 gate_A → gate_A 從 1 變成 0
                → gate_B = NOT(0) = 1（原本是 0）← 被間接修正了！
                → gate_C = OR(1, 1) = 1          ← 也被影響

我們只翻轉了 gate_A，但 gate_B 的值也跟著改變了。
這就是為什麼 Z3 建模要用「連接的」變數 — 翻轉效果會自動沿著電路傳播。

Z3 不需要知道電路物理結構，它只需要解布林約束方程式。
翻轉的傳播效果自然由約束之間的邏輯依賴關係表達出來。
```

---

**多筆 pattern 的完整範例**

```
假設有 2 筆 trigger pattern：
  Pattern 0: x=1, y=1 → golden PO_0=1, PO_1=1
  Pattern 1: x=1, y=0 → golden PO_0=0, PO_1=1

決策變數（共享！）：
  flip_A, flip_B, flip_C

Pattern 0 的電路變數和約束：
  p0_x == true,  p0_y == true
  p0_A == (p0_x AND p0_y) XOR flip_A
  p0_B == NOT(p0_A)       XOR flip_B
  p0_C == (p0_x OR p0_B)  XOR flip_C
  p0_B == true     （golden PO_0 for pattern 0）
  p0_C == true     （golden PO_1 for pattern 0）

Pattern 1 的電路變數和約束：
  p1_x == true,  p1_y == false
  p1_A == (p1_x AND p1_y) XOR flip_A    ← 同一個 flip_A！
  p1_B == NOT(p1_A)       XOR flip_B    ← 同一個 flip_B！
  p1_C == (p1_x OR p1_B)  XOR flip_C    ← 同一個 flip_C！
  p1_B == false    （golden PO_0 for pattern 1）
  p1_C == true     （golden PO_1 for pattern 1）

注意：
  flip_A/B/C 被兩組約束共享。
  Z3 必須找到一組 flip 設定，同時讓 pattern 0 和 pattern 1 的 PO 都正確。

  如果 flip_B=true：
    Pattern 0: p0_B = NOT(1) XOR T = 0 XOR 1 = 1 == golden(1) ✓
    Pattern 1: p1_A = AND(1,0) XOR F = 0
               p1_B = NOT(0) XOR T = 1 XOR 1 = 0 == golden(0) ✓
    → 兩筆都滿足！cost = 1

Z3 變數總數 = 3 (flip) + 5×2 (每筆 pattern 5 個節點) = 13
約束總數 = 5×2 (電路約束) + 2×2 (PO 約束) = 14

如果有 5 筆 pattern，一個 1000 node 的電路：
  變數 = N_candidates + 1000×5 = 5000+
  約束 = 1000×5 + PO×5 = 5000+
  → 這就是為什麼每輪只加 5 筆 pattern（避免 Z3 變數爆炸）
```

---

**對應到程式碼的建模**

```
程式碼中的實際 Z3 操作：

1. 建立 flip 變數（solve_maxsat_batch, line 369-383）：
   for 每個 candidate_node:
     flip_vars.push_back(ctx.bool_const("flip_XXX"))
     if forced_mask[node]:    // 某些 gate 被強制翻轉
       solver.add(flip_var == true)

2. 建立最小化目標（line 385-391）：
   costs = [ite(flip_0, 1, 0), ite(flip_1, 1, 0), ...]
   solver.minimize(sum(costs))

3. 對每筆 pattern 建立電路（line 393-438）：
   for 每筆 sample pattern:
     vars = [p{i}_node0, p{i}_node1, ...]    // 該 pattern 的電路變數
     add_circuit_constraints_with_flips(...)   // 加入電路約束
     for 每個 PO:
       solver.add(vars[PO_idx] == golden_value)  // PO 必須等於 golden

4. add_circuit_constraints_with_flips 的內部（line 154-237）：
   for 每個 node:
     if CONST: vars[idx] == constant_value
     if PI:    vars[idx] == pi_input_value
     if GATE:
       gate_expr = build_gate_expr_z3(gate_type, input_vars)
       // 關鍵：XOR flip
       if node 有對應的 flip 變數:
         gate_expr = gate_expr XOR flip_var    ← 這就是翻轉機制！
       solver.add(vars[idx] == gate_expr)

5. 求解（line 441-461）：
   result = solver.check()
   if SAT:
     model = solver.get_model()
     for 每個 flip 變數:
       if model.eval(flip_i) == true:
         selected_nodes.add(candidate_nodes[i])   // 這個 gate 要翻轉
```

##### 5.C.4 迭代式求解流程

```
remaining = 所有 trigger patterns
sample_pool = {}

Round 1:
  1. 從 remaining 取 5 筆加入 sample_pool（累積）
  2. collect_candidate_nodes: 找出跟錯誤 PO 相關的 gate
  3. solve_maxsat_batch(sample_pool 的所有 pattern)
     → Z3 求解，得到 fix_nodes = {PO_3}
  4. 驗證：把 fix_nodes 的 gate 在電路中翻轉（invert_gate_type）
     模擬所有 remaining pattern，比對 golden
     → 240,312 筆修好 ✓
     → 212,078 筆仍錯 → 成為新的 remaining

Round 2:
  1. 再取 5 筆加入 sample_pool（現在共 10 筆）
  2. 重新 collect_candidate_nodes
  3. solve_maxsat_batch（10 筆 pattern）
     → Z3 求解，得到 fix_nodes = {PO_3, PO_7}
  4. 驗證：模擬所有 pattern
     → 395,824 筆修好 ✓
     → 56,566 筆仍錯

Round 3:
  1. 再取 5 筆（共 15 筆）
  2. solve_maxsat_batch
     → fix_nodes = {PO_3, PO_7, PO_9}
  3. 驗證：全部 452,390 筆修好 ✓
  → remaining 為空，停止

最終 fix_nodes = {PO_3, PO_7, PO_9}

停止條件：
  - remaining 為空（全部修好）
  - 連續兩輪 remaining 沒有減少（stuck）
  - candidate_nodes 為空
```

##### 5.C.5 Rule 編碼與 MUX 插入

找到 fix_nodes 後，對每個 node 插入修補邏輯（在 `apply_rule_patch` 中）：

```
對每個 fix_node（例如 PO_3）：

1. Rule Factoring — 將 trigger rules 編碼成電路
   假設有 3 條 rules：
     rule_1: gate_100=1 AND gate_200=0
     rule_2: gate_100=1 AND gate_300=1
     rule_3: gate_400=0

   編碼成：
     r1 = AND(gate_100, NOT(gate_200))
     r2 = AND(gate_100, gate_300)
     r3 = NOT(gate_400)
     trigger_cond = OR(r1, r2, r3)

   使用 ABC synthesis 優化 trigger_cond 的電路（壓縮 gate 數量）

2. MUX 插入 — 在 PO_3 處加入選擇器
   修補前：PO_3 = trojan_logic(...)
   修補後：PO_3 = MUX(trigger_cond, golden_value, trojan_logic)

   展開：
     PO_3 = (trigger_cond AND golden_value) OR (NOT trigger_cond AND trojan_logic)

   意思：
     trigger_cond = 0（正常）→ 輸出 trojan_logic（跟 golden 一樣）
     trigger_cond = 1（觸發）→ 輸出 golden_value（強制修正）

3. XOR Bypass 優化
   若 golden_value 恰好 = NOT(trojan_logic)（在所有 trigger pattern 上）
   → 可以簡化為：PO_3 = trojan_logic XOR trigger_cond
   → 比 MUX 少一個 gate，更省面積
```

**完整流程圖：**

```
trigger rules (from Mining)
    │
    ▼
① Forbidden Mask
   rule 用到的 gate + fanin cone → 標記禁止修改
    │
    ▼
② Candidate Gate 選取（每輪更新）
   錯誤 PO 的 fanin cone 聯集 - forbidden = candidates
    │
    ▼
③ MaxSAT 迭代求解
   每輪取 5 筆 pattern，Z3 建模：
   ┌─────────────────────────────────────┐
   │ 變數：flip_0, flip_1, ..., flip_N  │
   │ 硬約束：                             │
   │   ∀ pattern p, ∀ PO:               │
   │     simulate(trojan, p, flips)      │
   │     output_PO == golden_PO          │
   │ 軟約束（最小化）：                    │
   │   minimize Σ flip_i                 │
   └─────────────────────────────────────┘
   → 驗證全部 pattern → 沒修好的留到下一輪
    │
    ▼
④ fix_nodes = [PO_3, PO_7, PO_9]
    │
    ▼
⑤ 對每個 fix_node:
   將 rules 編碼成 trigger_cond 電路
   → ABC synthesis 優化
   → 插入 MUX: output = trigger ? golden : trojan
    │
    ▼
⑥ verify_patch_groundtruth
   模擬所有 trigger pattern 確認修補正確
```

### 6. CEC 驗證（Combinational Equivalence Check）

修補後的電路需要通過形式化驗證，確認與 golden 完全等價。

```
工具：ABC (Berkeley Logic Synthesis)
命令：abc -c "cec golden.bench patched.bench"

結果處理：
  - "Networks are equivalent" → PASS → 輸出修補電路，結束
  - 不等價 → 解析 counter-example
    - ABC 輸出格式：INPUT: pi1 = 1'h1, pi2 = 1'h0, ...
    - 將 PI name 對應到 PI position index
    - 產生新的 trigger pattern

CEC Retry Loop（最多 5 輪）：
  1. 將 counter-example 加入 trigger patterns
  2. 從頭重跑整個流程（模擬 → VN → Mining → Fix）
  3. 新的 trigger pattern 讓 mining 發現更完整的 trigger 條件
  4. 新的 fix 覆蓋更多 trigger input → 更可能通過 CEC

典型情況：
  - 大多數案例 cec_round=0（首輪即通過）
  - 複雜案例需要 1-4 輪 CEC retry
  - 極少數案例 5 輪仍無法通過（trigger 極度複雜）
```

---

## 關鍵設計決策

### 為什麼用 Decision Tree？

- 電路的 trigger 通常是少數幾個 gate 的布林組合（AND/OR）
- Decision tree 天然表達布林規則，每條 rule 就是 AND of literals
- Tree 的輸出直接可以編碼成電路邏輯（MUX selector）
- 相比 neural network，tree 的 rule 是可解釋的，可以直接用於電路修補

### 為什麼需要 Virtual Node？

- 有些 trigger 需要多個 gate 同時為特定值才會觸發
- 單層 decision tree split 只能看一個 feature
- VN 把 `A AND B` 壓成單一 feature，讓 tree 用一次 split 就能表達
- 減少 rule 數量 → 修補電路更小 → area overhead 更低

### 為什麼 Strict Mode 會產生很多 Rules？

- Strict mode 要求 **0 false positive**（不能把正常 pattern 誤判為 trigger）
- 隨機生成的 negative pattern 涵蓋面廣，tree 需要很精確地分類
- 為了不漏判，tree 需要很多細緻的 split → 很多 leaf → 很多 rules
- 每條 rule 都需要編碼成電路 → rule 越多，MUX selector 越大 → area 越大

### CEC Retry 的必要性

- 手上的 error patterns 只是所有可能 trigger input 的子集
- Mining 只在這些 pattern 上訓練，可能遺漏某些 trigger 條件
- CEC 用形式化方法檢驗所有可能 input
- Counter-example 回饋讓 mining 逐步完善 trigger 條件
- 實驗顯示約 20% 的案例需要至少 1 輪 CEC retry

---

## CLI 參數對演算法的影響

| 參數 | 預設值 | 影響 |
|------|--------|------|
| `--depth N` | 10 | Non-strict 階段的 tree 深度上限。越大越精確但越慢 |
| `--neg-ratio N` | 50 | 負樣本倍率。越大越不容易 false positive 但記憶體越多 |
| `--mine-rounds N` | 15 | Hard-negative mining 最大輪數。越多越精確但越慢 |
| `--mine-max N` | 5000 | 每輪最多加入的 hard negative 數。控制訓練集增長速度 |
| `--force-split` | off | 強制 tree 繼續分裂。增加 rule 數但降低 false positive |
| `--no-strict` | off | 停用 strict retry。加快速度但可能有 false positive |
| `--no-virtual` | off | 停用 VN 生成。加快速度但可能增加 rule 數 |
| `--include-pi` | on | 將 PI 也加入 feature candidate。增加表達能力 |
