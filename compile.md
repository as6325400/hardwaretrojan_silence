# 專案實作規格：Partitioned Levelized Compiled-code Simulation for GPU

## 1. 專案目標
實作一個 **C++ 程式碼生成器（Code Generator）**。該工具需讀取組合電路網表（如 ISCAS85 `.bench` 或簡易的 Verilog/AIG），將其轉換為**多個高度最佳化的 CUDA Kernels**，以進行 GPU 加速的 Bit-parallel 邏輯/故障模擬（Logic / Fault Simulation）。

為了解決百萬級別邏輯閘直接編譯會導致 NVCC OOM（記憶體耗盡）或嚴重 Register Spilling 的問題，本專案必須採用 **Partitioning（分塊）** 策略。

## 2. 核心架構與實作步驟

請使用 **C++ (建議 C++17 或以上)** 依照以下流程實作生成器：

### Step 1: 解析與 DAG 建構 (Parsing & DAG Construction)
* 讀取輸入的 Netlist 檔案。
* 使用 `std::vector` 與 `std::unordered_map` 等現代 C++ 資料結構建立有向無環圖（Directed Acyclic Graph, DAG）。
* 為每個節點（邏輯閘）與邊（訊號線）分配唯一的整數 ID（從 0 到 N-1）。

### Step 2: 拓樸排序 (Topological Sort / Levelization)
* 從 Primary Inputs (PI) 開始走訪 DAG（可使用 Kahn's algorithm 或 DFS）。
* 確保在陣列或列表中，任何節點的前驅節點（Fan-ins）都排在該節點之前。

### Step 3: 分塊演算法 (Chunking / Partitioning)
* 將排序後的節點序列，每 K 個節點切分為一個 Chunk（例如 K = 5000 到 10000）。
* **Liveness Analysis（變數存活分析）**：這是效能關鍵。
  * 對於 Chunk 內的每個邏輯閘，檢查其 Fan-out。
  * 如果該邏輯閘的所有 Fan-out **都在同一個 Chunk 內**，則該節點的輸出為 **Local Variable**，只需分配為 CUDA Kernel 內的區域變數（Register）。
  * 如果該邏輯閘的 Fan-out **跨越到後續的 Chunk**，或者該節點是 Primary Output (PO)，則為 **Global Variable**，必須寫回 GPU 的 Global Memory (`d_wire_states`)。
  * Chunk 需要依賴先前 Chunk 的訊號時，必須從 `d_wire_states` 讀取。

### Step 4: CUDA 程式碼生成 (CUDA Code Generation)
利用 C++ 的檔案串流 (`std::ofstream`)，根據分塊結果自動產生對應的 `.cu` 檔案。

**4.1 記憶體佈局要求 (Memory Layout for Coalesced Access)**
* 為了最大化 Memory Bandwidth，全域狀態陣列 `d_wire_states` 必須採用以下 Indexing 方式：
  `wire_states[wire_id * num_patterns + tid]`
* 變數型態：使用 `uint64_t` 來實作 64-bit Bit-parallelism。

**4.2 單一 Chunk 的 Kernel 模板範例**
```cpp
// 自動生成的 chunk_xxx.cu
__global__ void simulate_chunk_xxx(uint64_t* wire_states, int num_patterns) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= num_patterns) return;

    // 1. Load dependencies from Global Memory (僅讀取跨 Chunk 的訊號)
    uint64_t w_12 = wire_states[12 * num_patterns + tid];
    uint64_t w_45 = wire_states[45 * num_patterns + tid];

    // 2. Logic Computation (純暫存器 Bitwise 運算，無分支)
    uint64_t w_100 = w_12 & w_45;      // AND gate (Local, 不寫回)
    uint64_t w_101 = ~(w_45 | w_100);  // NOR gate (Global, 需寫回)

    // 3. Store cross-chunk signals to Global Memory
    wire_states[101 * num_patterns + tid] = w_101;
}
```

# Step 5: Host Code 與 Makefile 生成
Host Code (main.cu)：

利用 std::ofstream 自動生成主程式。

配置 d_wire_states 的記憶體 (cudaMalloc)。

設定 Grid 與 Block dimensions。

按照拓樸順序，依序呼叫所有生成的 Chunk Kernels。

Makefile：

必須支援 -j 平行編譯多個生成的 .cu 檔案，以縮短編譯時間。

加入適當的 NVCC 最佳化參數（例如 -O3 -Xptxas -O3）。

3. 測試與驗證要求
實作完成後，請提供一個 C++ 的 Dummy Netlist 產生器函式（或獨立小程式）：

自動生成一個包含數萬個邏輯閘的測試網表（如長鏈狀或樹狀組合電路）。

執行 Code Generator 產生完整的 CUDA 專案目錄（包含所有 .cu 檔與 Makefile）。

確保生成的 CUDA 專案能夠成功編譯 (make -j) 並執行驗證。


