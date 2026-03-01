# CUDA GPU 加速計劃

## Context

模擬和決策樹是整個 mining pipeline 最耗時的兩個部分（分別佔 ~70% 和 ~20%）。目前 CPU 每次只能處理 64 個 pattern（一個 word_t），GPU 可以同時處理數萬到數百萬個 pattern。

**環境**: CUDA 13.1, RTX 5080 (sm_120, 16GB VRAM)

## 預期 Speedup

| 模組 | CPU 現況 | GPU 策略 | 預期加速 |
|------|---------|---------|---------|
| 電路模擬 | 每次 64 pattern, 循環數千次 | 一次 launch 處理 16K+ word blocks (1M+ patterns) | **20-50x** |
| 決策樹 split | OpenMP 平行 features | 每個 thread 一個 feature, `__popcll` | **5-20x** |
| 亂數產生 | CPU mt19937_64 | cuRAND Philox on GPU | **10-30x** |
| PO 比較 | CPU 逐 word block | GPU kernel 全部平行 | **20-50x** |
| **整體 pipeline** | baseline | GPU 加速 | **10-30x** |

### 記憶體限制與自適應 batch

| 電路 | Nodes | 16K blocks 記憶體 |
|------|-------|-----------------|
| c880 | ~880 | 110 MB |
| c7552 | ~7500 | 937 MB |
| AES | ~506K | 需分批: ~2000 blocks/batch |

設計會自動計算 `max_word_blocks = VRAM * 0.8 / (bytes_per_block)` 來適應不同大小的電路。

## 架構設計

### 核心思路
- 每個 CUDA thread 處理一個 word block (64 patterns)
- 所有 thread 對同一個 gate 執行相同操作 → **零 warp divergence**
- Memory layout: `values[node_idx * num_word_blocks + word_id]` → **coalesced access**
- 按 topological level 分組 gate，每個 level 一次 kernel launch → 減少 launch overhead
- Pattern 間完全獨立 → **不需要 inter-thread 同步**

### GPU Pipeline（取代 miner while loop）
```
1. cuRAND 在 GPU 上產生所有 PI bits
2. GPU simulate golden circuit (所有 word blocks 平行)
3. GPU simulate trojan circuit (所有 word blocks 平行)
4. GPU compare POs → diff_mask[num_word_blocks]
5. GPU gather feature node bits
6. GPU compute virtual feature bits
7. Download diff_mask + feature_bits 到 CPU (~幾 MB)
8. CPU 做 feature row packing 和 training data 收集
```

## 新增檔案

### 1. `src/core/gpu_circuit.cuh` — GPU 電路類別

```cpp
class GpuCircuit {
public:
    using word_t = unsigned long long;
    GpuCircuit(const circuit& base, std::size_t max_word_blocks);
    ~GpuCircuit();
    void simulate(const word_t* d_pi_bits, std::size_t num_word_blocks);
    word_t* d_values();
    const word_t* d_values() const;
    const int* d_po_indices() const;
    std::size_t num_nodes(), num_pis(), num_pos(), max_word_blocks() const;
private:
    // Device memory: values, pi_map, po_map, const nodes, gate CSR
    // Host: level boundaries for launch loop
};

// Standalone functions
void gpu_generate_random_pi(word_t* d_pi, size_t num_pis, size_t num_wb, ull seed);
void gpu_compare_po(golden, trojan, d_diff_mask, num_wb, pmask);
void gpu_gather_nodes(d_values, d_node_indices, num_gather, num_wb, d_out);
void gpu_compute_virtual_features(d_values, vn CSR data, num_vn, num_wb, pmask, d_out);
size_t gpu_compute_max_word_blocks(golden_nodes, trojan_nodes, num_pis, num_features);
```

### 2. `src/core/gpu_circuit.cu` — CUDA kernels

**Kernels:**
- `kernel_zero_values` — memset values to 0
- `kernel_set_pi` — 2D grid (word_block × pi_idx), set PI values from pi_bits
- `kernel_set_const` — 2D grid (word_block × const_idx), set constant nodes
- `kernel_eval_level` — 2D grid (word_block × gates_in_level), evaluate all gates at same topological level
- `kernel_compare_po` — 1D grid, XOR all POs, produce diff_mask
- `kernel_gather_nodes` — 2D grid, collect specific node values
- `kernel_gen_random_pi` — 1D grid, cuRAND Philox 產生 64-bit random words
- `kernel_virtual_features` — 2D grid, compute AND/OR virtual nodes

**Gate CSR format:**
```cpp
struct GpuGateBatch {
    int dest_node;
    int gtype;        // GType enum as int
    int input_offset; // into flat_inputs array
    int num_inputs;
};
```

**Constructor:** flatten circuit → CSR, compute topological levels, group gates by level, upload all to GPU.

**simulate():** zero → set PI → set CONST → for each level: launch `kernel_eval_level`.

### 3. `src/algorithm/gpu_tree.cuh` — GPU split finding header

```cpp
struct GpuSplitResult {
    double best_gain;
    std::size_t best_feature_idx;  // index into feature_indices
    bool found;
};

GpuSplitResult gpu_find_best_split(
    const word_t* col_data,           // [n_features * packed_words]
    const word_t* sample_mask,        // [packed_words]
    const word_t* sample_pos_mask,    // [packed_words]
    std::size_t packed_words,
    std::size_t n_features,
    std::size_t total_samples,
    std::size_t pos_count,
    std::size_t neg_count,
    double parent_impurity,
    const std::size_t* feature_indices);
```

### 4. `src/algorithm/gpu_tree.cu` — GPU split kernel

```cuda
__global__ void kernel_find_split(
    col_data, sample_mask, sample_pos_mask,
    packed_words, n_features, total_samples, pos, neg,
    parent_impurity, gains[n_features])
{
    int fi = blockIdx.x * blockDim.x + threadIdx.x;
    // For each feature: AND + __popcll → total1, pos1
    // Compute Gini gain
    gains[fi] = gain;
}
```

Host side: launch kernel → download gains → find max (or GPU reduction for large n_features).

## 修改檔案

### 5. `src/algorithm/miner.cpp`

在 `build_training_data()` 和 `eval_and_mine()` 中：
- `#ifdef USE_CUDA`: 用 GPU pipeline 取代 while loop
- 一次產生所有 PI bits → simulate → compare → gather → download
- 在 CPU 上做 filtering 和 feature row packing
- `neg_trace` 在 GPU mode 下跳過（user 用 `--mine-max 0` 不會用到）

### 6. `src/algorithm/decision_tree.cpp`

在 `build_node()` 的 find_best_split 區域：
- `#ifdef USE_CUDA`: 上傳 col_data/sample_mask/sample_pos_mask 到 GPU
- 呼叫 `gpu_find_best_split()`
- 設定 threshold: features > 64 才用 GPU（避免小問題的 launch overhead）

### 7. `src/main.cpp`

`build_stats_from_groundtruth()`:
- `#ifdef USE_CUDA`: GPU 模擬 + 比較 + 統計
- 用 GPU kernel 計算 gate ones count

### 8. `src/Makefile`

```makefile
# CUDA support (auto-detect)
NVCC := $(shell which nvcc 2>/dev/null)
ifneq ($(NVCC),)
  USE_CUDA = 1
  CUDA_HOME ?= $(shell dirname $(shell dirname $(NVCC)))
  NVCCFLAGS = -std=c++17 -O2 --gpu-architecture=native \
              -Xcompiler "-fopenmp" -I../extern
  CXXFLAGS += -DUSE_CUDA -I$(CUDA_HOME)/include
  CUDA_SRCS := $(wildcard core/*.cu algorithm/*.cu)
  CUDA_OBJS := $(CUDA_SRCS:%.cu=$(BUILD_DIR)/%.o)
  LIB_OBJS += $(CUDA_OBJS)
  LDFLAGS += -lcudart -L$(CUDA_HOME)/lib64
endif

$(BUILD_DIR)/%.o: %.cu
	mkdir -p $(dir $@)
	$(NVCC) $(NVCCFLAGS) -c -o $@ $<
```

## 驗證策略

1. `make clean && make` — 確認編譯通過
2. 用 c880 benchmark 測試正確性：
   ```
   ./bin/main ./benchmarks/c880.bench ./trojaned_bench/V0_.../c880_trojan0.bench \
     ./groundtruth/.../c880_trojan0_error_patterns.json \
     --depth 10 --mine-max 0 --output /tmp/gpu_test.bench
   ```
3. 比較 GPU 和 CPU 輸出是否一致
4. 用 `time` 測量 speedup

## 關鍵風險

1. **kernel launch overhead**: 大電路 (AES) 若 level 太多 (>1000)，每個 level 一次 launch 可能有 overhead → 用 CUDA graph 或合併小 level
2. **記憶體**: 大電路需要分批處理 → 已設計自適應 batch size
3. **cuRAND 初始化**: Philox per-thread init 較快，但首次 launch 仍有 overhead → seed 遞增避免重複
