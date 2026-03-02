# Profiling Notes

## Build & Test Commands (WSL)

```bash
# Build
cd /mnt/c/Users/jason/Desktop/hardwaretrojan_silence/src
touch main.cpp algorithm/miner.cpp && make -j$(nproc)

# Run AES trojan1 with timing
cd /mnt/c/Users/jason/Desktop/hardwaretrojan_silence
bin/main benchmarks/aes.bench \
  trojaned_bench/V0_singleTrigger_singlePayload/aes/aes_trojan1.bench \
  groundtruth/V0_singleTrigger_singlePayload/aes/aes_trojan1_error_patterns.json

# Run c7552 trojan1 with timing
bin/main benchmarks/c7552.bench \
  trojaned_bench/V0_singleTrigger_singlePayload/c7552/c7552_trojan1.bench \
  groundtruth/V0_singleTrigger_singlePayload/c7552/c7552_trojan1_error_patterns.json

# nsys profile (GPU detail)
nsys profile --stats=true --force-overwrite=true -o /tmp/prof \
  --trace=cuda,osrt --sample=cpu -- bin/main <args>
```

## WSL Invocation from Git Bash
```bash
wsl -e bash -c "cd /mnt/c/Users/jason/Desktop/hardwaretrojan_silence && <command> 2>&1"
```

## AES trojan1 Profile Results (2026-03-02)

Total: **48.8s** wall time

| Phase | Time (ms) | % | Type |
|---|---|---|---|
| parse+align | 1,109 | 2.3% | CPU (bench file I/O) |
| groundtruth_parse | 19,414 | **39.8%** | **CPU** (JSON parse) |
| pattern_build | 4,590 | **9.4%** | **CPU** (string→vector\<int\>) |
| gpu_init | 764 | 1.6% | GPU (GpuCircuit x2 + cudaMalloc) |
| gpu_trigger_sim | 5,367 | 11.0% | GPU (226K patterns simulate + accumulate) |
| gpu_notrigger_sim | 481 | 1.0% | GPU (random neg sim) |
| gpu_download+free | 3 | 0.0% | GPU→CPU |
| virtual_node | 5,876 | 12.0% | Mixed (1x run_mining) |
|   build_training_data | 3,497 | | GPU sim + CPU pack |
|   run_mining_loop | 2,373 | | CPU (decision tree) |
| final_mining | 4,115 | 8.4% | Mixed (1x run_mining) |
|   build_training_data | 2,556 | | GPU sim + CPU pack |
|   run_mining_loop | 1,558 | | CPU (decision tree) |
| kill+verify+write | 6,727 | 13.8% | Mixed (verify=GPU, write=CPU) |

### Key Bottlenecks
1. **groundtruth_parse: 19.4s (40%)** — #1 bottleneck, pure CPU JSON parsing
2. **kill+verify+write: 6.7s (14%)** — verify uses GPU sim, write is CPU I/O
3. **virtual_node: 5.9s (12%)** — phase1 mining (GPU sim + decision tree)
4. **gpu_trigger_sim: 5.4s (11%)** — GPU sim including CPU→GPU memcpy of packed PI
5. **pattern_build: 4.6s (9%)** — pure CPU string→int conversion
6. **final_mining: 4.1s (8%)** — GPU sim + decision tree

### CPU vs GPU Split
- **CPU-dominated: ~32s (65%)** — JSON parse, pattern convert, decision tree, file I/O
- **GPU: ~6.6s (14%)** — trigger/notrigger simulation only
- **Mixed: ~10s (21%)** — build_training_data (GPU sim + CPU pack)

## Files Modified for Timing
- `src/main.cpp` — `[TIMING]` cerr lines in main(), build_stats_from_groundtruth()
- `src/algorithm/miner.cpp` — `[TIMING]` cerr lines in run_mining()

## Optimization Opportunities
1. **groundtruth_parse (19.4s)**: Use simdjson or binary cache format
2. **pattern_build (4.6s)**: Store patterns as packed bits instead of vector\<int\>
3. **build_training_data (6s total)**: GPU sim is fast, but CPU→GPU packing of PI patterns is slow
4. **verify_patch_groundtruth**: Reuse existing GpuCircuit instead of rebuilding
5. **run_mining_loop**: Decision tree training is CPU-bound (kernel_find_split on GPU for large data)
