# Column-Major Refactor Plan

## Problem
Training data matrix is stored row-major (`PackedFeatureMatrix`), but both simulation output and decision tree split finding need column-major. This causes two redundant O(F×N) transposes per training phase.

## Files to Change

### 1. `src/algorithm/decision_tree.hpp`
- Change `PackedFeatureMatrix` to column-major layout:
  - `data[feature * packed_rows + word]` instead of `data[row * words_per_row + word]`
  - Add `packed_rows()` method: `(row_count + 63) / 64`
  - Keep `words_per_row()` for backward compat or remove
  - Add `col_ptr(feature)` accessor
  - Change `row_ptr()` → `feature_value(row, feature)` for individual lookups

### 2. `src/algorithm/decision_tree.cpp`
- `packed_feature_value()` (line 58-66): Change indexing to column-major
- `build_node()` (line 77-260):
  - Remove the transpose block (lines 136-153) — data is already column-major
  - `col_data` becomes a direct pointer into `features.data`
  - Sample splitting (line 254-256): use new `feature_value()` accessor
- GPU split path (line 155-165): pass column pointers directly

### 3. `src/algorithm/miner.cpp`
- Remove `fill_feature_row_from_bits()`, `append_feature_rows_from_bits_range()`, `append_feature_rows_from_bits_indices()` — no longer needed
- Remove `pack_feature_row()` — no longer needed
- Remove `FeatureIndexMap` — no longer needed
- **New function**: `append_columns_from_word_block(feature_bits, wb_index, matrix)`
  - Just copies `feature_bits[f]` into `matrix.data[f * packed_rows + wb_index]`
  - O(F) per word block instead of O(F×64)
- Update `build_training_data()`:
  - Pre-allocate column-major matrix for total_samples
  - GPU pos sim: directly write feature columns
  - GPU neg sim: directly write feature columns
  - CPU fallback: same column writes
- Update `eval_and_mine()`: adapt rule checking to column-major lookups
- Remove `words_per_row` usage, replace with `packed_rows`

### 4. Label storage
- `labels` vector stays as-is (one int per sample)
- For column-major, need to track which word-block slots are used
  - Pre-allocate `labels` to total capacity
  - Track `pos_count`, `neg_count` as before

## Key Invariant
- `data.size() == feature_count * packed_rows()`
- `data[f * packed_rows + w]` bit `b` = feature `f` value for sample `w*64+b`
- Must pre-allocate to max capacity since all columns grow together

## Performance Impact
- Matrix assembly: O(F×N) → O(F×N/64) — 64x faster
- Tree transpose: O(F×N) per node → O(0) — eliminated
- Split finding: unchanged O(F×N/64)
- Individual lookups: unchanged O(1)
