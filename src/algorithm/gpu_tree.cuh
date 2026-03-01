#pragma once

#include <cstddef>

using GpuWord = unsigned long long;

struct GpuSplitResult {
  double      best_gain;
  std::size_t best_fi;   // index into [0, n_features) — NOT a feature index
  bool        found;
};

// Find the best binary split over n_features features using GPU __popcll.
// All input arrays are HOST pointers; the function handles upload/download.
// col_data layout : [fi * packed_words + w]  (feature-major, same as CPU build)
// sample_mask     : [w]  bitmask of samples in this node
// sample_pos_mask : [w]  bitmask of positive samples
// Returns best_fi = fi of max-gain feature (maps back via feature_indices[fi]).
GpuSplitResult gpu_find_best_split(
    const GpuWord* col_data,          // host  [n_features * packed_words]
    const GpuWord* sample_mask,       // host  [packed_words]
    const GpuWord* sample_pos_mask,   // host  [packed_words]
    std::size_t    packed_words,
    std::size_t    n_features,
    std::size_t    total_samples,
    std::size_t    pos_count,
    std::size_t    neg_count,
    double         parent_impurity);
