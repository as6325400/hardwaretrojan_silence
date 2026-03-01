#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

// Column-major packed feature matrix.
// Layout: data[feature * packed_rows() + word] — bit b of that word
//         is the value of `feature` for sample (word * 64 + b).
struct PackedFeatureMatrix {
  using word_t = unsigned long long;
  static constexpr std::size_t kWordBits = sizeof(word_t) * 8U;

  std::vector<word_t> data;
  std::size_t feature_count = 0;
  std::size_t row_count = 0;       // number of samples
  std::size_t capacity_rows = 0;   // pre-allocated sample capacity

  // Number of 64-bit words per column (based on capacity, not row_count,
  // so that column stride stays fixed during incremental construction).
  std::size_t packed_rows() const {
    const std::size_t n = capacity_rows > 0 ? capacity_rows : row_count;
    return n == 0 ? 0 : (n + kWordBits - 1) / kWordBits;
  }

  // Pointer to the column data for a given feature.
  const word_t* col_ptr(std::size_t feature) const {
    return data.data() + feature * packed_rows();
  }
  word_t* col_ptr_mut(std::size_t feature) {
    return data.data() + feature * packed_rows();
  }

  // Look up a single feature value for a sample.
  int feature_value(std::size_t row, std::size_t feature) const {
    const std::size_t pr = packed_rows();
    const std::size_t w = row / kWordBits;
    const std::size_t b = row % kWordBits;
    return static_cast<int>((data[feature * pr + w] >> b) & word_t(1));
  }

  // Pre-allocate for `num_features` features × `num_samples` samples.
  void allocate(std::size_t num_features, std::size_t num_samples) {
    feature_count = num_features;
    capacity_rows = num_samples;
    row_count = 0;
    const std::size_t pr = packed_rows();
    data.assign(num_features * pr, word_t(0));
  }

  // Grow capacity so that at least `n` rows fit.  Re-layouts columns.
  void ensure_row_capacity(std::size_t n) {
    if (n <= capacity_rows) return;
    const std::size_t old_pr = packed_rows();
    capacity_rows = n;
    const std::size_t new_pr = packed_rows();
    if (new_pr == old_pr) return;
    std::vector<word_t> new_data(feature_count * new_pr, word_t(0));
    const std::size_t copy_words = old_pr < new_pr ? old_pr : new_pr;
    for (std::size_t f = 0; f < feature_count; ++f) {
      for (std::size_t w = 0; w < copy_words; ++w) {
        new_data[f * new_pr + w] = data[f * old_pr + w];
      }
    }
    data = std::move(new_data);
  }
};

struct DecisionTreeRule {
  std::vector<std::pair<std::size_t, int>> terms;
};

struct DecisionTreeModel {
  std::vector<DecisionTreeRule> rules;
  std::size_t max_depth_used = 0;
  std::size_t leaf_count = 0;
};

struct DecisionTreeOptions {
  std::size_t max_depth = 4;
  bool force_split = false;
};

DecisionTreeModel build_decision_tree(const PackedFeatureMatrix& features,
                                      const std::vector<int>& labels,
                                      const DecisionTreeOptions& options,
                                      std::string* error);

bool eval_rules(const std::vector<DecisionTreeRule>& rules,
                const std::vector<int>& features);

bool eval_rules_packed(const std::vector<DecisionTreeRule>& rules,
                       const PackedFeatureMatrix::word_t* features,
                       std::size_t feature_count);
