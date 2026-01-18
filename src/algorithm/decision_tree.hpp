#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

struct PackedFeatureMatrix {
  using word_t = unsigned long long;
  static constexpr std::size_t kWordBits = sizeof(word_t) * 8U;

  std::vector<word_t> data;
  std::size_t feature_count = 0;
  std::size_t row_count = 0;

  std::size_t words_per_row() const {
    return feature_count == 0 ? 0 : (feature_count + kWordBits - 1) / kWordBits;
  }

  const word_t* row_ptr(std::size_t row) const {
    return data.data() + row * words_per_row();
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
                                      std::string* error); // Build depth-limited decision tree (optional forced split) and return OR-of-AND rules.

bool eval_rules(const std::vector<DecisionTreeRule>& rules,
                const std::vector<int>& features); // Evaluate OR-of-AND rules on one feature vector.

bool eval_rules_packed(const std::vector<DecisionTreeRule>& rules,
                       const PackedFeatureMatrix::word_t* features,
                       std::size_t feature_count); // Evaluate OR-of-AND rules on packed feature vector.
