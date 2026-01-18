#include "decision_tree.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>

#ifdef _OPENMP
#include <omp.h>
#endif

namespace {

using PackedWord = PackedFeatureMatrix::word_t;
constexpr std::size_t kPackedWordBits = PackedFeatureMatrix::kWordBits;

struct Node {
  bool is_leaf = true;
  bool label = false;
  std::size_t feature = 0;
  std::unique_ptr<Node> left;
  std::unique_ptr<Node> right;
};

struct BuildStats {
  std::size_t max_depth_used = 0;
  std::size_t leaf_count = 0;
};

double gini_impurity(std::size_t pos, std::size_t neg) {
  const double total = static_cast<double>(pos + neg);
  if (total <= 0.0) {
    return 0.0;
  }
  const double p = static_cast<double>(pos) / total;
  const double q = static_cast<double>(neg) / total;
  return 1.0 - (p * p + q * q);
}

int packed_feature_value(const PackedFeatureMatrix& features,
                         std::size_t words_per_row,
                         std::size_t row,
                         std::size_t feature) {
  const std::size_t word_idx = feature / kPackedWordBits;
  const std::size_t bit_idx = feature % kPackedWordBits;
  const PackedWord* row_ptr = features.data.data() + row * words_per_row;
  return static_cast<int>((row_ptr[word_idx] >> bit_idx) & PackedWord(1));
}

std::unique_ptr<Node> make_leaf(bool label, std::size_t depth, BuildStats& stats) {
  auto node = std::make_unique<Node>();
  node->is_leaf = true;
  node->label = label;
  stats.max_depth_used = std::max(stats.max_depth_used, depth);
  stats.leaf_count += 1;
  return node;
}

std::unique_ptr<Node> build_node(const PackedFeatureMatrix& features,
                                 const std::vector<int>& labels,
                                 const std::vector<std::size_t>& samples,
                                 const std::vector<std::size_t>& feature_indices,
                                 std::size_t depth,
                                 const DecisionTreeOptions& options,
                                 BuildStats& stats) {
  if (samples.empty()) {
    return make_leaf(false, depth, stats);
  }

  std::size_t pos = 0;
  std::size_t neg = 0;
  for (std::size_t idx : samples) {
    if (labels[idx] == 1) {
      pos += 1;
    } else {
      neg += 1;
    }
  }

  if (pos == 0) {
    return make_leaf(false, depth, stats);
  }
  if (neg == 0) {
    return make_leaf(true, depth, stats);
  }
  if (depth >= options.max_depth || feature_indices.empty()) {
    return make_leaf(true, depth, stats);
  }

  const std::size_t words_per_row = features.words_per_row();
  const double parent_impurity = gini_impurity(pos, neg);
  double best_gain = -std::numeric_limits<double>::infinity();
  std::size_t best_feature = 0;
  bool found = false;

#ifdef _OPENMP
  double global_best_gain = -std::numeric_limits<double>::infinity();
  std::size_t global_best_feature = 0;
  bool global_found = false;

  #pragma omp parallel
  {
    double local_best_gain = -std::numeric_limits<double>::infinity();
    std::size_t local_best_feature = 0;
    bool local_found = false;

    #pragma omp for schedule(static)
    for (std::size_t i = 0; i < feature_indices.size(); ++i) {
      const std::size_t f = feature_indices[i];
      std::size_t pos0 = 0;
      std::size_t neg0 = 0;
      std::size_t pos1 = 0;
      std::size_t neg1 = 0;
      for (std::size_t idx : samples) {
        const int value = packed_feature_value(features, words_per_row, idx, f);
        if (value == 1) {
          if (labels[idx] == 1) {
            pos1 += 1;
          } else {
            neg1 += 1;
          }
        } else {
          if (labels[idx] == 1) {
            pos0 += 1;
          } else {
            neg0 += 1;
          }
        }
      }

      const std::size_t total0 = pos0 + neg0;
      const std::size_t total1 = pos1 + neg1;
      if (total0 == 0 || total1 == 0) {
        continue;
      }

      const double weighted_impurity =
          (static_cast<double>(total0) / static_cast<double>(samples.size())) *
              gini_impurity(pos0, neg0) +
          (static_cast<double>(total1) /
           static_cast<double>(samples.size())) *
              gini_impurity(pos1, neg1);
      const double gain = parent_impurity - weighted_impurity;

      if (!local_found || gain > local_best_gain) {
        local_best_gain = gain;
        local_best_feature = f;
        local_found = true;
      }
    }

    #pragma omp critical
    {
      if (local_found && (!global_found || local_best_gain > global_best_gain)) {
        global_best_gain = local_best_gain;
        global_best_feature = local_best_feature;
        global_found = true;
      }
    }
  }

  if (global_found) {
    best_gain = global_best_gain;
    best_feature = global_best_feature;
    found = true;
  }
#else
  for (std::size_t f : feature_indices) {
    std::size_t pos0 = 0;
    std::size_t neg0 = 0;
    std::size_t pos1 = 0;
    std::size_t neg1 = 0;
    for (std::size_t idx : samples) {
      const int value = packed_feature_value(features, words_per_row, idx, f);
      if (value == 1) {
        if (labels[idx] == 1) {
          pos1 += 1;
        } else {
          neg1 += 1;
        }
      } else {
        if (labels[idx] == 1) {
          pos0 += 1;
        } else {
          neg0 += 1;
        }
      }
    }

    const std::size_t total0 = pos0 + neg0;
    const std::size_t total1 = pos1 + neg1;
    if (total0 == 0 || total1 == 0) {
      continue;
    }

    const double weighted_impurity =
        (static_cast<double>(total0) / static_cast<double>(samples.size())) *
            gini_impurity(pos0, neg0) +
        (static_cast<double>(total1) / static_cast<double>(samples.size())) *
            gini_impurity(pos1, neg1);
    const double gain = parent_impurity - weighted_impurity;

    if (!found || gain > best_gain) {
      best_gain = gain;
      best_feature = f;
      found = true;
    }
  }
#endif

  if (!found || (!options.force_split && best_gain <= 0.0)) {
    return make_leaf(true, depth, stats);
  }

  std::vector<std::size_t> left_samples;
  std::vector<std::size_t> right_samples;
  left_samples.reserve(samples.size());
  right_samples.reserve(samples.size());
  for (std::size_t idx : samples) {
    const int value = packed_feature_value(features, words_per_row, idx, best_feature);
    if (value == 1) {
      right_samples.push_back(idx);
    } else {
      left_samples.push_back(idx);
    }
  }

  std::vector<std::size_t> next_features;
  next_features.reserve(feature_indices.size() - 1);
  for (std::size_t f : feature_indices) {
    if (f != best_feature) {
      next_features.push_back(f);
    }
  }

  auto node = std::make_unique<Node>();
  node->is_leaf = false;
  node->feature = best_feature;
  node->left = build_node(features, labels, left_samples, next_features, depth + 1, options, stats);
  node->right = build_node(features, labels, right_samples, next_features, depth + 1, options, stats);
  stats.max_depth_used = std::max(stats.max_depth_used, depth);
  return node;
}

void collect_rules(const Node& node,
                   std::vector<std::pair<std::size_t, int>>& path,
                   std::vector<DecisionTreeRule>& rules) {
  if (node.is_leaf) {
    if (node.label) {
      rules.push_back(DecisionTreeRule{path});
    }
    return;
  }

  if (node.left) {
    path.push_back({node.feature, 0});
    collect_rules(*node.left, path, rules);
    path.pop_back();
  }
  if (node.right) {
    path.push_back({node.feature, 1});
    collect_rules(*node.right, path, rules);
    path.pop_back();
  }
}

}  // namespace

DecisionTreeModel build_decision_tree(const PackedFeatureMatrix& features,
                                      const std::vector<int>& labels,
                                      const DecisionTreeOptions& options,
                                      std::string* error) {
  DecisionTreeModel model;
  if (error) {
    error->clear();
  }
  if (features.row_count == 0 || labels.empty()) {
    if (error) {
      *error = "empty training data";
    }
    return model;
  }
  if (features.row_count != labels.size()) {
    if (error) {
      *error = "feature/label size mismatch";
    }
    return model;
  }

  const std::size_t feature_count = features.feature_count;
  if (feature_count == 0) {
    if (error) {
      *error = "empty feature set";
    }
    return model;
  }
  const std::size_t words_per_row = features.words_per_row();
  if (features.data.size() != features.row_count * words_per_row) {
    if (error) {
      *error = "packed feature size mismatch";
    }
    return model;
  }

  std::vector<std::size_t> samples(features.row_count);
  for (std::size_t i = 0; i < samples.size(); ++i) {
    samples[i] = i;
  }

  std::vector<std::size_t> feature_indices(feature_count);
  for (std::size_t i = 0; i < feature_count; ++i) {
    feature_indices[i] = i;
  }

  BuildStats stats;
  auto root = build_node(features, labels, samples, feature_indices, 0, options, stats);
  model.max_depth_used = stats.max_depth_used;
  model.leaf_count = stats.leaf_count;

  std::vector<std::pair<std::size_t, int>> path;
  collect_rules(*root, path, model.rules);

  if (model.rules.empty()) {
    if (error) {
      *error = "no positive rules found";
    }
  }
  return model;
}

bool eval_rules(const std::vector<DecisionTreeRule>& rules,
                const std::vector<int>& features) {
  for (const auto& rule : rules) {
    bool match = true;
    for (const auto& term : rule.terms) {
      const std::size_t idx = term.first;
      const int expected = term.second;
      if (idx >= features.size()) {
        match = false;
        break;
      }
      const int value = features[idx] ? 1 : 0;
      if (value != expected) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}

bool eval_rules_packed(const std::vector<DecisionTreeRule>& rules,
                       const PackedFeatureMatrix::word_t* features,
                       std::size_t feature_count) {
  if (!features) {
    return false;
  }
  for (const auto& rule : rules) {
    bool match = true;
    for (const auto& term : rule.terms) {
      const std::size_t idx = term.first;
      const int expected = term.second;
      if (idx >= feature_count) {
        match = false;
        break;
      }
      const std::size_t word_idx = idx / kPackedWordBits;
      const std::size_t bit_idx = idx % kPackedWordBits;
      const int value =
          static_cast<int>((features[word_idx] >> bit_idx) & PackedWord(1));
      if (value != expected) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}
