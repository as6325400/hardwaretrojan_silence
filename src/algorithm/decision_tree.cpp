#include "decision_tree.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>

namespace {

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

std::unique_ptr<Node> make_leaf(bool label, std::size_t depth, BuildStats& stats) {
  auto node = std::make_unique<Node>();
  node->is_leaf = true;
  node->label = label;
  stats.max_depth_used = std::max(stats.max_depth_used, depth);
  stats.leaf_count += 1;
  return node;
}

std::unique_ptr<Node> build_node(const std::vector<std::vector<int>>& features,
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

  const double parent_impurity = gini_impurity(pos, neg);
  double best_gain = -std::numeric_limits<double>::infinity();
  std::size_t best_feature = 0;
  bool found = false;

  for (std::size_t f : feature_indices) {
    std::size_t pos0 = 0;
    std::size_t neg0 = 0;
    std::size_t pos1 = 0;
    std::size_t neg1 = 0;
    for (std::size_t idx : samples) {
      const int value = features[idx][f];
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

  if (!found || (!options.force_split && best_gain <= 0.0)) {
    return make_leaf(true, depth, stats);
  }

  std::vector<std::size_t> left_samples;
  std::vector<std::size_t> right_samples;
  left_samples.reserve(samples.size());
  right_samples.reserve(samples.size());
  for (std::size_t idx : samples) {
    const int value = features[idx][best_feature];
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

DecisionTreeModel build_decision_tree(const std::vector<std::vector<int>>& features,
                                      const std::vector<int>& labels,
                                      const DecisionTreeOptions& options,
                                      std::string* error) {
  DecisionTreeModel model;
  if (error) {
    error->clear();
  }
  if (features.empty() || labels.empty()) {
    if (error) {
      *error = "empty training data";
    }
    return model;
  }
  if (features.size() != labels.size()) {
    if (error) {
      *error = "feature/label size mismatch";
    }
    return model;
  }

  const std::size_t feature_count = features.front().size();
  for (const auto& row : features) {
    if (row.size() != feature_count) {
      if (error) {
        *error = "inconsistent feature dimensions";
      }
      return model;
    }
  }

  std::vector<std::size_t> samples(features.size());
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
