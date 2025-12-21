#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

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

DecisionTreeModel build_decision_tree(const std::vector<std::vector<int>>& features,
                                      const std::vector<int>& labels,
                                      const DecisionTreeOptions& options,
                                      std::string* error); // Build depth-limited decision tree (optional forced split) and return OR-of-AND rules.

bool eval_rules(const std::vector<DecisionTreeRule>& rules,
                const std::vector<int>& features); // Evaluate OR-of-AND rules on one feature vector.
