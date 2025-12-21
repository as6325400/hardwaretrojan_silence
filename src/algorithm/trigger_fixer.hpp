#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "../core/circuit.hpp"
#include "decision_tree.hpp"

struct FixResult {
  std::size_t rules_total = 0;
  std::size_t rules_applied = 0;
  std::size_t rules_skipped = 0;
  std::size_t po_candidates = 0;
  std::size_t po_fixed = 0;
};

bool apply_rule_fix(const circuit& golden,
                    circuit& trojan,
                    const std::vector<std::vector<int>>& trigger_patterns,
                    const std::vector<int>& feature_nodes,
                    const DecisionTreeModel& model,
                    FixResult* result,
                    std::string* error); // Patch POs to select golden outputs when decision-tree rules match.
