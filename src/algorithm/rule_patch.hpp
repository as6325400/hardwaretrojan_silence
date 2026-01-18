#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "../core/circuit.hpp"
#include "decision_tree.hpp"

void simplify_rules(std::vector<DecisionTreeRule>* rules);

std::string pi_values_to_bits(const std::vector<int>& pi_values);

std::string derive_patched_path(const std::string& trojan_path);

bool apply_rule_inversion(circuit& net,
                          const std::vector<int>& feature_nodes,
                          const DecisionTreeModel& model,
                          int fix_idx,
                          std::size_t base_nodes,
                          std::string* error);

bool evaluate_fix_candidate(const circuit& base,
                            const std::vector<int>& feature_nodes,
                            const DecisionTreeModel& model,
                            int fix_idx,
                            std::size_t* out_area,
                            std::size_t* out_level,
                            std::string* error);
