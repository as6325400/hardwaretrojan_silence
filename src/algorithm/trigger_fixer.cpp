#include "trigger_fixer.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace {

struct PoRuleStats {
  std::size_t match_count = 0;
  std::size_t mismatch_count = 0;
  std::size_t same_count = 0;
};

std::vector<int> collect_features(const circuit& trojan,
                                  const std::vector<int>& feature_nodes) {
  std::vector<int> row;
  row.reserve(feature_nodes.size());
  for (int idx : feature_nodes) {
    const int val = trojan.get_cell(idx).val;
    row.push_back(val ? 1 : 0);
  }
  return row;
}

int build_and_tree(circuit& trojan,
                   const std::vector<int>& nodes) {
  if (nodes.empty()) {
    return trojan.add_const_auto("rule_const_", 1);
  }
  std::vector<int> current = nodes;
  while (current.size() > 1U) {
    std::vector<int> next;
    next.reserve((current.size() + 1U) / 2U);
    for (std::size_t i = 0; i < current.size(); i += 2U) {
      if (i + 1U < current.size()) {
        int and_idx = trojan.add_gate_auto("rule_and_", GType::AND,
                                           std::vector<int>{current[i], current[i + 1U]});
        next.push_back(and_idx);
      } else {
        next.push_back(current[i]);
      }
    }
    current.swap(next);
  }
  return current[0];
}

int build_or_tree(circuit& trojan,
                  const std::vector<int>& nodes) {
  if (nodes.empty()) {
    return trojan.add_const_auto("rule_const_", 0);
  }
  std::vector<int> current = nodes;
  while (current.size() > 1U) {
    std::vector<int> next;
    next.reserve((current.size() + 1U) / 2U);
    for (std::size_t i = 0; i < current.size(); i += 2U) {
      if (i + 1U < current.size()) {
        int or_idx = trojan.add_gate_auto("rule_or_", GType::OR,
                                          std::vector<int>{current[i], current[i + 1U]});
        next.push_back(or_idx);
      } else {
        next.push_back(current[i]);
      }
    }
    current.swap(next);
  }
  return current[0];
}

int build_trigger_match(circuit& trojan,
                        const std::vector<int>& feature_nodes,
                        const DecisionTreeModel& model,
                        std::size_t* rules_used,
                        std::size_t* rules_empty,
                        std::string* error) {
  std::vector<int> rule_matches;
  *rules_used = 0;
  *rules_empty = 0;

  for (const auto& rule : model.rules) {
    if (rule.terms.empty()) {
      (*rules_empty)++;
      continue;
    }
    std::vector<int> literals;
    literals.reserve(rule.terms.size());
    for (const auto& term : rule.terms) {
      const std::size_t feature_idx = term.first;
      if (feature_idx >= feature_nodes.size()) {
        if (error) {
          *error = "rule term index out of range";
        }
        return -1;
      }
      const int node_idx = feature_nodes[feature_idx];
      const int expected = term.second ? 1 : 0;
      if (expected == 1) {
        literals.push_back(node_idx);
      } else {
        int not_idx = trojan.add_gate_auto("rule_not_", GType::NOT,
                                           std::vector<int>{node_idx});
        literals.push_back(not_idx);
      }
    }
    int match_idx = build_and_tree(trojan, literals);
    rule_matches.push_back(match_idx);
    (*rules_used)++;
  }

  if (rule_matches.empty()) {
    if (error) {
      *error = "no usable rules to build trigger match";
    }
    return -1;
  }

  if (rule_matches.size() == 1) {
    return rule_matches[0];
  }

  return build_or_tree(trojan, rule_matches);
}

bool build_golden_cone_clone(const circuit& golden,
                             circuit& trojan,
                             const std::vector<std::size_t>& po_positions,
                             std::vector<int>* golden_po_nodes,
                             std::string* error) {
  if (error) {
    error->clear();
  }
  if (!golden_po_nodes) {
    if (error) {
      *error = "golden PO container is null";
    }
    return false;
  }
  golden_po_nodes->assign(trojan.po_count(), -1);

  if (po_positions.empty()) {
    return true;
  }

  circuit golden_copy = golden;
  try {
    golden_copy.ensure_eval_order();
  } catch (const std::exception& e) {
    if (error) {
      *error = std::string("golden eval order error: ") + e.what();
    }
    return false;
  }

  if (golden_copy.pi_count() != trojan.pi_count()) {
    if (error) {
      *error = "PI count mismatch between golden and trojan";
    }
    return false;
  }

  const auto& g_po = golden_copy.po_indices();
  for (std::size_t pos : po_positions) {
    if (pos >= g_po.size()) {
      if (error) {
        *error = "golden PO position out of range";
      }
      return false;
    }
  }

  std::vector<char> needed(golden_copy.node_count(), 0);
  std::vector<int> stack;
  for (std::size_t pos : po_positions) {
    stack.push_back(g_po[pos]);
    while (!stack.empty()) {
      int node_idx = stack.back();
      stack.pop_back();
      if (node_idx < 0 ||
          static_cast<std::size_t>(node_idx) >= needed.size()) {
        if (error) {
          *error = "golden node index out of range";
        }
        return false;
      }
      if (needed[static_cast<std::size_t>(node_idx)]) {
        continue;
      }
      needed[static_cast<std::size_t>(node_idx)] = 1;
      const cell& c = golden_copy.get_cell(node_idx);
      if (c.ctype == CType::GATE) {
        for (int input_idx : c.inputs) {
          stack.push_back(input_idx);
        }
      }
    }
  }

  std::vector<int> node_map(golden_copy.node_count(), -1);
  const auto& g_pi = golden_copy.pi_indices();
  const auto& t_pi = trojan.pi_indices();
  for (std::size_t i = 0; i < g_pi.size(); ++i) {
    node_map[g_pi[i]] = t_pi[i];
  }

  for (std::size_t i = 0; i < golden_copy.node_count(); ++i) {
    if (!needed[i]) {
      continue;
    }
    const cell& c = golden_copy.get_cell(static_cast<int>(i));
    if (c.ctype == CType::CONST) {
      node_map[i] = trojan.add_const_auto("golden_const_", c.val);
    }
  }

  for (int idx : golden_copy.eval_order()) {
    if (!needed[static_cast<std::size_t>(idx)]) {
      continue;
    }
    const cell& c = golden_copy.get_cell(idx);
    if (c.ctype != CType::GATE) {
      continue;
    }
    std::vector<int> inputs;
    inputs.reserve(c.inputs.size());
    for (int input_idx : c.inputs) {
      if (input_idx < 0 ||
          static_cast<std::size_t>(input_idx) >= node_map.size()) {
        if (error) {
          *error = "golden input index out of range";
        }
        return false;
      }
      const int mapped = node_map[static_cast<std::size_t>(input_idx)];
      if (mapped < 0) {
        if (error) {
          *error = "golden input not mapped";
        }
        return false;
      }
      inputs.push_back(mapped);
    }
    const int new_idx = trojan.add_gate_auto("golden_gate_", c.gtype, inputs);
    node_map[static_cast<std::size_t>(idx)] = new_idx;
  }

  for (std::size_t pos : po_positions) {
    const int idx = g_po[pos];
    if (idx < 0 || static_cast<std::size_t>(idx) >= node_map.size()) {
      if (error) {
        *error = "golden PO index out of range";
      }
      return false;
    }
    const int mapped = node_map[static_cast<std::size_t>(idx)];
    if (mapped < 0) {
      if (error) {
        *error = "golden PO not mapped";
      }
      return false;
    }
    (*golden_po_nodes)[pos] = mapped;
  }

  return true;
}

}  // namespace

bool apply_rule_fix(const circuit& golden,
                    circuit& trojan,
                    const std::vector<std::vector<int>>& trigger_patterns,
                    const std::vector<int>& feature_nodes,
                    const DecisionTreeModel& model,
                    FixResult* result,
                    std::string* error) {
  if (error) {
    error->clear();
  }
  if (!result) {
    if (error) {
      *error = "Fix result pointer is null";
    }
    return false;
  }
  *result = FixResult{};
  result->rules_total = model.rules.size();

  if (model.rules.empty()) {
    if (error) {
      *error = "No rules to apply";
    }
    return false;
  }
  if (golden.po_count() != trojan.po_count()) {
    if (error) {
      *error = "PO count mismatch between golden and trojan";
    }
    return false;
  }
  if (feature_nodes.empty()) {
    if (error) {
      *error = "No feature nodes for rule evaluation";
    }
    return false;
  }

  const std::size_t po_count = trojan.po_count();
  std::vector<int> po_mismatch(po_count, 0);
  std::vector<PoRuleStats> po_stats(po_count);

  if (!trigger_patterns.empty()) {
    circuit golden_sim = golden;
    circuit trojan_sim = trojan;
    for (const auto& pattern : trigger_patterns) {
      std::vector<int> golden_outputs;
      std::vector<int> trojan_outputs;
      try {
        golden_outputs = golden_sim.simulate(pattern);
        trojan_outputs = trojan_sim.simulate(pattern);
      } catch (const std::exception& e) {
        std::cerr << "Rule fix simulation error: " << e.what() << "\n";
        continue;
      }
      const std::vector<int> features = collect_features(trojan_sim, feature_nodes);
      const bool match = eval_rules(model.rules, features);
      for (std::size_t i = 0; i < po_count; ++i) {
        const bool mismatch = (golden_outputs[i] != trojan_outputs[i]);
        if (mismatch) {
          po_mismatch[i] = 1;
        }
        if (match) {
          PoRuleStats& stats = po_stats[i];
          stats.match_count += 1;
          if (mismatch) {
            stats.mismatch_count += 1;
          } else {
            stats.same_count += 1;
          }
        }
      }
    }
  }

  result->po_candidates = std::count(po_mismatch.begin(), po_mismatch.end(), 1);
  if (result->po_candidates == 0) {
    return true;
  }

  enum class FixMode {
    None,
    Xor,
    GoldenMux
  };

  std::vector<FixMode> fix_modes(po_count, FixMode::None);
  std::vector<std::size_t> mux_positions;
  for (std::size_t i = 0; i < po_count; ++i) {
    const PoRuleStats& stats = po_stats[i];
    if (stats.match_count == 0 || stats.mismatch_count == 0) {
      continue;
    }
    fix_modes[i] = FixMode::GoldenMux;
    mux_positions.push_back(i);
  }

  bool need_fix = false;
  for (FixMode mode : fix_modes) {
    if (mode != FixMode::None) {
      need_fix = true;
      break;
    }
  }
  if (!need_fix) {
    return true;
  }

  std::size_t rules_used = 0;
  std::size_t rules_empty = 0;
  int trigger_match = build_trigger_match(trojan,
                                          feature_nodes,
                                          model,
                                          &rules_used,
                                          &rules_empty,
                                          error);
  if (trigger_match < 0) {
    return false;
  }

  result->rules_applied = rules_used;
  result->rules_skipped = model.rules.size() - rules_used;
  if (rules_empty > 0) {
    result->rules_skipped = model.rules.size() - rules_used;
  }

  const cell& match_cell = trojan.get_cell(trigger_match);
  const bool match_const = (match_cell.ctype == CType::CONST);
  const int match_const_val = match_const ? (match_cell.val ? 1 : 0) : 0;
  if (match_const && match_const_val == 0) {
    return true;
  }
  if (match_const && match_const_val == 1) {
    if (error) {
      *error = "trigger rule is unconditional; skipping fix";
    }
    return false;
  }

  std::vector<int> golden_po_nodes;
  if (!mux_positions.empty()) {
    if (!build_golden_cone_clone(golden, trojan, mux_positions, &golden_po_nodes, error)) {
      return false;
    }
    if (golden_po_nodes.size() != po_count) {
      if (error) {
        *error = "golden PO mapping size mismatch";
      }
      return false;
    }
  }

  int not_match_idx = -1;
  for (std::size_t i = 0; i < po_count; ++i) {
    if (fix_modes[i] == FixMode::None) {
      continue;
    }
    const int po_idx = trojan.po_indices()[i];
    int fixed_idx = po_idx;
    if (fix_modes[i] == FixMode::Xor) {
      fixed_idx = trojan.add_gate_auto("rule_fix_xor_", GType::XOR,
                                       std::vector<int>{po_idx, trigger_match});
      result->po_fixed_xor += 1;
    } else if (fix_modes[i] == FixMode::GoldenMux) {
      if (i >= golden_po_nodes.size() || golden_po_nodes[i] < 0) {
        if (error) {
          *error = "missing golden PO mapping";
        }
        return false;
      }
      if (not_match_idx < 0) {
        not_match_idx = trojan.add_gate_auto("rule_fix_not_", GType::NOT,
                                             std::vector<int>{trigger_match});
      }
      const int golden_po_idx = golden_po_nodes[i];
      int keep_idx = trojan.add_gate_auto("rule_fix_and_", GType::AND,
                                          std::vector<int>{not_match_idx, po_idx});
      int fix_idx = trojan.add_gate_auto("rule_fix_and_", GType::AND,
                                         std::vector<int>{trigger_match, golden_po_idx});
      fixed_idx = trojan.add_gate_auto("rule_fix_or_", GType::OR,
                                       std::vector<int>{keep_idx, fix_idx});
      result->po_fixed_mux += 1;
    }
    trojan.set_po_index(i, fixed_idx);
    result->po_fixed += 1;
  }

  return true;
}
