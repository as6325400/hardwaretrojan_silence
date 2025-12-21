#include "trigger_fixer.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace {

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

  if (*rules_empty > 0) {
    return trojan.add_const_auto("rule_const_", 1);
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

bool build_golden_clone(const circuit& golden,
                        circuit& trojan,
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
  golden_po_nodes->clear();

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

  std::vector<int> node_map(golden_copy.node_count(), -1);
  const auto& g_pi = golden_copy.pi_indices();
  const auto& t_pi = trojan.pi_indices();
  for (std::size_t i = 0; i < g_pi.size(); ++i) {
    node_map[g_pi[i]] = t_pi[i];
  }

  for (std::size_t i = 0; i < golden_copy.node_count(); ++i) {
    const cell& c = golden_copy.get_cell(static_cast<int>(i));
    if (c.ctype == CType::CONST) {
      node_map[i] = trojan.add_const_auto("golden_const_", c.val);
    }
  }

  for (int idx : golden_copy.eval_order()) {
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

  const auto& g_po = golden_copy.po_indices();
  golden_po_nodes->reserve(g_po.size());
  for (int idx : g_po) {
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
    golden_po_nodes->push_back(mapped);
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
      for (std::size_t i = 0; i < po_count; ++i) {
        if (golden_outputs[i] != trojan_outputs[i]) {
          po_mismatch[i] = 1;
        }
      }
    }
  }

  result->po_candidates = std::count(po_mismatch.begin(), po_mismatch.end(), 1);
  if (result->po_candidates == 0) {
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
    result->rules_applied = model.rules.size();
    result->rules_skipped = 0;
  }

  std::vector<int> golden_po_nodes;
  if (!build_golden_clone(golden, trojan, &golden_po_nodes, error)) {
    return false;
  }
  if (golden_po_nodes.size() != po_count) {
    if (error) {
      *error = "golden PO mapping size mismatch";
    }
    return false;
  }

  const cell& match_cell = trojan.get_cell(trigger_match);
  const bool match_const = (match_cell.ctype == CType::CONST);
  const int match_const_val = match_const ? (match_cell.val ? 1 : 0) : 0;

  int not_match_idx = -1;
  for (std::size_t i = 0; i < po_count; ++i) {
    if (po_mismatch[i] == 0) {
      continue;
    }
    const int po_idx = trojan.po_indices()[i];
    const int golden_po_idx = golden_po_nodes[i];
    int fixed_idx = po_idx;
    if (match_const) {
      if (match_const_val == 1) {
        fixed_idx = golden_po_idx;
      } else {
        fixed_idx = po_idx;
      }
    } else {
      if (not_match_idx < 0) {
        not_match_idx = trojan.add_gate_auto("rule_fix_not_", GType::NOT,
                                             std::vector<int>{trigger_match});
      }
      int keep_idx = trojan.add_gate_auto("rule_fix_and_", GType::AND,
                                          std::vector<int>{not_match_idx, po_idx});
      int fix_idx = trojan.add_gate_auto("rule_fix_and_", GType::AND,
                                         std::vector<int>{trigger_match, golden_po_idx});
      fixed_idx = trojan.add_gate_auto("rule_fix_or_", GType::OR,
                                       std::vector<int>{keep_idx, fix_idx});
    }
    trojan.set_po_index(i, fixed_idx);
    result->po_fixed += 1;
  }

  return true;
}
