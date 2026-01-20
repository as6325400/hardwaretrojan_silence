#include "rule_patch.hpp"

#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace {

int build_and_tree(circuit& net,
                   const std::vector<int>& nodes,
                   const std::string& prefix) {
  if (nodes.empty()) {
    return net.add_const_auto(prefix + "const_", 1);
  }
  std::vector<int> current = nodes;
  while (current.size() > 1U) {
    std::vector<int> next;
    next.reserve((current.size() + 1U) / 2U);
    for (std::size_t i = 0; i < current.size(); i += 2U) {
      if (i + 1U < current.size()) {
        int and_idx = net.add_gate_auto(prefix + "and_", GType::AND,
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

int build_or_tree(circuit& net,
                  const std::vector<int>& nodes,
                  const std::string& prefix) {
  if (nodes.empty()) {
    return net.add_const_auto(prefix + "const_", 0);
  }
  std::vector<int> current = nodes;
  while (current.size() > 1U) {
    std::vector<int> next;
    next.reserve((current.size() + 1U) / 2U);
    for (std::size_t i = 0; i < current.size(); i += 2U) {
      if (i + 1U < current.size()) {
        int or_idx = net.add_gate_auto(prefix + "or_", GType::OR,
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

int build_trigger_match_gate(circuit& net,
                             const std::vector<int>& feature_nodes,
                             const DecisionTreeModel& model,
                             std::string* error) {
  if (error) {
    error->clear();
  }
  if (model.rules.empty()) {
    if (error) {
      *error = "no rules to build trigger match";
    }
    return -1;
  }

  std::vector<int> rule_matches;
  std::size_t empty_rules = 0;
  for (const auto& rule : model.rules) {
    if (rule.terms.empty()) {
      empty_rules += 1;
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
        int not_idx = net.add_gate_auto("rule_not_", GType::NOT,
                                        std::vector<int>{node_idx});
        literals.push_back(not_idx);
      }
    }
    int match_idx = build_and_tree(net, literals, "rule_and_");
    rule_matches.push_back(match_idx);
  }

  if (empty_rules > 0) {
    if (error) {
      *error = "trigger rule is unconditional; skipping patch";
    }
    return -1;
  }
  if (rule_matches.empty()) {
    if (error) {
      *error = "no usable rules to build trigger match";
    }
    return -1;
  }
  if (rule_matches.size() == 1U) {
    return rule_matches[0];
  }
  return build_or_tree(net, rule_matches, "rule_or_");
}

}  // namespace

void simplify_rules(std::vector<DecisionTreeRule>* rules) {
  if (!rules) {
    return;
  }
  std::vector<DecisionTreeRule> cleaned;
  cleaned.reserve(rules->size());

  for (const auto& rule : *rules) {
    std::unordered_map<std::size_t, int> values;
    bool conflict = false;
    for (const auto& term : rule.terms) {
      auto it = values.find(term.first);
      if (it == values.end()) {
        values.emplace(term.first, term.second);
      } else if (it->second != term.second) {
        conflict = true;
        break;
      }
    }
    if (conflict) {
      continue;
    }
    DecisionTreeRule simplified;
    simplified.terms.reserve(values.size());
    for (const auto& entry : values) {
      simplified.terms.push_back({entry.first, entry.second});
    }
    std::sort(simplified.terms.begin(), simplified.terms.end());
    cleaned.push_back(std::move(simplified));
  }

  std::vector<char> removed(cleaned.size(), 0);
  for (std::size_t i = 0; i < cleaned.size(); ++i) {
    if (removed[i]) {
      continue;
    }
    for (std::size_t j = 0; j < cleaned.size(); ++j) {
      if (i == j || removed[j]) {
        continue;
      }
      const auto& a = cleaned[i].terms;
      const auto& b = cleaned[j].terms;
      if (a.size() > b.size()) {
        continue;
      }
      std::size_t ai = 0;
      std::size_t bi = 0;
      bool subset = true;
      while (ai < a.size() && bi < b.size()) {
        if (a[ai].first == b[bi].first &&
            a[ai].second == b[bi].second) {
          ++ai;
          ++bi;
        } else if (a[ai].first > b[bi].first ||
                   (a[ai].first == b[bi].first &&
                    a[ai].second > b[bi].second)) {
          ++bi;
        } else {
          subset = false;
          break;
        }
      }
      if (subset && ai == a.size()) {
        removed[j] = 1;
      }
    }
  }

  std::vector<DecisionTreeRule> final_rules;
  final_rules.reserve(cleaned.size());
  for (std::size_t i = 0; i < cleaned.size(); ++i) {
    if (!removed[i]) {
      final_rules.push_back(std::move(cleaned[i]));
    }
  }
  *rules = std::move(final_rules);
}

std::string pi_values_to_bits(const std::vector<int>& pi_values) {
  std::string bits;
  bits.reserve(pi_values.size());
  for (int v : pi_values) {
    bits.push_back(v ? '1' : '0');
  }
  return bits;
}

std::string derive_patched_path(const std::string& trojan_path) {
  std::string dir;
  std::string base = trojan_path;
  const std::size_t slash = base.find_last_of("/\\");
  if (slash != std::string::npos) {
    dir = base.substr(0, slash + 1);
    base = base.substr(slash + 1);
  }
  const std::size_t dot = base.rfind('.');
  if (dot != std::string::npos) {
    base = base.substr(0, dot);
  }
  return dir + base + "_patched.bench";
}

bool apply_rule_inversion(circuit& net,
                          const std::vector<int>& feature_nodes,
                          const DecisionTreeModel& model,
                          int fix_idx,
                          std::size_t base_nodes,
                          std::string* error) {
  if (error) {
    error->clear();
  }
  if (fix_idx < 0 || static_cast<std::size_t>(fix_idx) >= net.node_count()) {
    if (error) {
      *error = "fix node index out of range";
    }
    return false;
  }

  int match_idx = build_trigger_match_gate(net, feature_nodes, model, error);
  if (match_idx < 0) {
    return false;
  }

  int xor_idx = net.add_gate_auto("rule_flip_xor_", GType::XOR,
                                  std::vector<int>{fix_idx, match_idx});
  net.replace_gate_inputs(fix_idx, xor_idx, base_nodes);

  const auto& po_indices = net.po_indices();
  for (std::size_t pos = 0; pos < po_indices.size(); ++pos) {
    if (po_indices[pos] == fix_idx) {
      net.set_po_index(pos, xor_idx);
    }
  }
  return true;
}

bool evaluate_fix_candidate(const circuit& base,
                            const std::vector<int>& feature_nodes,
                            const DecisionTreeModel& model,
                            int fix_idx,
                            std::size_t* out_area,
                            std::size_t* out_level,
                            std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out_area || !out_level) {
    if (error) {
      *error = "output pointers are null";
    }
    return false;
  }

  circuit candidate = base;
  const std::size_t base_nodes = candidate.node_count();
  if (!apply_rule_inversion(candidate, feature_nodes, model, fix_idx, base_nodes, error)) {
    return false;
  }
  try {
    candidate.ensure_eval_order();
    *out_area = candidate.area();
    *out_level = candidate.level();
  } catch (const std::exception& e) {
    if (error) {
      *error = e.what();
    }
    return false;
  }
  return true;
}

bool verify_patch_groundtruth(const circuit& golden,
                              const circuit& patched,
                              const std::vector<std::vector<int>>& patterns,
                              std::size_t* mismatch_index,
                              std::string* error) {
  if (error) {
    error->clear();
  }
  if (mismatch_index) {
    *mismatch_index = 0;
  }
  if (patterns.empty()) {
    return true;
  }
  if (golden.pi_count() != patched.pi_count()) {
    if (error) {
      *error = "PI count mismatch";
    }
    return false;
  }
  if (golden.po_count() != patched.po_count()) {
    if (error) {
      *error = "PO count mismatch";
    }
    return false;
  }

  circuit golden_eval = golden;
  circuit patched_eval = patched;
  for (std::size_t i = 0; i < patterns.size(); ++i) {
    try {
      const std::vector<int> g_out = golden_eval.simulate(patterns[i]);
      const std::vector<int> p_out = patched_eval.simulate(patterns[i]);
      if (g_out != p_out) {
        if (mismatch_index) {
          *mismatch_index = i;
        }
        if (error) {
          *error = "groundtruth mismatch";
        }
        return false;
      }
    } catch (const std::exception& e) {
      if (mismatch_index) {
        *mismatch_index = i;
      }
      if (error) {
        *error = e.what();
      }
      return false;
    }
  }

  return true;
}
