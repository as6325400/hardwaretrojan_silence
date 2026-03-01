#include "rule_patch.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "../core/packed_circuit.hpp"
#include "../io/eqn_parser.hpp"

#ifdef USE_CUDA
#include <cuda_runtime.h>
#include "../core/gpu_circuit.cuh"
#endif

namespace {

struct LiteralKey {
  std::size_t feature_idx = 0;
  int expected = 0;
};

struct RuleExpr {
  std::vector<LiteralKey> features;
  std::vector<int> shared_nodes;
};

struct SubsetInfo {
  std::vector<LiteralKey> literals;
  std::vector<std::size_t> rules;
};

struct SharedInfo {
  std::size_t k = 0;
  std::size_t m = 0;
  std::size_t gain = 0;
  int node_idx = -1;
};

std::string temp_dir() {
  const char* tmp = std::getenv("TMPDIR");
  if (tmp && *tmp) {
    return tmp;
  }
  return "/tmp";
}

std::string make_temp_path(const std::string& suffix) {
  static std::uint64_t counter = 0;
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  std::ostringstream oss;
  oss << temp_dir() << "/rule_patch_" << now << "_" << counter++ << suffix;
  return oss.str();
}

std::string make_rule_signature(const std::vector<DecisionTreeRule>& rules,
                                std::size_t feature_count) {
  std::ostringstream oss;
  oss << "f" << feature_count << "|";
  for (const auto& rule : rules) {
    std::vector<std::pair<std::size_t, int>> terms = rule.terms;
    std::sort(terms.begin(), terms.end());
    oss << "[";
    for (const auto& term : terms) {
      oss << term.first << '=' << term.second << ',';
    }
    oss << "];";
  }
  return oss.str();
}

bool write_rules_pla(const std::vector<DecisionTreeRule>& rules,
                     std::size_t feature_count,
                     const std::string& path,
                     std::string* error) {
  if (error) {
    error->clear();
  }
  std::ofstream out(path);
  if (!out) {
    if (error) {
      *error = "failed to open PLA: " + path;
    }
    return false;
  }
  out << ".i " << feature_count << "\n";
  out << ".o 1\n";
  out << ".ilb";
  for (std::size_t i = 0; i < feature_count; ++i) {
    out << " f" << i;
  }
  out << "\n";
  out << ".ob F\n";
  out << ".p " << rules.size() << "\n";
  for (const auto& rule : rules) {
    std::string cube(feature_count, '-');
    for (const auto& term : rule.terms) {
      if (term.first >= feature_count) {
        if (error) {
          *error = "rule term index out of range";
        }
        return false;
      }
      cube[term.first] = term.second ? '1' : '0';
    }
    out << cube << " 1\n";
  }
  out << ".e\n";
  return true;
}

bool run_abc_optimize(const std::string& pla_path,
                      const std::string& eqn_path,
                      std::string* error) {
  if (error) {
    error->clear();
  }
  const char* abc_bin = std::getenv("ABC_BIN");
  std::string abc_cmd = (abc_bin && *abc_bin) ? abc_bin : "abc";
  const std::string flow =
      "strash; balance; rewrite; refactor; balance; rewrite -z; refactor -z";
  const std::string script =
      "read_pla '" + pla_path + "'; " + flow + "; write_eqn '" + eqn_path + "'";
  abc_cmd += " -c \"" + script + "\" > /dev/null 2>&1";
  FILE* pipe = popen(abc_cmd.c_str(), "r");
  if (!pipe) {
    if (error) {
      *error = "ABC failed to launch, make sure abc is in PATH or set ABC_BIN";
    }
    return false;
  }
  const int ret = pclose(pipe);
  if (ret != 0) {
    if (error) {
      *error = "ABC failed (exit " + std::to_string(ret) +
               "), make sure abc is in PATH or set ABC_BIN";
    }
    return false;
  }
  return true;
}

struct TempFiles {
  std::string pla;
  std::string eqn;
  ~TempFiles() {
    if (!pla.empty()) {
      std::remove(pla.c_str());
    }
    if (!eqn.empty()) {
      std::remove(eqn.c_str());
    }
  }
};

bool load_optimized_rule_circuit(const DecisionTreeModel& model,
                                 std::size_t feature_count,
                                 circuit* out,
                                 std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out) {
    if (error) {
      *error = "optimized circuit output is null";
    }
    return false;
  }
  if (model.rules.empty()) {
    if (error) {
      *error = "no rules to optimize";
    }
    return false;
  }
  const std::string key = make_rule_signature(model.rules, feature_count);
  static std::unordered_map<std::string, circuit> cache;
  auto it = cache.find(key);
  if (it != cache.end()) {
    *out = it->second;
    return true;
  }

  TempFiles tmp;
  tmp.pla = make_temp_path(".pla");
  tmp.eqn = make_temp_path(".eqn");
  if (!write_rules_pla(model.rules, feature_count, tmp.pla, error)) {
    return false;
  }
  if (!run_abc_optimize(tmp.pla, tmp.eqn, error)) {
    return false;
  }

  circuit optimized;
  if (!bench_io::parse_eqn_file(tmp.eqn, optimized, error)) {
    return false;
  }

  cache.emplace(key, optimized);
  *out = std::move(optimized);
  return true;
}

bool parse_feature_index(const std::string& name, std::size_t* feature_idx) {
  if (!feature_idx) {
    return false;
  }
  if (name.size() < 2) {
    return false;
  }
  if (name[0] != 'f' && name[0] != 'F') {
    return false;
  }
  std::size_t value = 0;
  for (std::size_t i = 1; i < name.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(name[i]);
    if (!std::isdigit(c)) {
      return false;
    }
    value = value * 10 + static_cast<std::size_t>(c - '0');
  }
  *feature_idx = value;
  return true;
}

int instantiate_optimized_logic(circuit& net,
                                const std::vector<int>& feature_nodes,
                                const circuit& optimized,
                                std::string* error) {
  if (error) {
    error->clear();
  }

  circuit temp = optimized;
  try {
    temp.ensure_eval_order();
  } catch (const std::exception& e) {
    if (error) {
      *error = e.what();
    }
    return -1;
  }

  std::vector<int> node_map(temp.node_count(), -1);
  std::unordered_map<std::string, int> feature_by_name;
  feature_by_name.reserve(feature_nodes.size());
  for (int node_idx : feature_nodes) {
    feature_by_name.emplace(net.node_name(node_idx), node_idx);
  }

  const auto& pi_indices = temp.pi_indices();
  std::vector<int> mapped_pi(pi_indices.size(), -1);
  bool parsed_all = true;
  for (std::size_t i = 0; i < pi_indices.size(); ++i) {
    const int pi_idx = pi_indices[i];
    const std::string& name = temp.node_name(pi_idx);
    std::size_t feature_idx = 0;
    if (parse_feature_index(name, &feature_idx) &&
        feature_idx < feature_nodes.size()) {
      mapped_pi[i] = feature_nodes[feature_idx];
      continue;
    }
    auto it = feature_by_name.find(name);
    if (it != feature_by_name.end()) {
      mapped_pi[i] = it->second;
      continue;
    }
    parsed_all = false;
    break;
  }

  if (!parsed_all) {
    if (pi_indices.size() != feature_nodes.size()) {
      if (error) {
        *error = "optimized PI names do not match features";
      }
      return -1;
    }
    for (std::size_t i = 0; i < pi_indices.size(); ++i) {
      mapped_pi[i] = feature_nodes[i];
    }
  }

  for (std::size_t i = 0; i < pi_indices.size(); ++i) {
    node_map[pi_indices[i]] = mapped_pi[i];
  }

  for (std::size_t i = 0; i < temp.node_count(); ++i) {
    const cell& c = temp.get_cell(static_cast<int>(i));
    if (c.ctype == CType::CONST) {
      node_map[i] = net.add_const_auto("rule_opt_const_", c.val);
    }
  }

  for (int idx : temp.eval_order()) {
    const cell& c = temp.get_cell(idx);
    if (c.ctype != CType::GATE) {
      continue;
    }
    std::vector<int> inputs;
    inputs.reserve(c.inputs.size());
    for (int input_idx : c.inputs) {
      if (input_idx < 0 || static_cast<std::size_t>(input_idx) >= node_map.size()) {
        if (error) {
          *error = "optimized gate input out of range";
        }
        return -1;
      }
      const int mapped = node_map[input_idx];
      if (mapped < 0) {
        if (error) {
          *error = "optimized gate input unresolved";
        }
        return -1;
      }
      inputs.push_back(mapped);
    }
    node_map[idx] = net.add_gate_auto("rule_opt_gate_", c.gtype, inputs);
  }

  const auto& po_indices = temp.po_indices();
  if (po_indices.empty()) {
    if (error) {
      *error = "optimized logic has no outputs";
    }
    return -1;
  }
  const int out_idx = node_map[po_indices[0]];
  if (out_idx < 0) {
    if (error) {
      *error = "optimized output unresolved";
    }
    return -1;
  }
  return out_idx;
}

std::string subset_key(const std::vector<LiteralKey>& literals) {
  std::string key;
  key.reserve(literals.size() * 16);
  for (const auto& lit : literals) {
    key.append(std::to_string(lit.feature_idx));
    key.push_back('=');
    key.push_back(lit.expected ? '1' : '0');
    key.push_back(';');
  }
  return key;
}

void enumerate_subsets(const std::vector<LiteralKey>& literals,
                       std::size_t start,
                       std::size_t remaining,
                       std::vector<LiteralKey>* current,
                       std::vector<std::vector<LiteralKey>>* out) {
  if (!current || !out) {
    return;
  }
  if (remaining == 0) {
    out->push_back(*current);
    return;
  }
  if (start >= literals.size()) {
    return;
  }
  for (std::size_t i = start; i + remaining <= literals.size(); ++i) {
    current->push_back(literals[i]);
    enumerate_subsets(literals, i + 1, remaining - 1, current, out);
    current->pop_back();
  }
}

bool rule_contains_subset(const std::vector<LiteralKey>& rule,
                          const std::vector<LiteralKey>& subset) {
  std::size_t i = 0;
  std::size_t j = 0;
  while (i < rule.size() && j < subset.size()) {
    const auto& a = rule[i];
    const auto& b = subset[j];
    if (a.feature_idx == b.feature_idx && a.expected == b.expected) {
      ++i;
      ++j;
    } else if (a.feature_idx < b.feature_idx ||
               (a.feature_idx == b.feature_idx && a.expected < b.expected)) {
      ++i;
    } else {
      return false;
    }
  }
  return j == subset.size();
}

void remove_subset(std::vector<LiteralKey>* rule,
                   const std::vector<LiteralKey>& subset) {
  if (!rule) {
    return;
  }
  std::vector<LiteralKey> updated;
  updated.reserve(rule->size());
  std::size_t i = 0;
  std::size_t j = 0;
  while (i < rule->size()) {
    if (j < subset.size() &&
        (*rule)[i].feature_idx == subset[j].feature_idx &&
        (*rule)[i].expected == subset[j].expected) {
      ++i;
      ++j;
      continue;
    }
    updated.push_back((*rule)[i]);
    ++i;
  }
  rule->swap(updated);
}

int get_literal_node(circuit& net,
                     const std::vector<int>& feature_nodes,
                     std::unordered_map<std::size_t, int>* not_cache,
                     std::size_t feature_idx,
                     int expected) {
  const int base_idx = feature_nodes[feature_idx];
  if (expected == 1) {
    return base_idx;
  }
  if (!not_cache) {
    return net.add_gate_auto("rule_not_", GType::NOT, std::vector<int>{base_idx});
  }
  auto it = not_cache->find(feature_idx);
  if (it != not_cache->end()) {
    return it->second;
  }
  int not_idx = net.add_gate_auto("rule_not_", GType::NOT,
                                  std::vector<int>{base_idx});
  (*not_cache)[feature_idx] = not_idx;
  return not_idx;
}

void apply_factoring(circuit& net,
                     const std::vector<int>& feature_nodes,
                     std::vector<RuleExpr>* rules,
                     std::size_t min_k,
                     std::size_t max_k,
                     std::size_t min_m,
                     std::size_t gain_threshold,
                     std::size_t max_shared,
                     std::vector<int>* created_nodes,
                     std::vector<SharedInfo>* shared_info) {
  if (!rules || rules->empty()) {
    return;
  }
  std::unordered_map<std::size_t, int> not_cache;

  for (auto& rule : *rules) {
    std::sort(rule.features.begin(), rule.features.end(),
              [](const LiteralKey& a, const LiteralKey& b) {
                if (a.feature_idx != b.feature_idx) {
                  return a.feature_idx < b.feature_idx;
                }
                return a.expected < b.expected;
              });
  }

  while (created_nodes && created_nodes->size() < max_shared) {
    std::unordered_map<std::string, SubsetInfo> subsets;
    for (std::size_t r = 0; r < rules->size(); ++r) {
      const auto& rule = (*rules)[r].features;
      if (rule.size() < min_k) {
        continue;
      }
      const std::size_t upper_k = std::min(max_k, rule.size());
      for (std::size_t k = min_k; k <= upper_k; ++k) {
        std::vector<LiteralKey> current;
        std::vector<std::vector<LiteralKey>> combos;
        enumerate_subsets(rule, 0, k, &current, &combos);
        for (auto& combo : combos) {
          const std::string key = subset_key(combo);
          auto& entry = subsets[key];
          if (entry.literals.empty()) {
            entry.literals = std::move(combo);
          }
          entry.rules.push_back(r);
        }
      }
    }

    std::size_t best_gain = 0;
    std::string best_key;
    SubsetInfo best_subset;
    for (auto& item : subsets) {
      const auto& subset = item.second.literals;
      if (subset.empty()) {
        continue;
      }
      const std::size_t k = subset.size();
      const std::size_t m = item.second.rules.size();
      if (k < min_k || k > max_k || m < min_m) {
        continue;
      }
      const std::size_t gain = (m - 1) * (k - 1);
      if (gain >= gain_threshold && gain > best_gain) {
        best_gain = gain;
        best_key = item.first;
        best_subset = item.second;
      }
    }

    if (best_gain == 0 || best_subset.literals.empty()) {
      break;
    }

    std::vector<int> nodes;
    nodes.reserve(best_subset.literals.size());
    for (const auto& lit : best_subset.literals) {
      nodes.push_back(get_literal_node(net,
                                       feature_nodes,
                                       &not_cache,
                                       lit.feature_idx,
                                       lit.expected));
    }
    int shared_idx = -1;
    if (nodes.empty()) {
      shared_idx = net.add_const_auto("rule_share_const_", 1);
    } else if (nodes.size() == 1U) {
      shared_idx = nodes[0];
    } else {
      std::vector<int> current = nodes;
      while (current.size() > 1U) {
        std::vector<int> next;
        next.reserve((current.size() + 1U) / 2U);
        for (std::size_t i = 0; i < current.size(); i += 2U) {
          if (i + 1U < current.size()) {
            int and_idx = net.add_gate_auto("rule_share_and_", GType::AND,
                                            std::vector<int>{current[i], current[i + 1U]});
            next.push_back(and_idx);
          } else {
            next.push_back(current[i]);
          }
        }
        current.swap(next);
      }
      shared_idx = current[0];
    }
    if (created_nodes) {
      created_nodes->push_back(shared_idx);
    }
    if (shared_info) {
      SharedInfo info;
      info.k = best_subset.literals.size();
      info.m = best_subset.rules.size();
      info.gain = best_gain;
      info.node_idx = shared_idx;
      shared_info->push_back(info);
    }

    for (std::size_t r : best_subset.rules) {
      if (r >= rules->size()) {
        continue;
      }
      auto& rule = (*rules)[r];
      if (!rule_contains_subset(rule.features, best_subset.literals)) {
        continue;
      }
      remove_subset(&rule.features, best_subset.literals);
      rule.shared_nodes.push_back(shared_idx);
    }
  }
}

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

std::string make_unique_name(circuit& net, const std::string& base) {
  std::size_t suffix = 0;
  std::string candidate = base;
  while (net.has_node(candidate)) {
    candidate = base + std::to_string(suffix++);
  }
  return candidate;
}

bool preserve_po_name_on_replace(circuit& net,
                                 int old_idx,
                                 int new_idx,
                                 std::string* error) {
  if (error) {
    error->clear();
  }
  if (old_idx == new_idx) {
    return true;
  }
  const std::string old_name = net.node_name(old_idx);
  const std::string renamed =
      make_unique_name(net, old_name + "_orig_");
  if (!net.rename_node(old_idx, renamed, error)) {
    return false;
  }
  if (!net.rename_node(new_idx, old_name, error)) {
    return false;
  }
  return true;
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

  std::vector<RuleExpr> rule_exprs;
  rule_exprs.reserve(model.rules.size());
  std::size_t empty_rules = 0;
  for (const auto& rule : model.rules) {
    if (rule.terms.empty()) {
      empty_rules += 1;
      continue;
    }
    RuleExpr expr;
    expr.features.reserve(rule.terms.size());
    for (const auto& term : rule.terms) {
      const std::size_t feature_idx = term.first;
      if (feature_idx >= feature_nodes.size()) {
        if (error) {
          *error = "rule term index out of range";
        }
        return -1;
      }
      expr.features.push_back(LiteralKey{feature_idx, term.second ? 1 : 0});
    }
    rule_exprs.push_back(std::move(expr));
  }

  if (empty_rules > 0) {
    if (error) {
      *error = "trigger rule is unconditional; skipping patch";
    }
    return -1;
  }
  if (rule_exprs.empty()) {
    if (error) {
      *error = "no usable rules to build trigger match";
    }
    return -1;
  }

  if (model.rules.size() > 1U) {
    circuit optimized;
    std::string opt_error;
    if (load_optimized_rule_circuit(model,
                                    feature_nodes.size(),
                                    &optimized,
                                    &opt_error)) {
      int opt_idx = instantiate_optimized_logic(net,
                                                feature_nodes,
                                                optimized,
                                                &opt_error);
      if (opt_idx >= 0) {
        std::cout << "rule_opt_abc rules " << model.rules.size()
                  << " nodes " << optimized.node_count() << "\n";
        return opt_idx;
      }
    }
    if (!opt_error.empty()) {
      std::cerr << "rule_opt_abc fallback: " << opt_error << "\n";
    }
  }

  const std::size_t k_min = 2;
  const std::size_t k_max = 4;
  const std::size_t min_m = 3;
  const std::size_t gain_threshold = 3;
  const std::size_t max_shared_nodes = 12;
  std::vector<int> shared_nodes;
  std::vector<SharedInfo> shared_info;
  std::size_t literals_before = 0;
  for (const auto& rule : rule_exprs) {
    literals_before += rule.features.size();
  }
  apply_factoring(net,
                  feature_nodes,
                  &rule_exprs,
                  k_min,
                  k_max,
                  min_m,
                  gain_threshold,
                  max_shared_nodes,
                  &shared_nodes,
                  &shared_info);
  std::size_t literals_after = 0;
  for (const auto& rule : rule_exprs) {
    literals_after += rule.features.size() + rule.shared_nodes.size();
  }
  std::cout << "rule_factoring_rules " << rule_exprs.size()
            << " literals " << literals_before
            << " -> " << literals_after
            << " shared_nodes " << shared_nodes.size() << "\n";
  for (std::size_t i = 0; i < shared_info.size(); ++i) {
    const auto& info = shared_info[i];
    std::cout << "rule_factoring_node " << (i + 1)
              << " idx " << info.node_idx
              << " k " << info.k
              << " m " << info.m
              << " gain " << info.gain << "\n";
  }

  std::unordered_map<std::size_t, int> not_cache;
  std::vector<int> rule_matches;
  rule_matches.reserve(rule_exprs.size());
  for (const auto& rule : rule_exprs) {
    std::vector<int> literals;
    literals.reserve(rule.features.size() + rule.shared_nodes.size());
    for (const auto& lit : rule.features) {
      literals.push_back(get_literal_node(net,
                                          feature_nodes,
                                          &not_cache,
                                          lit.feature_idx,
                                          lit.expected));
    }
    for (int shared_idx : rule.shared_nodes) {
      literals.push_back(shared_idx);
    }
    if (literals.empty()) {
      if (error) {
        *error = "trigger rule is unconditional; skipping patch";
      }
      return -1;
    }
    int match_idx = build_and_tree(net, literals, "rule_and_");
    rule_matches.push_back(match_idx);
  }

  if (rule_matches.size() == 1U) {
    return rule_matches[0];
  }
  return build_or_tree(net, rule_matches, "rule_or_");
}

bool extract_single_literal_trigger(const std::vector<int>& feature_nodes,
                                    const DecisionTreeModel& model,
                                    int* trigger_idx,
                                    int* expected_value,
                                    std::string* error) {
  if (error) {
    error->clear();
  }
  if (model.rules.empty()) {
    return false;
  }

  bool have_literal = false;
  std::size_t feature_idx = 0;
  int expected = 0;
  for (const auto& rule : model.rules) {
    if (rule.terms.empty()) {
      return false;
    }
    if (rule.terms.size() != 1U) {
      return false;
    }
    const auto& term = rule.terms[0];
    if (!have_literal) {
      feature_idx = term.first;
      expected = term.second ? 1 : 0;
      have_literal = true;
    } else if (term.first != feature_idx || term.second != expected) {
      return false;
    }
  }

  if (!have_literal) {
    return false;
  }
  if (feature_idx >= feature_nodes.size()) {
    if (error) {
      *error = "trigger feature index out of range";
    }
    return false;
  }
  if (trigger_idx) {
    *trigger_idx = feature_nodes[feature_idx];
  }
  if (expected_value) {
    *expected_value = expected;
  }
  return true;
}

bool is_not_gate_of(const circuit& net, int node_idx, int input_idx) {
  if (node_idx < 0 || input_idx < 0 ||
      static_cast<std::size_t>(node_idx) >= net.node_count() ||
      static_cast<std::size_t>(input_idx) >= net.node_count()) {
    return false;
  }
  const cell& c = net.get_cell(node_idx);
  if (c.ctype != CType::GATE || c.gtype != GType::NOT || c.inputs.size() != 1U) {
    return false;
  }
  return c.inputs[0] == input_idx;
}

bool matches_trigger_input(const circuit& net,
                           int input_idx,
                           int trigger_idx,
                           int expected_value,
                           GType gtype) {
  bool needs_invert = false;
  if (gtype == GType::XOR) {
    needs_invert = (expected_value == 0);
  } else if (gtype == GType::XNOR) {
    needs_invert = (expected_value != 0);
  } else {
    return false;
  }

  if (!needs_invert) {
    return input_idx == trigger_idx;
  }
  return is_not_gate_of(net, input_idx, trigger_idx);
}

bool apply_rule_bypass(circuit& net,
                       const std::vector<int>& feature_nodes,
                       const DecisionTreeModel& model,
                       int fix_idx,
                       std::size_t base_nodes,
                       bool* applied,
                       std::string* error) {
  if (error) {
    error->clear();
  }
  if (applied) {
    *applied = false;
  }
  if (fix_idx < 0 || static_cast<std::size_t>(fix_idx) >= net.node_count()) {
    if (error) {
      *error = "fix node index out of range";
    }
    return false;
  }

  int trigger_idx = -1;
  int expected_value = 0;
  std::string trigger_error;
  if (!extract_single_literal_trigger(feature_nodes,
                                      model,
                                      &trigger_idx,
                                      &expected_value,
                                      &trigger_error)) {
    if (!trigger_error.empty()) {
      if (error) {
        *error = trigger_error;
      }
      return false;
    }
    return true;
  }

  const cell& fix_cell = net.get_cell(fix_idx);
  if (fix_cell.ctype != CType::GATE) {
    return true;
  }
  if (fix_cell.gtype != GType::XOR && fix_cell.gtype != GType::XNOR) {
    return true;
  }
  if (fix_cell.inputs.size() != 2U) {
    return true;
  }

  int bypass_idx = -1;
  int matches = 0;
  if (matches_trigger_input(net,
                            fix_cell.inputs[0],
                            trigger_idx,
                            expected_value,
                            fix_cell.gtype)) {
    bypass_idx = fix_cell.inputs[1];
    matches += 1;
  }
  if (matches_trigger_input(net,
                            fix_cell.inputs[1],
                            trigger_idx,
                            expected_value,
                            fix_cell.gtype)) {
    bypass_idx = fix_cell.inputs[0];
    matches += 1;
  }
  if (matches != 1) {
    return true;
  }
  if (bypass_idx < 0 ||
      static_cast<std::size_t>(bypass_idx) >= net.node_count()) {
    if (error) {
      *error = "bypass node index out of range";
    }
    return false;
  }

  net.replace_gate_inputs(fix_idx, bypass_idx, base_nodes);
  const auto& po_indices = net.po_indices();
  bool po_renamed = false;
  for (std::size_t pos = 0; pos < po_indices.size(); ++pos) {
    if (po_indices[pos] == fix_idx) {
      if (!po_renamed) {
        if (!preserve_po_name_on_replace(net, fix_idx, bypass_idx, error)) {
          return false;
        }
        po_renamed = true;
      }
      net.set_po_index(pos, bypass_idx);
    }
  }
  net.force_gate_const(fix_idx, 0);
  if (applied) {
    *applied = true;
  }
  return true;
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

std::string derive_rule_merged_path(const std::string& trojan_path) {
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
  return dir + base + "_rule_merged.bench";
}

bool append_rule_match_node(circuit& net,
                            const std::vector<int>& feature_nodes,
                            const DecisionTreeModel& model,
                            int* out_idx,
                            std::string* out_name,
                            std::string* error) {
  if (error) {
    error->clear();
  }
  if (out_idx) {
    *out_idx = -1;
  }
  if (out_name) {
    out_name->clear();
  }
  int match_idx = build_trigger_match_gate(net, feature_nodes, model, error);
  if (match_idx < 0) {
    return false;
  }
  const std::string name = make_unique_name(net, "rule_match_");
  net.define_gate(name, GType::BUFF, std::vector<int>{match_idx});
  const int created_idx = net.node_index(name);
  if (out_idx) {
    *out_idx = created_idx;
  }
  if (out_name) {
    *out_name = name;
  }
  return true;
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
  bool po_renamed = false;
  for (std::size_t pos = 0; pos < po_indices.size(); ++pos) {
    if (po_indices[pos] == fix_idx) {
      if (!po_renamed) {
        if (!preserve_po_name_on_replace(net, fix_idx, xor_idx, error)) {
          return false;
        }
        po_renamed = true;
      }
      net.set_po_index(pos, xor_idx);
    }
  }
  return true;
}

bool apply_rule_patch(circuit& net,
                      const std::vector<int>& feature_nodes,
                      const DecisionTreeModel& model,
                      int fix_idx,
                      std::size_t base_nodes,
                      bool* used_bypass,
                      std::string* error) {
  if (used_bypass) {
    *used_bypass = false;
  }
  bool bypass_applied = false;
  if (!apply_rule_bypass(net,
                         feature_nodes,
                         model,
                         fix_idx,
                         base_nodes,
                         &bypass_applied,
                         error)) {
    return false;
  }
  if (bypass_applied) {
    if (used_bypass) {
      *used_bypass = true;
    }
    return true;
  }

  return apply_rule_inversion(net, feature_nodes, model, fix_idx, base_nodes, error);
}

bool try_kill_simple_trigger(circuit& net,
                             const std::vector<int>& feature_nodes,
                             const DecisionTreeModel& model,
                             int* trigger_idx,
                             int* forced_value,
                             std::string* error) {
  if (error) {
    error->clear();
  }
  if (trigger_idx) {
    *trigger_idx = -1;
  }
  if (forced_value) {
    *forced_value = 0;
  }
  int trigger_node = -1;
  int expected = 0;
  std::string trigger_error;
  if (!extract_single_literal_trigger(feature_nodes,
                                      model,
                                      &trigger_node,
                                      &expected,
                                      &trigger_error)) {
    if (error && !trigger_error.empty()) {
      *error = trigger_error;
    }
    return false;
  }
  if (trigger_node < 0 ||
      static_cast<std::size_t>(trigger_node) >= net.node_count()) {
    if (error) {
      *error = "trigger node index out of range";
    }
    return false;
  }
  const cell& c = net.get_cell(trigger_node);
  if (c.ctype != CType::GATE) {
    if (error) {
      *error = "trigger node is not a gate";
    }
    return false;
  }
  // Virtual nodes (vn_*) are floating gates whose output is not connected
  // to any part of the original circuit.  Forcing them to a constant does
  // not neutralise the trojan, so reject them here and let the caller fall
  // through to a payload-fix approach that patches the real trigger gates.
  const std::string& name = net.node_name(trigger_node);
  if (name.size() >= 3 && name[0] == 'v' && name[1] == 'n' && name[2] == '_') {
    // Report which VN was identified so the caller can expand it.
    if (trigger_idx) {
      *trigger_idx = trigger_node;
    }
    if (forced_value) {
      *forced_value = expected ? 0 : 1;
    }
    if (error) {
      *error = "trigger is a virtual node (cannot kill directly)";
    }
    return false;
  }
  const int kill_value = expected ? 0 : 1;
  net.force_gate_const(trigger_node, kill_value);
  if (trigger_idx) {
    *trigger_idx = trigger_node;
  }
  if (forced_value) {
    *forced_value = kill_value;
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
  if (!apply_rule_patch(candidate,
                        feature_nodes,
                        model,
                        fix_idx,
                        base_nodes,
                        nullptr,
                        error)) {
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

#ifdef USE_CUDA
  // ── GPU path: batch patterns into GPU word blocks ──────────────────────────
  if (golden.node_count() >= 50000) try {
    circuit golden_copy = golden;
    circuit patched_copy = patched;
    golden_copy.ensure_eval_order();
    patched_copy.ensure_eval_order();

    const std::size_t num_pis = golden.pi_count();
    const std::size_t max_wb = gpu_compute_max_word_blocks(
        golden_copy.node_count(), patched_copy.node_count(), num_pis, 0);

    GpuCircuit gpu_golden(golden_copy, max_wb);
    GpuCircuit gpu_patched(patched_copy, max_wb);

    // Allocate device buffers for PI bits and diff_mask
    GpuCircuit::word_t* d_pi_bits = nullptr;
    GpuCircuit::word_t* d_diff_mask = nullptr;
    cudaMalloc(&d_pi_bits, num_pis * max_wb * sizeof(GpuCircuit::word_t));
    cudaMalloc(&d_diff_mask, max_wb * sizeof(GpuCircuit::word_t));

    constexpr std::size_t kBits = 64;
    const std::size_t total = patterns.size();
    std::size_t offset = 0;

    while (offset < total) {
      const std::size_t chunk = std::min(max_wb * kBits, total - offset);
      const std::size_t chunk_wb = (chunk + kBits - 1) / kBits;
      const GpuCircuit::word_t pmask =
          (chunk % kBits == 0) ? ~GpuCircuit::word_t(0)
                               : (GpuCircuit::word_t(1) << (chunk % kBits)) - 1;

      // Pack patterns into PI bit layout
      std::vector<GpuCircuit::word_t> h_pi(num_pis * chunk_wb, 0);
      gpu_pack_pi_patterns(patterns, offset, chunk, num_pis,
                           h_pi.data(), chunk_wb);

      cudaMemcpy(d_pi_bits, h_pi.data(),
                 num_pis * chunk_wb * sizeof(GpuCircuit::word_t),
                 cudaMemcpyHostToDevice);

      gpu_golden.simulate(d_pi_bits, chunk_wb);
      gpu_patched.simulate(d_pi_bits, chunk_wb);
      gpu_compare_po(gpu_golden, gpu_patched, d_diff_mask, chunk_wb, pmask);

      // Download diff_mask and check
      std::vector<GpuCircuit::word_t> h_diff(chunk_wb);
      cudaMemcpy(h_diff.data(), d_diff_mask,
                 chunk_wb * sizeof(GpuCircuit::word_t),
                 cudaMemcpyDeviceToHost);

      for (std::size_t w = 0; w < chunk_wb; ++w) {
        if (h_diff[w] != 0) {
          const std::size_t bit = static_cast<std::size_t>(
              __builtin_ctzll(h_diff[w]));
          const std::size_t idx = offset + w * kBits + bit;
          if (mismatch_index) *mismatch_index = idx;
          if (error) *error = "groundtruth mismatch";
          cudaFree(d_pi_bits);
          cudaFree(d_diff_mask);
          return false;
        }
      }

      offset += chunk;
    }

    cudaFree(d_pi_bits);
    cudaFree(d_diff_mask);
    return true;
  } catch (...) {
    // GPU failed — fall through to CPU path
  }
#endif

  // ── CPU fallback ───────────────────────────────────────────────────────────
  circuit golden_eval = golden;
  circuit patched_eval = patched;
  packed_circuit golden_packed(golden_eval);
  packed_circuit patched_packed(patched_eval);
  std::size_t offset = 0;
  while (offset < patterns.size()) {
    const std::size_t remaining = patterns.size() - offset;
    const std::size_t block_size =
        std::min(packed_circuit::kWordBits, remaining);
    std::vector<std::vector<int>> block;
    block.reserve(block_size);
    for (std::size_t p = 0; p < block_size; ++p) {
      block.push_back(patterns[offset + p]);
    }

    bool packed_ok = false;
    try {
      golden_packed.simulate(block);
      patched_packed.simulate(block);
      packed_ok = true;
    } catch (const std::exception& e) {
      if (error) {
        *error = e.what();
      }
    }

    if (!packed_ok) {
      for (std::size_t p = 0; p < block.size(); ++p) {
        try {
          const std::vector<int> g_out = golden_eval.simulate(block[p]);
          const std::vector<int> p_out = patched_eval.simulate(block[p]);
          if (g_out != p_out) {
            if (mismatch_index) {
              *mismatch_index = offset + p;
            }
            if (error) {
              *error = "groundtruth mismatch";
            }
            return false;
          }
        } catch (const std::exception& e) {
          if (mismatch_index) {
            *mismatch_index = offset + p;
          }
          if (error) {
            *error = e.what();
          }
          return false;
        }
      }
      offset += block_size;
      continue;
    }

    packed_circuit::word_t diff_mask = 0;
    for (std::size_t o = 0; o < golden_eval.po_count(); ++o) {
      diff_mask |= (golden_packed.po_bits(o) ^ patched_packed.po_bits(o));
    }
    diff_mask &= packed_circuit::mask_for_count(block_size);
    if (diff_mask != 0) {
      const std::size_t bit =
          static_cast<std::size_t>(__builtin_ctzll(diff_mask));
      if (mismatch_index) {
        *mismatch_index = offset + bit;
      }
      if (error) {
        *error = "groundtruth mismatch";
      }
      return false;
    }

    offset += block_size;
  }

  return true;
}
