#include "virtual_node.hpp"

#include <algorithm>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>

void generate_virtual_candidates(
    const std::vector<int>& base_candidates,
    std::size_t max_arity,
    std::vector<VirtualNodeDef>* out) {
  if (!out) {
    return;
  }
  out->clear();

  const std::size_t n = base_candidates.size();
  if (n < 2) {
    return;
  }

  // Pairwise AND with all 4 polarity combinations.
  // OR variants are omitted because AND(NOT a, NOT b) = NOR(a,b)
  // and the tree can split on feature=0 which is equivalent to NOT.
  // So AND with all polarities covers the same information as OR.
  for (std::size_t i = 0; i < n; ++i) {
    for (std::size_t j = i + 1; j < n; ++j) {
      const int a = base_candidates[i];
      const int b = base_candidates[j];
      for (int pa = 0; pa < 2; ++pa) {
        for (int pb = 0; pb < 2; ++pb) {
          out->push_back(VirtualNodeDef{
              GType::AND,
              {{a, pa != 0}, {b, pb != 0}}});
        }
      }
    }
  }

  // Triple AND combinations (if max_arity >= 3 and feasible count).
  if (max_arity >= 3 && n >= 3) {
    // Only generate triples if the count is manageable (< 5000).
    const std::size_t triple_count = n * (n - 1) * (n - 2) / 6;
    if (triple_count * 8 <= 5000) {
      for (std::size_t i = 0; i < n; ++i) {
        for (std::size_t j = i + 1; j < n; ++j) {
          for (std::size_t k = j + 1; k < n; ++k) {
            const int a = base_candidates[i];
            const int b = base_candidates[j];
            const int c = base_candidates[k];
            for (int pa = 0; pa < 2; ++pa) {
              for (int pb = 0; pb < 2; ++pb) {
                for (int pc = 0; pc < 2; ++pc) {
                  out->push_back(VirtualNodeDef{
                      GType::AND,
                      {{a, pa != 0}, {b, pb != 0}, {c, pc != 0}}});
                }
              }
            }
          }
        }
      }
    }
  }
}

std::vector<int> add_virtual_gates_to_circuit(
    circuit& net,
    const std::vector<VirtualNodeDef>& defs) {
  // Cache NOT gates per original signal to avoid duplicates.
  std::unordered_map<int, int> not_cache;

  auto get_input = [&](int node_idx, bool inverted) -> int {
    if (!inverted) {
      return node_idx;
    }
    auto it = not_cache.find(node_idx);
    if (it != not_cache.end()) {
      return it->second;
    }
    const int not_idx =
        net.add_gate_auto("vn_not_", GType::NOT, {node_idx});
    not_cache[node_idx] = not_idx;
    return not_idx;
  };

  std::vector<int> result;
  result.reserve(defs.size());

  for (const auto& def : defs) {
    std::vector<int> actual_inputs;
    actual_inputs.reserve(def.inputs.size());
    for (const auto& inp : def.inputs) {
      actual_inputs.push_back(get_input(inp.first, inp.second));
    }
    const int gate_idx =
        net.add_gate_auto("vn_", def.op, actual_inputs);
    result.push_back(gate_idx);
  }

  return result;
}

std::vector<packed_circuit::word_t> compute_virtual_feature_bits(
    const packed_circuit& packed,
    const std::vector<VirtualNodeDef>& defs,
    packed_circuit::word_t pattern_mask) {
  std::vector<packed_circuit::word_t> result;
  result.reserve(defs.size());
  for (const auto& def : defs) {
    packed_circuit::word_t val = 0;
    if (def.op == GType::AND) {
      val = pattern_mask;  // Start with all-1s for AND.
      for (const auto& inp : def.inputs) {
        packed_circuit::word_t bits = packed.node_bits(inp.first);
        if (inp.second) {
          bits = (~bits) & pattern_mask;
        }
        val &= bits;
      }
    } else if (def.op == GType::OR) {
      val = 0;  // Start with all-0s for OR.
      for (const auto& inp : def.inputs) {
        packed_circuit::word_t bits = packed.node_bits(inp.first);
        if (inp.second) {
          bits = (~bits) & pattern_mask;
        }
        val |= bits;
      }
    } else if (def.op == GType::NOT && !def.inputs.empty()) {
      packed_circuit::word_t bits = packed.node_bits(def.inputs[0].first);
      val = (~bits) & pattern_mask;
    }
    result.push_back(val);
  }
  return result;
}

int compute_virtual_feature_value(
    const circuit& c,
    const VirtualNodeDef& def) {
  if (def.op == GType::AND) {
    for (const auto& inp : def.inputs) {
      int v = c.get_cell(inp.first).val;
      if (inp.second) v = !v;
      if (!v) return 0;
    }
    return 1;
  }
  if (def.op == GType::OR) {
    for (const auto& inp : def.inputs) {
      int v = c.get_cell(inp.first).val;
      if (inp.second) v = !v;
      if (v) return 1;
    }
    return 0;
  }
  if (def.op == GType::NOT && !def.inputs.empty()) {
    return !c.get_cell(def.inputs[0].first).val;
  }
  return 0;
}

std::vector<int> find_used_virtual_gate_indices(
    const std::vector<int>& feature_nodes,
    const DecisionTreeModel& model,
    std::size_t original_node_count) {
  std::unordered_set<int> used;
  for (const auto& rule : model.rules) {
    for (const auto& term : rule.terms) {
      const std::size_t fidx = term.first;
      if (fidx < feature_nodes.size()) {
        const int node_idx = feature_nodes[fidx];
        if (node_idx >= static_cast<int>(original_node_count)) {
          used.insert(node_idx);
        }
      }
    }
  }
  std::vector<int> sorted(used.begin(), used.end());
  std::sort(sorted.begin(), sorted.end());
  return sorted;
}

namespace {

// Canonical key for a subclause: sorted list of (circuit_node, inverted).
// Format: "node1+node2~node3+" where + means not-inverted, ~ means inverted.
std::string subclause_key(
    const std::vector<std::pair<int, bool>>& lits) {
  // Copy and sort by (node, inverted).
  auto sorted = lits;
  std::sort(sorted.begin(), sorted.end(),
            [](const std::pair<int, bool>& a,
               const std::pair<int, bool>& b) {
              if (a.first != b.first) return a.first < b.first;
              return a.second < b.second;
            });
  std::string key;
  for (const auto& lit : sorted) {
    key += std::to_string(lit.first);
    key += lit.second ? '~' : '+';
  }
  return key;
}

// Enumerate all k-subsets of `items` and call `callback` for each.
void enumerate_subsets(
    const std::vector<std::pair<int, bool>>& items,
    std::size_t k,
    const std::function<void(const std::vector<std::pair<int, bool>>&)>& callback) {
  const std::size_t n = items.size();
  if (k > n || k == 0) return;

  std::vector<std::size_t> indices(k);
  for (std::size_t i = 0; i < k; ++i) {
    indices[i] = i;
  }

  while (true) {
    std::vector<std::pair<int, bool>> subset;
    subset.reserve(k);
    for (std::size_t idx : indices) {
      subset.push_back(items[idx]);
    }
    callback(subset);

    // Advance to next combination.
    std::size_t pos = k;
    while (pos > 0) {
      --pos;
      if (indices[pos] + (k - pos) < n) {
        ++indices[pos];
        for (std::size_t j = pos + 1; j < k; ++j) {
          indices[j] = indices[j - 1] + 1;
        }
        break;
      }
      if (pos == 0) return;  // All combinations exhausted.
    }
  }
}

}  // namespace

void mine_subclauses_from_rules(
    const std::vector<int>& feature_nodes,
    const DecisionTreeModel& model,
    std::size_t min_len,
    std::size_t max_len,
    std::size_t max_candidates,
    const std::vector<VirtualNodeDef>& existing_vn,
    std::vector<VirtualNodeDef>* out,
    std::size_t first_virtual_idx) {
  if (!out) return;
  out->clear();
  if (model.rules.empty() || min_len < 2) return;

  // Build set of existing virtual node keys for deduplication.
  std::unordered_set<std::string> existing_keys;
  for (const auto& vn : existing_vn) {
    existing_keys.insert(subclause_key(vn.inputs));
  }

  // Count frequency of each subclause across all rules.
  std::unordered_map<std::string, std::size_t> freq;
  std::unordered_map<std::string, std::vector<std::pair<int, bool>>> key_to_lits;

  // Maximum number of real (non-virtual) terms to consider per rule.
  // Prevents combinatorial explosion on long rules.
  const std::size_t max_terms_per_rule = 12;

  for (const auto& rule : model.rules) {
    // Convert rule terms to (circuit_node, inverted) literals.
    // Skip virtual features (index >= first_virtual_idx) to prevent
    // VN-on-VN composition which causes uncontrolled layering.
    std::vector<std::pair<int, bool>> lits;
    for (const auto& term : rule.terms) {
      // Skip virtual features if first_virtual_idx is set.
      if (first_virtual_idx > 0 && term.first >= first_virtual_idx) {
        continue;
      }
      if (term.first < feature_nodes.size()) {
        lits.emplace_back(feature_nodes[term.first],
                          term.second == 0);
      }
    }

    // Truncate to max_terms_per_rule to avoid subset explosion.
    if (lits.size() > max_terms_per_rule) {
      lits.resize(max_terms_per_rule);
    }

    // Enumerate subclauses of each length.
    // Use a set to avoid counting duplicate subclauses within one rule.
    std::unordered_set<std::string> seen_in_rule;
    for (std::size_t k = min_len; k <= std::min(max_len, lits.size()); ++k) {
      enumerate_subsets(lits, k,
                        [&](const std::vector<std::pair<int, bool>>& subset) {
        std::string key = subclause_key(subset);
        if (existing_keys.count(key)) return;  // Skip existing.
        if (seen_in_rule.insert(key).second) {
          freq[key]++;
          if (key_to_lits.find(key) == key_to_lits.end()) {
            key_to_lits[key] = subset;
          }
        }
      });
    }
  }

  // Sort by frequency (descending), then by key for determinism.
  std::vector<std::pair<std::string, std::size_t>> sorted_entries(
      freq.begin(), freq.end());
  std::sort(sorted_entries.begin(), sorted_entries.end(),
            [](const std::pair<std::string, std::size_t>& a,
               const std::pair<std::string, std::size_t>& b) {
              if (a.second != b.second) return a.second > b.second;
              return a.first < b.first;
            });

  // Only keep subclauses that appear in at least 2 rules.
  std::size_t count = 0;
  for (const auto& entry : sorted_entries) {
    if (count >= max_candidates) break;
    if (entry.second < 2) break;  // Frequency < 2, not useful.
    const auto& lits = key_to_lits[entry.first];
    VirtualNodeDef def;
    def.op = GType::AND;
    def.inputs = lits;
    out->push_back(std::move(def));
    ++count;
  }
}
