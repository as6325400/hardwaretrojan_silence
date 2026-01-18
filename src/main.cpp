#include <algorithm>
#include <atomic>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <z3++.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "algorithm/candidate_selector.hpp"
#include "algorithm/miner.hpp"
#include "algorithm/pattern_sampler.hpp"
#include "algorithm/trigger_fixer.hpp"
#include "core/circuit_compare.hpp"
#include "core/packed_circuit.hpp"
#include "io/bench_parser.hpp"
#include "io/bench_writer.hpp"
#include "io/cli_options.hpp"
#include "io/parallel_collect_log.hpp"

using namespace std;

namespace {

std::uint64_t popcount_ull(packed_circuit::word_t value) {
  return static_cast<std::uint64_t>(__builtin_popcountll(value));
}

packed_circuit::word_t take_first_bits(packed_circuit::word_t mask,
                                       size_t count) {
  packed_circuit::word_t out = 0;
  while (mask && count > 0) {
    const packed_circuit::word_t lsb = mask & (~mask + 1ULL);
    out |= lsb;
    mask &= (mask - 1);
    count -= 1;
  }
  return out;
}

struct SimState {
  std::vector<int> values;
  std::vector<int> outputs;
};

SimState simulate_with_override(circuit& c,
                                const std::vector<int>& pi_values,
                                int override_idx,
                                int override_value) {
  c.ensure_eval_order();
  const auto& pi_indices = c.pi_indices();
  if (pi_values.size() != pi_indices.size()) {
    throw std::runtime_error("PI vector size mismatch");
  }

  SimState state;
  state.values.assign(c.node_count(), -1);

  for (std::size_t i = 0; i < c.node_count(); ++i) {
    const cell& cell = c.get_cell(static_cast<int>(i));
    if (cell.ctype == CType::CONST) {
      state.values[i] = cell.val ? 1 : 0;
    }
  }

  for (std::size_t i = 0; i < pi_indices.size(); ++i) {
    state.values[static_cast<std::size_t>(pi_indices[i])] =
        pi_values[i] ? 1 : 0;
  }

  if (override_idx >= 0 &&
      static_cast<std::size_t>(override_idx) < state.values.size()) {
    state.values[static_cast<std::size_t>(override_idx)] =
        override_value ? 1 : 0;
  }

  for (int idx : c.eval_order()) {
    if (override_idx == idx) {
      continue;
    }
    const cell& gate = c.get_cell(idx);
    if (gate.ctype != CType::GATE) {
      continue;
    }
    if (gate.inputs.empty()) {
      throw std::runtime_error("gate with no inputs: " + c.node_name(idx));
    }
    auto read_input = [&](int input_idx) -> int {
      if (input_idx < 0 ||
          static_cast<std::size_t>(input_idx) >= state.values.size()) {
        throw std::runtime_error("input index out of range for node: " +
                                 c.node_name(idx));
      }
      int val = state.values[static_cast<std::size_t>(input_idx)];
      if (val < 0) {
        throw std::runtime_error("uninitialized input for node: " +
                                 c.node_name(idx));
      }
      return val ? 1 : 0;
    };

    int out = 0;
    switch (gate.gtype) {
      case GType::AND: {
        out = 1;
        for (int input_idx : gate.inputs) {
          out &= read_input(input_idx);
        }
        break;
      }
      case GType::OR: {
        out = 0;
        for (int input_idx : gate.inputs) {
          out |= read_input(input_idx);
        }
        break;
      }
      case GType::NAND: {
        out = 1;
        for (int input_idx : gate.inputs) {
          out &= read_input(input_idx);
        }
        out = out ? 0 : 1;
        break;
      }
      case GType::NOR: {
        out = 0;
        for (int input_idx : gate.inputs) {
          out |= read_input(input_idx);
        }
        out = out ? 0 : 1;
        break;
      }
      case GType::NOT: {
        if (gate.inputs.size() != 1U) {
          throw std::runtime_error("NOT gate expects 1 input: " + c.node_name(idx));
        }
        out = read_input(gate.inputs[0]) ? 0 : 1;
        break;
      }
      case GType::BUFF: {
        if (gate.inputs.size() != 1U) {
          throw std::runtime_error("BUFF gate expects 1 input: " + c.node_name(idx));
        }
        out = read_input(gate.inputs[0]);
        break;
      }
      case GType::XOR: {
        out = 0;
        for (int input_idx : gate.inputs) {
          out ^= read_input(input_idx);
        }
        break;
      }
      case GType::XNOR: {
        out = 0;
        for (int input_idx : gate.inputs) {
          out ^= read_input(input_idx);
        }
        out = out ? 0 : 1;
        break;
      }
    }
    state.values[static_cast<std::size_t>(idx)] = out;
  }

  state.outputs.reserve(c.po_count());
  for (int idx : c.po_indices()) {
    int val = state.values[static_cast<std::size_t>(idx)];
    if (val < 0) {
      throw std::runtime_error("output not evaluated: " + c.node_name(idx));
    }
    state.outputs.push_back(val);
  }

  return state;
}

void mark_fanin_cone(const circuit& c,
                     int node_idx,
                     std::vector<char>* cone) {
  if (!cone) {
    return;
  }
  if (node_idx < 0 ||
      static_cast<std::size_t>(node_idx) >= cone->size()) {
    throw std::runtime_error("fan-in node index out of range");
  }
  std::vector<int> stack;
  stack.push_back(node_idx);
  while (!stack.empty()) {
    int idx = stack.back();
    stack.pop_back();
    if (idx < 0 ||
        static_cast<std::size_t>(idx) >= cone->size()) {
      throw std::runtime_error("fan-in node index out of range");
    }
    if ((*cone)[static_cast<std::size_t>(idx)]) {
      continue;
    }
    (*cone)[static_cast<std::size_t>(idx)] = 1;
    const cell& cnode = c.get_cell(idx);
    if (cnode.ctype == CType::GATE) {
      for (int input_idx : cnode.inputs) {
        stack.push_back(input_idx);
      }
    }
  }
}

void intersect_in_place(std::vector<char>& target,
                        const std::vector<char>& other) {
  if (target.size() != other.size()) {
    throw std::runtime_error("intersection size mismatch");
  }
  for (std::size_t i = 0; i < target.size(); ++i) {
    target[i] = (target[i] && other[i]) ? 1 : 0;
  }
}

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

std::vector<int> extract_features_from_values(
    const std::vector<int>& values,
    const std::vector<int>& feature_nodes) {
  std::vector<int> row;
  row.reserve(feature_nodes.size());
  for (int idx : feature_nodes) {
    if (idx < 0 || static_cast<std::size_t>(idx) >= values.size()) {
      row.push_back(0);
    } else {
      row.push_back(values[static_cast<std::size_t>(idx)] ? 1 : 0);
    }
  }
  return row;
}

struct PackedValues {
  std::vector<packed_circuit::word_t> values;
  packed_circuit::word_t mask = 0;
};

PackedValues simulate_packed_values(circuit& c,
                                    const std::vector<packed_circuit::word_t>& pi_bits,
                                    std::size_t pattern_count) {
  if (pattern_count > packed_circuit::kWordBits) {
    throw std::runtime_error("pattern count exceeds 64");
  }

  PackedValues out;
  out.mask = packed_circuit::mask_for_count(pattern_count);
  out.values.assign(c.node_count(), 0);

  c.ensure_eval_order();
  const auto& pi_indices = c.pi_indices();
  if (pi_bits.size() != pi_indices.size()) {
    throw std::runtime_error("PI vector size mismatch");
  }

  for (std::size_t i = 0; i < pi_indices.size(); ++i) {
    const int idx = pi_indices[i];
    if (idx < 0 || static_cast<std::size_t>(idx) >= out.values.size()) {
      throw std::runtime_error("PI index out of range");
    }
    out.values[static_cast<std::size_t>(idx)] = pi_bits[i] & out.mask;
  }

  for (std::size_t idx = 0; idx < c.node_count(); ++idx) {
    const cell& node = c.get_cell(static_cast<int>(idx));
    if (node.ctype == CType::CONST) {
      out.values[idx] = node.val ? out.mask : packed_circuit::word_t(0);
    }
  }

  for (int idx : c.eval_order()) {
    if (idx < 0 || static_cast<std::size_t>(idx) >= out.values.size()) {
      throw std::runtime_error("gate index out of range");
    }
    const cell& node = c.get_cell(idx);
    if (node.ctype != CType::GATE) {
      continue;
    }
    if (node.inputs.empty()) {
      throw std::runtime_error("gate with no inputs: " + c.node_name(idx));
    }

    packed_circuit::word_t value = 0;
    switch (node.gtype) {
      case GType::AND: {
        value = out.mask;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= out.values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value &= out.values[static_cast<std::size_t>(input_idx)];
        }
        break;
      }
      case GType::OR: {
        value = 0;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= out.values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value |= out.values[static_cast<std::size_t>(input_idx)];
        }
        break;
      }
      case GType::NAND: {
        value = out.mask;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= out.values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value &= out.values[static_cast<std::size_t>(input_idx)];
        }
        value = (~value) & out.mask;
        break;
      }
      case GType::NOR: {
        value = 0;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= out.values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value |= out.values[static_cast<std::size_t>(input_idx)];
        }
        value = (~value) & out.mask;
        break;
      }
      case GType::NOT: {
        if (node.inputs.size() != 1U) {
          throw std::runtime_error("NOT gate expects 1 input: " +
                                   c.node_name(idx));
        }
        const int input_idx = node.inputs[0];
        if (input_idx < 0 ||
            static_cast<std::size_t>(input_idx) >= out.values.size()) {
          throw std::runtime_error("gate input index out of range");
        }
        value = (~out.values[static_cast<std::size_t>(input_idx)]) & out.mask;
        break;
      }
      case GType::BUFF: {
        if (node.inputs.size() != 1U) {
          throw std::runtime_error("BUFF gate expects 1 input: " +
                                   c.node_name(idx));
        }
        const int input_idx = node.inputs[0];
        if (input_idx < 0 ||
            static_cast<std::size_t>(input_idx) >= out.values.size()) {
          throw std::runtime_error("gate input index out of range");
        }
        value = out.values[static_cast<std::size_t>(input_idx)];
        break;
      }
      case GType::XOR: {
        value = 0;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= out.values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value ^= out.values[static_cast<std::size_t>(input_idx)];
        }
        break;
      }
      case GType::XNOR: {
        value = 0;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= out.values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value ^= out.values[static_cast<std::size_t>(input_idx)];
        }
        value = (~value) & out.mask;
        break;
      }
    }
    out.values[static_cast<std::size_t>(idx)] = value;
  }

  return out;
}

std::vector<packed_circuit::word_t> simulate_packed_with_flip(
    circuit& c,
    const std::vector<packed_circuit::word_t>& base_values,
    const std::vector<char>& fanout_cone,
    int flip_idx,
    packed_circuit::word_t flip_bits,
    packed_circuit::word_t mask) {
  if (base_values.size() != c.node_count()) {
    throw std::runtime_error("base value size mismatch");
  }
  if (fanout_cone.size() != c.node_count()) {
    throw std::runtime_error("fanout cone size mismatch");
  }
  if (flip_idx < 0 || static_cast<std::size_t>(flip_idx) >= c.node_count()) {
    throw std::runtime_error("flip node index out of range");
  }

  std::vector<packed_circuit::word_t> values = base_values;
  values[static_cast<std::size_t>(flip_idx)] = flip_bits & mask;

  c.ensure_eval_order();
  for (int idx : c.eval_order()) {
    if (idx < 0 || static_cast<std::size_t>(idx) >= values.size()) {
      throw std::runtime_error("gate index out of range");
    }
    if (idx == flip_idx) {
      continue;
    }
    if (!fanout_cone[static_cast<std::size_t>(idx)]) {
      continue;
    }
    const cell& node = c.get_cell(idx);
    if (node.ctype != CType::GATE) {
      continue;
    }
    if (node.inputs.empty()) {
      throw std::runtime_error("gate with no inputs: " + c.node_name(idx));
    }

    packed_circuit::word_t value = 0;
    switch (node.gtype) {
      case GType::AND: {
        value = mask;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value &= values[static_cast<std::size_t>(input_idx)];
        }
        break;
      }
      case GType::OR: {
        value = 0;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value |= values[static_cast<std::size_t>(input_idx)];
        }
        break;
      }
      case GType::NAND: {
        value = mask;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value &= values[static_cast<std::size_t>(input_idx)];
        }
        value = (~value) & mask;
        break;
      }
      case GType::NOR: {
        value = 0;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value |= values[static_cast<std::size_t>(input_idx)];
        }
        value = (~value) & mask;
        break;
      }
      case GType::NOT: {
        if (node.inputs.size() != 1U) {
          throw std::runtime_error("NOT gate expects 1 input: " +
                                   c.node_name(idx));
        }
        const int input_idx = node.inputs[0];
        if (input_idx < 0 ||
            static_cast<std::size_t>(input_idx) >= values.size()) {
          throw std::runtime_error("gate input index out of range");
        }
        value = (~values[static_cast<std::size_t>(input_idx)]) & mask;
        break;
      }
      case GType::BUFF: {
        if (node.inputs.size() != 1U) {
          throw std::runtime_error("BUFF gate expects 1 input: " +
                                   c.node_name(idx));
        }
        const int input_idx = node.inputs[0];
        if (input_idx < 0 ||
            static_cast<std::size_t>(input_idx) >= values.size()) {
          throw std::runtime_error("gate input index out of range");
        }
        value = values[static_cast<std::size_t>(input_idx)];
        break;
      }
      case GType::XOR: {
        value = 0;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value ^= values[static_cast<std::size_t>(input_idx)];
        }
        break;
      }
      case GType::XNOR: {
        value = 0;
        for (int input_idx : node.inputs) {
          if (input_idx < 0 ||
              static_cast<std::size_t>(input_idx) >= values.size()) {
            throw std::runtime_error("gate input index out of range");
          }
          value ^= values[static_cast<std::size_t>(input_idx)];
        }
        value = (~value) & mask;
        break;
      }
    }
    values[static_cast<std::size_t>(idx)] = value;
  }

  return values;
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

std::vector<z3::expr> make_node_vars(z3::context& ctx,
                                     const std::string& prefix,
                                     std::size_t count) {
  std::vector<z3::expr> vars;
  vars.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    vars.push_back(ctx.bool_const((prefix + std::to_string(i)).c_str()));
  }
  return vars;
}

bool build_gate_expr(const cell& gate,
                     const std::vector<z3::expr>& vars,
                     z3::expr* out,
                     std::string* error) {
  if (!out) {
    if (error) {
      *error = "Gate expression output is null";
    }
    return false;
  }
  if (gate.inputs.empty()) {
    if (error) {
      *error = "gate with no inputs";
    }
    return false;
  }
  auto read_input = [&](int input_idx) -> z3::expr {
    if (input_idx < 0 || static_cast<std::size_t>(input_idx) >= vars.size()) {
      throw std::runtime_error("gate input index out of range");
    }
    return vars[static_cast<std::size_t>(input_idx)];
  };

  z3::expr acc = read_input(gate.inputs[0]);
  switch (gate.gtype) {
    case GType::AND: {
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        acc = acc && read_input(gate.inputs[i]);
      }
      *out = acc;
      return true;
    }
    case GType::OR: {
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        acc = acc || read_input(gate.inputs[i]);
      }
      *out = acc;
      return true;
    }
    case GType::NAND: {
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        acc = acc && read_input(gate.inputs[i]);
      }
      *out = !acc;
      return true;
    }
    case GType::NOR: {
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        acc = acc || read_input(gate.inputs[i]);
      }
      *out = !acc;
      return true;
    }
    case GType::NOT: {
      if (gate.inputs.size() != 1U) {
        if (error) {
          *error = "NOT gate expects 1 input";
        }
        return false;
      }
      *out = !read_input(gate.inputs[0]);
      return true;
    }
    case GType::BUFF: {
      if (gate.inputs.size() != 1U) {
        if (error) {
          *error = "BUFF gate expects 1 input";
        }
        return false;
      }
      *out = read_input(gate.inputs[0]);
      return true;
    }
    case GType::XOR: {
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        acc = (acc != read_input(gate.inputs[i]));
      }
      *out = acc;
      return true;
    }
    case GType::XNOR: {
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        acc = (acc != read_input(gate.inputs[i]));
      }
      *out = !acc;
      return true;
    }
  }

  if (error) {
    *error = "unsupported gate type";
  }
  return false;
}

std::vector<char> build_fanout_cone(const circuit& c, int start_idx) {
  if (start_idx < 0 ||
      static_cast<std::size_t>(start_idx) >= c.node_count()) {
    throw std::runtime_error("fanout start node out of range");
  }

  const std::size_t node_count = c.node_count();
  std::vector<std::vector<int>> fanout(node_count);
  for (std::size_t idx = 0; idx < node_count; ++idx) {
    const cell& node = c.get_cell(static_cast<int>(idx));
    if (node.ctype != CType::GATE) {
      continue;
    }
    for (int input_idx : node.inputs) {
      if (input_idx < 0 ||
          static_cast<std::size_t>(input_idx) >= node_count) {
        throw std::runtime_error("fanout input index out of range");
      }
      fanout[static_cast<std::size_t>(input_idx)].push_back(
          static_cast<int>(idx));
    }
  }

  std::vector<char> in_cone(node_count, 0);
  std::vector<int> stack;
  stack.push_back(start_idx);
  while (!stack.empty()) {
    int idx = stack.back();
    stack.pop_back();
    if (idx < 0 || static_cast<std::size_t>(idx) >= node_count) {
      throw std::runtime_error("fanout node index out of range");
    }
    if (in_cone[static_cast<std::size_t>(idx)]) {
      continue;
    }
    in_cone[static_cast<std::size_t>(idx)] = 1;
    for (int next_idx : fanout[static_cast<std::size_t>(idx)]) {
      stack.push_back(next_idx);
    }
  }

  return in_cone;
}

bool add_circuit_constraints(z3::context& ctx,
                             const circuit& c,
                             const std::vector<z3::expr>& vars,
                             const std::vector<z3::expr>& pi_vars,
                             z3::solver& solver,
                             int override_idx,
                             const std::vector<z3::expr>* orig_vars,
                             std::string* error) {
  if (vars.size() != c.node_count()) {
    if (error) {
      *error = "Variable count mismatch with circuit nodes";
    }
    return false;
  }

  std::vector<int> pi_pos_by_idx(c.node_count(), -1);
  const auto& pi_indices = c.pi_indices();
  if (pi_indices.size() != pi_vars.size()) {
    if (error) {
      *error = "PI variable count mismatch";
    }
    return false;
  }
  for (std::size_t pos = 0; pos < pi_indices.size(); ++pos) {
    const int idx = pi_indices[pos];
    if (idx < 0 || static_cast<std::size_t>(idx) >= pi_pos_by_idx.size()) {
      if (error) {
        *error = "PI index out of range";
      }
      return false;
    }
    pi_pos_by_idx[static_cast<std::size_t>(idx)] = static_cast<int>(pos);
  }

  for (std::size_t idx = 0; idx < c.node_count(); ++idx) {
    if (override_idx >= 0 &&
        static_cast<std::size_t>(override_idx) == idx) {
      if (!orig_vars) {
        if (error) {
          *error = "Override requires original variables";
        }
        return false;
      }
      solver.add(vars[idx] == !(*orig_vars)[idx]);
      continue;
    }

    const cell& node = c.get_cell(static_cast<int>(idx));
    switch (node.ctype) {
      case CType::CONST: {
        solver.add(vars[idx] == ctx.bool_val(node.val != 0));
        break;
      }
      case CType::PI: {
        const int pos = pi_pos_by_idx[idx];
        if (pos < 0 || static_cast<std::size_t>(pos) >= pi_vars.size()) {
          if (error) {
            *error = "PI position not found";
          }
          return false;
        }
        solver.add(vars[idx] == pi_vars[static_cast<std::size_t>(pos)]);
        break;
      }
      case CType::GATE: {
        z3::expr gate_expr = ctx.bool_val(false);
        try {
          if (!build_gate_expr(node, vars, &gate_expr, error)) {
            return false;
          }
        } catch (const std::exception& e) {
          if (error) {
            *error = e.what();
          }
          return false;
        }
        solver.add(vars[idx] == gate_expr);
        break;
      }
      case CType::UNDEF: {
        if (error) {
          *error = "Undefined node in circuit";
        }
        return false;
      }
    }
  }

  return true;
}

bool add_flipped_cone_constraints(z3::context& ctx,
                                  const circuit& c,
                                  const std::vector<z3::expr>& base_vars,
                                  const std::vector<z3::expr>& flip_vars,
                                  const std::vector<z3::expr>& pi_vars,
                                  const std::vector<char>& cone,
                                  int flip_idx,
                                  z3::solver& solver,
                                  std::string* error) {
  if (base_vars.size() != c.node_count() ||
      flip_vars.size() != c.node_count()) {
    if (error) {
      *error = "Variable count mismatch with circuit nodes";
    }
    return false;
  }
  if (cone.size() != c.node_count()) {
    if (error) {
      *error = "Cone size mismatch with circuit nodes";
    }
    return false;
  }
  if (flip_idx < 0 ||
      static_cast<std::size_t>(flip_idx) >= c.node_count()) {
    if (error) {
      *error = "Flip node index out of range";
    }
    return false;
  }
  if (!cone[static_cast<std::size_t>(flip_idx)]) {
    if (error) {
      *error = "Flip node not in fanout cone";
    }
    return false;
  }

  std::vector<z3::expr> mixed_vars = base_vars;
  for (std::size_t i = 0; i < cone.size(); ++i) {
    if (cone[i]) {
      mixed_vars[i] = flip_vars[i];
    }
  }

  std::vector<int> pi_pos_by_idx(c.node_count(), -1);
  const auto& pi_indices = c.pi_indices();
  if (pi_indices.size() != pi_vars.size()) {
    if (error) {
      *error = "PI variable count mismatch";
    }
    return false;
  }
  for (std::size_t pos = 0; pos < pi_indices.size(); ++pos) {
    const int idx = pi_indices[pos];
    if (idx < 0 || static_cast<std::size_t>(idx) >= pi_pos_by_idx.size()) {
      if (error) {
        *error = "PI index out of range";
      }
      return false;
    }
    pi_pos_by_idx[static_cast<std::size_t>(idx)] = static_cast<int>(pos);
  }

  for (std::size_t idx = 0; idx < c.node_count(); ++idx) {
    if (!cone[idx]) {
      continue;
    }
    if (static_cast<int>(idx) == flip_idx) {
      solver.add(flip_vars[idx] == !base_vars[idx]);
      continue;
    }

    const cell& node = c.get_cell(static_cast<int>(idx));
    switch (node.ctype) {
      case CType::CONST: {
        solver.add(flip_vars[idx] == ctx.bool_val(node.val != 0));
        break;
      }
      case CType::PI: {
        const int pos = pi_pos_by_idx[idx];
        if (pos < 0 || static_cast<std::size_t>(pos) >= pi_vars.size()) {
          if (error) {
            *error = "PI position not found";
          }
          return false;
        }
        solver.add(flip_vars[idx] == pi_vars[static_cast<std::size_t>(pos)]);
        break;
      }
      case CType::GATE: {
        z3::expr gate_expr = ctx.bool_val(false);
        try {
          if (!build_gate_expr(node, mixed_vars, &gate_expr, error)) {
            return false;
          }
        } catch (const std::exception& e) {
          if (error) {
            *error = e.what();
          }
          return false;
        }
        solver.add(flip_vars[idx] == gate_expr);
        break;
      }
      case CType::UNDEF: {
        if (error) {
          *error = "Undefined node in circuit";
        }
        return false;
      }
    }
  }

  return true;
}

bool collect_rule_counterexamples(
    const circuit& golden,
    const circuit& trojan,
    const MiningResult& result,
    std::size_t round_index,
    const std::unordered_set<std::string>& groundtruth_bits,
    std::unordered_set<std::string>* seen_bits,
    std::size_t max_models,
    std::size_t max_counterexamples,
    std::vector<std::vector<int>>* counterexamples,
    std::string* error) {
  if (error) {
    error->clear();
  }
  if (!counterexamples) {
    if (error) {
      *error = "counterexample output is null";
    }
    return false;
  }
  counterexamples->clear();
  if (result.model.rules.empty()) {
    return true;
  }
  if (max_models == 0 || max_counterexamples == 0) {
    return true;
  }

  const std::size_t report_step = 5000;
  const std::size_t pi_count = trojan.pi_count();
  std::size_t thread_count = 1;
#ifdef _OPENMP
  thread_count = static_cast<std::size_t>(omp_get_max_threads());
#else
  thread_count = std::thread::hardware_concurrency();
  if (thread_count == 0) {
    thread_count = 1;
  }
#endif

  std::size_t target_prefixes = thread_count * 16;
  if (target_prefixes == 0) {
    target_prefixes = 1;
  }
  std::size_t prefix_bits = 0;
  std::size_t prefix_count = 1;
  while (prefix_bits < pi_count && prefix_count < target_prefixes) {
    prefix_bits += 1;
    prefix_count <<= 1;
  }

  std::atomic<std::size_t> next_prefix(0);
  std::atomic<std::size_t> models_checked(0);
  std::atomic<std::size_t> counterexample_count(0);
  std::atomic<bool> stop_flag(false);
  std::atomic<bool> error_flag(false);
  std::mutex error_mutex;
  std::mutex progress_mutex;
  std::string shared_error;
  std::vector<std::size_t> prefix_counts(thread_count, 0);
  struct ThreadResult {
    std::vector<std::vector<int>> counterexamples;
    std::unordered_set<std::string> seen;
  };
  std::vector<ThreadResult> thread_results(thread_count);

  std::cout << "sat_enum_setup round " << round_index
            << " threads " << thread_count
            << " prefix_bits " << prefix_bits
            << " prefixes " << prefix_count
            << " target_prefixes " << target_prefixes
            << " max_models " << max_models
            << " max_new " << max_counterexamples << "\n";

  auto set_error = [&](const std::string& msg) {
    if (!error_flag.exchange(true)) {
      std::lock_guard<std::mutex> lock(error_mutex);
      shared_error = msg;
    }
    stop_flag.store(true);
  };

#ifdef _OPENMP
#pragma omp parallel
#endif
  {
    if (stop_flag.load()) {
      // Skip work if another thread already requested stop.
    } else {
      bool abort_thread = false;

      z3::context ctx;
      z3::solver solver(ctx);

      std::vector<z3::expr> pi_vars;
      pi_vars.reserve(pi_count);
      for (std::size_t i = 0; i < pi_count; ++i) {
        pi_vars.push_back(ctx.bool_const(("pi_" + std::to_string(i)).c_str()));
      }

      std::vector<z3::expr> trojan_vars =
          make_node_vars(ctx, "t_", trojan.node_count());

      std::string local_error;
      if (!add_circuit_constraints(ctx,
                                   trojan,
                                   trojan_vars,
                                   pi_vars,
                                   solver,
                                   -1,
                                   nullptr,
                                   &local_error)) {
        set_error(local_error);
        abort_thread = true;
      }

      z3::expr rule_expr = ctx.bool_val(false);
      if (!abort_thread) {
        for (const auto& rule : result.model.rules) {
          z3::expr term_expr = ctx.bool_val(true);
          for (const auto& term : rule.terms) {
            const std::size_t feature_idx = term.first;
            const int value = term.second;
            if (feature_idx >= result.feature_nodes.size()) {
              set_error("feature index out of range");
              abort_thread = true;
              break;
            }
            const int node_idx = result.feature_nodes[feature_idx];
            if (node_idx < 0 ||
                static_cast<std::size_t>(node_idx) >= trojan_vars.size()) {
              set_error("feature node index out of range");
              abort_thread = true;
              break;
            }
            term_expr =
                term_expr && (trojan_vars[static_cast<std::size_t>(node_idx)] ==
                              ctx.bool_val(value != 0));
          }
          if (abort_thread) {
            break;
          }
          rule_expr = rule_expr || term_expr;
        }
      }
      if (!abort_thread) {
        solver.add(rule_expr);
      }

      const auto& trojan_po_indices = trojan.po_indices();
      const auto& golden_po_indices = golden.po_indices();
      if (!abort_thread && trojan_po_indices.size() != golden_po_indices.size()) {
        set_error("PO count mismatch");
        abort_thread = true;
      }

      circuit golden_eval = golden;
      circuit trojan_eval = trojan;

      const std::size_t tid =
#ifdef _OPENMP
          static_cast<std::size_t>(omp_get_thread_num());
#else
          0U;
#endif
      std::size_t local_prefixes = 0;
      ThreadResult* local_result =
          (tid < thread_results.size()) ? &thread_results[tid] : nullptr;

      if (!abort_thread) {
        while (!stop_flag.load()) {
      const std::size_t prefix_idx = next_prefix.fetch_add(1);
      if (prefix_idx >= prefix_count) {
        break;
      }
      local_prefixes += 1;

      solver.push();
      for (std::size_t bit = 0; bit < prefix_bits; ++bit) {
        const bool value = ((prefix_idx >> bit) & 1U) != 0;
        solver.add(pi_vars[bit] == ctx.bool_val(value));
      }

      bool prefix_exhausted = false;
      while (!stop_flag.load()) {
        if (models_checked.load() >= max_models) {
          stop_flag.store(true);
          break;
        }

        std::vector<std::vector<int>> patterns;
        std::vector<std::string> bits_list;
        patterns.reserve(packed_circuit::kWordBits);
        bits_list.reserve(packed_circuit::kWordBits);

        for (std::size_t i = 0; i < packed_circuit::kWordBits; ++i) {
          if (stop_flag.load()) {
            break;
          }
          if (models_checked.load() >= max_models) {
            stop_flag.store(true);
            break;
          }
          const z3::check_result res = solver.check();
          if (res == z3::unsat) {
            prefix_exhausted = true;
            break;
          }
          if (res == z3::unknown) {
            set_error("SAT returned unknown");
            prefix_exhausted = true;
            break;
          }

          z3::model m = solver.get_model();
          std::vector<int> pi_values;
          pi_values.reserve(pi_vars.size());
          std::string bits;
          bits.reserve(pi_vars.size());
          z3::expr block = ctx.bool_val(false);
          for (const auto& pi_var : pi_vars) {
            z3::expr val = m.eval(pi_var, true);
            bool bit = false;
            if (val.is_true()) {
              bit = true;
              bits.push_back('1');
            } else if (val.is_false()) {
              bit = false;
              bits.push_back('0');
            } else {
              bits.push_back('x');
            }
            pi_values.push_back(bit ? 1 : 0);
            if (val.is_true() || val.is_false()) {
              block = block || (pi_var != ctx.bool_val(bit));
            }
          }
          solver.add(block);
          const std::size_t current = models_checked.fetch_add(1) + 1;
          if (report_step > 0 && current % report_step == 0) {
            std::lock_guard<std::mutex> lock(progress_mutex);
            std::cout << "sat_enum_progress round " << round_index
                      << " models " << current << "\n";
          }

          if (groundtruth_bits.find(bits) != groundtruth_bits.end()) {
            continue;
          }
          if (seen_bits && seen_bits->find(bits) != seen_bits->end()) {
            continue;
          }
          if (local_result) {
            local_result->seen.insert(bits);
          }

          patterns.push_back(std::move(pi_values));
          bits_list.push_back(std::move(bits));
        }

        if (patterns.empty()) {
          if (prefix_exhausted) {
            break;
          }
          continue;
        }

        const std::size_t pattern_count = patterns.size();
        std::vector<packed_circuit::word_t> pi_bits(pi_count, 0);
        for (std::size_t p = 0; p < pattern_count; ++p) {
          if (patterns[p].size() != pi_count) {
            set_error("PI vector size mismatch");
            break;
          }
          for (std::size_t i = 0; i < pi_count; ++i) {
            if (patterns[p][i]) {
              pi_bits[i] |= (packed_circuit::word_t(1) << p);
            }
          }
        }
        if (stop_flag.load()) {
          break;
        }

        PackedValues golden_values;
        PackedValues trojan_values;
        try {
          golden_values = simulate_packed_values(golden_eval, pi_bits, pattern_count);
          trojan_values = simulate_packed_values(trojan_eval, pi_bits, pattern_count);
        } catch (const std::exception& e) {
          set_error(e.what());
          break;
        }

        packed_circuit::word_t diff_mask = 0;
        for (std::size_t pos = 0; pos < trojan_po_indices.size(); ++pos) {
          const int trojan_po = trojan_po_indices[pos];
          const int golden_po = golden_po_indices[pos];
          if (trojan_po < 0 ||
              golden_po < 0 ||
              static_cast<std::size_t>(trojan_po) >= trojan_values.values.size() ||
              static_cast<std::size_t>(golden_po) >= golden_values.values.size()) {
            set_error("PO index out of range");
            break;
          }
          diff_mask |=
              (trojan_values.values[static_cast<std::size_t>(trojan_po)] ^
               golden_values.values[static_cast<std::size_t>(golden_po)]);
        }
        if (stop_flag.load()) {
          break;
        }
        diff_mask &= trojan_values.mask;

        const packed_circuit::word_t safe_mask =
            (~diff_mask) & trojan_values.mask;
        if (safe_mask != 0) {
          const int bit_idx = __builtin_ctzll(safe_mask);
          if (bit_idx >= 0 &&
              static_cast<std::size_t>(bit_idx) < patterns.size()) {
            if (counterexample_count.fetch_add(1) < max_counterexamples) {
              if (local_result) {
                local_result->counterexamples.push_back(
                    std::move(patterns[bit_idx]));
              }
            }
          }
          stop_flag.store(true);
          break;
        }
      }

          solver.pop();
          if (stop_flag.load()) {
            break;
          }
        }
      }

      if (tid < prefix_counts.size()) {
        prefix_counts[tid] = local_prefixes;
      }
    }
  }

  if (seen_bits) {
    for (auto& thread_result : thread_results) {
      for (auto& bits : thread_result.seen) {
        seen_bits->insert(std::move(bits));
      }
    }
  }
  for (auto& thread_result : thread_results) {
    for (auto& pattern : thread_result.counterexamples) {
      if (counterexamples->size() >= max_counterexamples) {
        break;
      }
      counterexamples->push_back(std::move(pattern));
    }
    if (counterexamples->size() >= max_counterexamples) {
      break;
    }
  }

  if (!prefix_counts.empty()) {
    std::size_t sum = 0;
    std::size_t min_count = prefix_counts[0];
    std::size_t max_count = prefix_counts[0];
    std::size_t idle = 0;
    for (std::size_t count : prefix_counts) {
      sum += count;
      min_count = std::min(min_count, count);
      max_count = std::max(max_count, count);
      if (count == 0) {
        idle += 1;
      }
    }

    if (prefix_counts.size() <= 16) {
      for (std::size_t i = 0; i < prefix_counts.size(); ++i) {
        std::cout << "sat_enum_thread_prefixes round " << round_index
                  << " thread " << i
                  << " prefixes " << prefix_counts[i] << "\n";
      }
    }
    const std::size_t avg = prefix_counts.empty()
                                ? 0
                                : (sum / prefix_counts.size());
    std::cout << "sat_enum_prefix_dist round " << round_index
              << " min " << min_count
              << " max " << max_count
              << " avg " << avg
              << " idle " << idle
              << " total " << sum << "\n";
  }

  if (error_flag.load()) {
    if (error) {
      std::lock_guard<std::mutex> lock(error_mutex);
      *error = shared_error;
    }
    return false;
  }

  return true;
}

struct SatNodeResult {
  bool success = true;
  std::string error;
  std::vector<std::string> lines;
};

SatNodeResult sat_check_payload_node(const circuit& golden,
                                     const circuit& trojan,
                                     const MiningResult& result,
                                     int fix_idx,
                                     std::size_t batch_size) {
  SatNodeResult result_out;
  if (fix_idx < 0 ||
      static_cast<std::size_t>(fix_idx) >= trojan.node_count()) {
    result_out.success = false;
    result_out.error = "payload_sat error: fix node index out of range";
    return result_out;
  }

  z3::context ctx;
  z3::solver solver(ctx);

  std::vector<z3::expr> pi_vars;
  pi_vars.reserve(trojan.pi_count());
  for (std::size_t i = 0; i < trojan.pi_count(); ++i) {
    pi_vars.push_back(ctx.bool_const(("pi_" + std::to_string(i)).c_str()));
  }

  std::vector<z3::expr> trojan_vars =
      make_node_vars(ctx, "t_", trojan.node_count());

  std::string error;
  if (!add_circuit_constraints(ctx,
                               trojan,
                               trojan_vars,
                               pi_vars,
                               solver,
                               -1,
                               nullptr,
                               &error)) {
    result_out.success = false;
    result_out.error = "payload_sat error: " + error;
    return result_out;
  }
  z3::expr rule_expr = ctx.bool_val(false);
  for (const auto& rule : result.model.rules) {
    z3::expr term_expr = ctx.bool_val(true);
    for (const auto& term : rule.terms) {
      const std::size_t feature_idx = term.first;
      const int value = term.second;
      if (feature_idx >= result.feature_nodes.size()) {
        result_out.success = false;
        result_out.error = "payload_sat error: feature index out of range";
        return result_out;
      }
      const int node_idx = result.feature_nodes[feature_idx];
      if (node_idx < 0 ||
          static_cast<std::size_t>(node_idx) >= trojan_vars.size()) {
        result_out.success = false;
        result_out.error = "payload_sat error: feature node index out of range";
        return result_out;
      }
      term_expr =
          term_expr && (trojan_vars[static_cast<std::size_t>(node_idx)] ==
                        ctx.bool_val(value != 0));
    }
    rule_expr = rule_expr || term_expr;
  }
  solver.add(rule_expr);

  std::vector<char> fanout_cone;
  try {
    fanout_cone = build_fanout_cone(trojan, fix_idx);
  } catch (const std::exception& e) {
    result_out.success = false;
    result_out.error = std::string("payload_sat error: ") + e.what();
    return result_out;
  }

  std::vector<z3::expr> trojan_flip_vars =
      make_node_vars(ctx, "tf_", trojan.node_count());
  if (!add_flipped_cone_constraints(ctx,
                                    trojan,
                                    trojan_vars,
                                    trojan_flip_vars,
                                    pi_vars,
                                    fanout_cone,
                                    fix_idx,
                                    solver,
                                    &error)) {
    result_out.success = false;
    result_out.error = "payload_sat error: " + error;
    return result_out;
  }

  z3::expr observable = ctx.bool_val(false);
  bool has_observable = false;
  for (int po : trojan.po_indices()) {
    if (po >= 0 &&
        static_cast<std::size_t>(po) < fanout_cone.size() &&
        fanout_cone[static_cast<std::size_t>(po)]) {
      observable = observable ||
                   (trojan_vars[static_cast<std::size_t>(po)] !=
                    trojan_flip_vars[static_cast<std::size_t>(po)]);
      has_observable = true;
    }
  }
  if (has_observable) {
    solver.add(observable);
  }

  circuit golden_eval = golden;
  circuit trojan_eval = trojan;
  const auto& trojan_po_indices = trojan.po_indices();
  const auto& golden_po_indices = golden.po_indices();
  if (trojan_po_indices.size() != golden_po_indices.size()) {
    result_out.success = false;
    result_out.error = "payload_sat error: PO count mismatch";
    return result_out;
  }
  const std::size_t pi_count = trojan.pi_count();
  int counter = 0;
  while (true) {

    std::cout << counter++ << '\n';

    std::vector<std::vector<int>> patterns;
    std::vector<std::string> bits_list;
    patterns.reserve(batch_size);
    bits_list.reserve(batch_size);

    for (std::size_t i = 0; i < batch_size; ++i) {
      const z3::check_result res = solver.check();
      if (res == z3::unsat) {
        if (patterns.empty()) {
          result_out.lines.push_back("payload_sat_safe " +
                                     trojan.node_name(fix_idx));
        }
        break;
      }
      if (res == z3::unknown) {
        result_out.lines.push_back("payload_sat_unknown " +
                                   trojan.node_name(fix_idx));
        patterns.clear();
        break;
      }

      z3::model m = solver.get_model();
      std::vector<int> pi_values;
      pi_values.reserve(pi_vars.size());
      std::string bits;
      bits.reserve(pi_vars.size());
      z3::expr block = ctx.bool_val(false);
      for (const auto& pi_var : pi_vars) {
        z3::expr val = m.eval(pi_var, true);
        bool bit = false;
        if (val.is_true()) {
          bit = true;
          bits.push_back('1');
        } else if (val.is_false()) {
          bit = false;
          bits.push_back('0');
        } else {
          bits.push_back('x');
        }
        pi_values.push_back(bit ? 1 : 0);
        if (val.is_true() || val.is_false()) {
          block = block || (pi_var != ctx.bool_val(bit));
        }
      }
      solver.add(block);
      patterns.push_back(std::move(pi_values));
      bits_list.push_back(std::move(bits));
    }

    if (patterns.empty()) {
      break;
    }

    const std::size_t pattern_count = patterns.size();
    std::vector<packed_circuit::word_t> pi_bits(pi_count, 0);
    for (std::size_t p = 0; p < pattern_count; ++p) {
      if (patterns[p].size() != pi_count) {
        result_out.success = false;
        result_out.error = "payload_sat error: PI vector size mismatch";
        return result_out;
      }
      for (std::size_t i = 0; i < pi_count; ++i) {
        if (patterns[p][i]) {
          pi_bits[i] |= (packed_circuit::word_t(1) << p);
        }
      }
    }

    PackedValues golden_values;
    PackedValues trojan_values;
    std::vector<packed_circuit::word_t> flipped_values;
    try {
      golden_values = simulate_packed_values(golden_eval, pi_bits, pattern_count);
      trojan_values = simulate_packed_values(trojan_eval, pi_bits, pattern_count);
      const packed_circuit::word_t flip_bits =
          (~trojan_values.values[static_cast<std::size_t>(fix_idx)]) &
          trojan_values.mask;
      flipped_values = simulate_packed_with_flip(trojan_eval,
                                                 trojan_values.values,
                                                 fanout_cone,
                                                 fix_idx,
                                                 flip_bits,
                                                 trojan_values.mask);
    } catch (const std::exception& e) {
      result_out.success = false;
      result_out.error = std::string("payload_sat error: ") + e.what();
      return result_out;
    }

    packed_circuit::word_t mismatch_mask = 0;
    for (std::size_t pos = 0; pos < trojan_po_indices.size(); ++pos) {
      const int trojan_po = trojan_po_indices[pos];
      const int golden_po = golden_po_indices[pos];
      if (trojan_po < 0 ||
          golden_po < 0 ||
          static_cast<std::size_t>(trojan_po) >= flipped_values.size() ||
          static_cast<std::size_t>(golden_po) >= golden_values.values.size()) {
        result_out.success = false;
        result_out.error = "payload_sat error: PO index out of range";
        return result_out;
      }
      mismatch_mask |=
          (golden_values.values[static_cast<std::size_t>(golden_po)] ^
           flipped_values[static_cast<std::size_t>(trojan_po)]);
    }
    mismatch_mask &= trojan_values.mask;

    if (mismatch_mask != 0) {
      while (mismatch_mask) {
        const int bit_idx = __builtin_ctzll(mismatch_mask);
        if (bit_idx >= 0 &&
            static_cast<std::size_t>(bit_idx) < bits_list.size()) {
          result_out.lines.push_back("payload_sat_counterexample " +
                                     trojan.node_name(fix_idx) + " " +
                                     bits_list[static_cast<std::size_t>(bit_idx)]);
        }
        mismatch_mask &= (mismatch_mask - 1);
      }
      break;
    }

  }

  return result_out;
}

[[maybe_unused]] bool sat_check_payload(const circuit& golden,
                       const circuit& trojan,
                       const MiningResult& result,
                       const std::vector<int>& fix_nodes) {
  if (fix_nodes.empty()) {
    std::cout << "payload_sat skipped: no fix nodes\n";
    return true;
  }
  if (result.model.rules.empty()) {
    std::cout << "payload_sat skipped: no rules\n";
    return true;
  }
  if (golden.pi_count() != trojan.pi_count()) {
    std::cerr << "payload_sat error: PI count mismatch\n";
    return false;
  }
  if (golden.po_count() != trojan.po_count()) {
    std::cerr << "payload_sat error: PO count mismatch\n";
    return false;
  }

  std::cout << "payload_sat_check_nodes " << fix_nodes.size() << "\n";
  std::vector<SatNodeResult> results(fix_nodes.size());
  std::atomic<bool> error_flag(false);
  std::string error_message;
  const std::size_t batch_size =
      std::min<std::size_t>(packed_circuit::kWordBits, 64U);

#ifdef _OPENMP
#pragma omp parallel for schedule(dynamic)
#endif
  for (std::size_t i = 0; i < fix_nodes.size(); ++i) {
    if (error_flag.load()) {
      continue;
    }
    SatNodeResult node_result =
        sat_check_payload_node(golden, trojan, result, fix_nodes[i], batch_size);
    if (!node_result.success) {
      error_flag.store(true);
#ifdef _OPENMP
#pragma omp critical
#endif
      {
        error_message = node_result.error;
      }
    }
    results[i] = std::move(node_result);
  }

  if (error_flag.load()) {
    if (!error_message.empty()) {
      std::cerr << error_message << "\n";
    }
    return false;
  }

  for (const auto& node_result : results) {
    for (const auto& line : node_result.lines) {
      std::cout << line << "\n";
    }
  }

  return true;
}

void analyze_payload_nodes(const circuit& golden,
                           const circuit& trojan,
                           const PatternStats& stats,
                           const MiningResult& result,
                           std::vector<int>* fix_nodes_out) {
  if (stats.trigger_patterns.empty()) {
    std::cout << "payload_analysis skipped: no error patterns\n";
    return;
  }
  if (trojan.po_count() == 0) {
    std::cout << "payload_analysis skipped: no PO\n";
    return;
  }

  const std::size_t node_count = trojan.node_count();
  const std::size_t po_count = trojan.po_count();
  const auto& po_indices = trojan.po_indices();

  std::vector<std::vector<char>> po_cones(
      po_count, std::vector<char>(node_count, 0));
  for (std::size_t i = 0; i < po_count; ++i) {
    mark_fanin_cone(trojan, po_indices[i], &po_cones[i]);
  }

  const std::size_t pattern_count = stats.trigger_patterns.size();
  std::vector<char> global_intersection(node_count, 1);
  bool global_initialized = false;

  std::vector<std::vector<int>> golden_outputs_list(pattern_count);
  std::size_t patterns_with_mismatch = 0;

#ifdef _OPENMP
  std::atomic<bool> error_flag(false);
  std::string error_message;

#pragma omp parallel
  {
    circuit golden_eval = golden;
    circuit trojan_eval = trojan;
    std::vector<char> local_intersection;
    bool local_initialized = false;
    std::size_t local_mismatch = 0;

#pragma omp for schedule(static)
    for (std::size_t p = 0; p < pattern_count; ++p) {
      if (error_flag.load()) {
        continue;
      }
      const auto& pattern = stats.trigger_patterns[p];
      std::vector<int> golden_outputs;
      std::vector<int> trojan_outputs;
      try {
        golden_outputs = golden_eval.simulate(pattern);
        trojan_outputs = trojan_eval.simulate(pattern);
      } catch (const std::exception& e) {
        const std::string msg = e.what();
        if (!error_flag.exchange(true)) {
#pragma omp critical
          {
            error_message = msg;
          }
        }
        continue;
      }
      golden_outputs_list[p] = golden_outputs;

      std::vector<std::size_t> mismatch_pos;
      for (std::size_t i = 0; i < po_count; ++i) {
        if (golden_outputs[i] != trojan_outputs[i]) {
          mismatch_pos.push_back(i);
        }
      }
      if (mismatch_pos.empty()) {
        continue;
      }
      local_mismatch += 1;

      std::vector<char> pattern_intersection;
      bool pattern_initialized = false;
      for (std::size_t pos : mismatch_pos) {
        if (!pattern_initialized) {
          pattern_intersection = po_cones[pos];
          pattern_initialized = true;
        } else {
          intersect_in_place(pattern_intersection, po_cones[pos]);
        }
      }

      if (!pattern_initialized) {
        continue;
      }
      if (!local_initialized) {
        local_intersection = pattern_intersection;
        local_initialized = true;
      } else {
        intersect_in_place(local_intersection, pattern_intersection);
      }
    }

#pragma omp critical
    {
      patterns_with_mismatch += local_mismatch;
      if (local_initialized) {
        if (!global_initialized) {
          global_intersection = local_intersection;
          global_initialized = true;
        } else {
          intersect_in_place(global_intersection, local_intersection);
        }
      }
    }
  }

  if (error_flag.load()) {
    std::cerr << "payload_analysis simulation error: " << error_message << "\n";
    return;
  }
#else
  circuit golden_eval = golden;
  circuit trojan_eval = trojan;
  for (std::size_t p = 0; p < pattern_count; ++p) {
    const auto& pattern = stats.trigger_patterns[p];
    std::vector<int> golden_outputs;
    std::vector<int> trojan_outputs;
    try {
      golden_outputs = golden_eval.simulate(pattern);
      trojan_outputs = trojan_eval.simulate(pattern);
    } catch (const std::exception& e) {
      std::cerr << "payload_analysis simulation error: " << e.what() << "\n";
      return;
    }
    golden_outputs_list[p] = golden_outputs;

    std::vector<std::size_t> mismatch_pos;
    for (std::size_t i = 0; i < po_count; ++i) {
      if (golden_outputs[i] != trojan_outputs[i]) {
        mismatch_pos.push_back(i);
      }
    }
    if (mismatch_pos.empty()) {
      continue;
    }
    patterns_with_mismatch += 1;

    std::vector<char> pattern_intersection;
    bool pattern_initialized = false;
    for (std::size_t pos : mismatch_pos) {
      if (!pattern_initialized) {
        pattern_intersection = po_cones[pos];
        pattern_initialized = true;
      } else {
        intersect_in_place(pattern_intersection, po_cones[pos]);
      }
    }

    if (!pattern_initialized) {
      continue;
    }
    if (!global_initialized) {
      global_intersection = pattern_intersection;
      global_initialized = true;
    } else {
      intersect_in_place(global_intersection, pattern_intersection);
    }
  }
#endif

  std::cout << "payload_patterns_with_mismatch " << patterns_with_mismatch
            << "\n";

  if (!global_initialized) {
    std::cout << "payload_fanin_intersection nodes 0\n";
    return;
  }

  std::vector<int> candidate_nodes;
  for (std::size_t i = 0; i < global_intersection.size(); ++i) {
    if (global_intersection[i]) {
      candidate_nodes.push_back(static_cast<int>(i));
    }
  }

  std::cout << "payload_fanin_intersection nodes "
            << candidate_nodes.size() << "\n";
  for (int idx : candidate_nodes) {
    std::cout << "payload_fanin_node " << trojan.node_name(idx) << "\n";
  }

  if (candidate_nodes.empty()) {
    return;
  }
  if (result.model.rules.empty()) {
    std::cout << "payload_rule_check skipped: no rules\n";
    return;
  }

  std::vector<char> candidate_ok(candidate_nodes.size(), 1);
  std::size_t total_patterns = stats.trigger_patterns.size();
  std::size_t rule_miss = 0;

#ifdef _OPENMP
  std::atomic<bool> rule_error(false);
  std::string rule_error_message;

#pragma omp parallel
  {
    circuit trojan_eval = trojan;
    std::vector<char> local_ok(candidate_nodes.size(), 1);
    std::size_t local_rule_miss = 0;

#pragma omp for schedule(static)
    for (std::size_t p = 0; p < total_patterns; ++p) {
      if (rule_error.load()) {
        continue;
      }
      const auto& pattern = stats.trigger_patterns[p];
      SimState trojan_state;
      try {
        trojan_state = simulate_with_override(trojan_eval, pattern, -1, 0);
      } catch (const std::exception& e) {
        const std::string msg = e.what();
        if (!rule_error.exchange(true)) {
#pragma omp critical
          {
            rule_error_message = msg;
          }
        }
        continue;
      }
      const std::vector<int> features =
          extract_features_from_values(trojan_state.values, result.feature_nodes);
      const bool rule_match = eval_rules(result.model.rules, features);
      if (!rule_match) {
        local_rule_miss += 1;
        continue;
      }

      for (std::size_t i = 0; i < candidate_nodes.size(); ++i) {
        if (!local_ok[i]) {
          continue;
        }
        const int node_idx = candidate_nodes[i];
        if (node_idx < 0 ||
            static_cast<std::size_t>(node_idx) >= trojan_state.values.size()) {
          local_ok[i] = 0;
          continue;
        }
        const int original =
            trojan_state.values[static_cast<std::size_t>(node_idx)];
        const int flipped = original ? 0 : 1;
        SimState flipped_state;
        try {
          flipped_state =
              simulate_with_override(trojan_eval, pattern, node_idx, flipped);
        } catch (const std::exception& e) {
          const std::string msg = e.what();
          if (!rule_error.exchange(true)) {
#pragma omp critical
            {
              rule_error_message = msg;
            }
          }
          local_ok[i] = 0;
          continue;
        }
        if (flipped_state.outputs != golden_outputs_list[p]) {
          local_ok[i] = 0;
        }
      }
    }

#pragma omp critical
    {
      rule_miss += local_rule_miss;
      for (std::size_t i = 0; i < candidate_ok.size(); ++i) {
        candidate_ok[i] = (candidate_ok[i] && local_ok[i]) ? 1 : 0;
      }
    }
  }

  if (rule_error.load()) {
    std::cerr << "payload_rule_check simulation error: "
              << rule_error_message << "\n";
    return;
  }
#else
  circuit trojan_eval = trojan;
  for (std::size_t p = 0; p < total_patterns; ++p) {
    const auto& pattern = stats.trigger_patterns[p];
    SimState trojan_state;
    try {
      trojan_state = simulate_with_override(trojan_eval, pattern, -1, 0);
    } catch (const std::exception& e) {
      std::cerr << "payload_rule_check simulation error: " << e.what() << "\n";
      return;
    }
    const std::vector<int> features =
        extract_features_from_values(trojan_state.values, result.feature_nodes);
    const bool rule_match = eval_rules(result.model.rules, features);
    if (!rule_match) {
      rule_miss += 1;
      continue;
    }

    for (std::size_t i = 0; i < candidate_nodes.size(); ++i) {
      if (!candidate_ok[i]) {
        continue;
      }
      const int node_idx = candidate_nodes[i];
      if (node_idx < 0 ||
          static_cast<std::size_t>(node_idx) >= trojan_state.values.size()) {
        candidate_ok[i] = 0;
        continue;
      }
      const int original = trojan_state.values[static_cast<std::size_t>(node_idx)];
      const int flipped = original ? 0 : 1;
      SimState flipped_state;
      try {
        flipped_state = simulate_with_override(trojan_eval, pattern, node_idx, flipped);
      } catch (const std::exception& e) {
        std::cerr << "payload_flip simulation error: " << e.what() << "\n";
        return;
      }
      if (flipped_state.outputs != golden_outputs_list[p]) {
        candidate_ok[i] = 0;
      }
    }
  }
#endif

  if (rule_miss > 0) {
    std::cout << "payload_rule_unmatched " << rule_miss
              << " of " << total_patterns << "\n";
  }

  std::vector<int> fix_nodes;
  for (std::size_t i = 0; i < candidate_nodes.size(); ++i) {
    if (candidate_ok[i]) {
      fix_nodes.push_back(candidate_nodes[i]);
    }
  }

  std::cout << "payload_fix_nodes " << fix_nodes.size() << "\n";
  for (int idx : fix_nodes) {
    std::cout << "payload_fix_node " << trojan.node_name(idx) << "\n";
  }

  if (fix_nodes_out) {
    *fix_nodes_out = fix_nodes;
  }
}

string derive_groundtruth_path(const string& trojan_path) {
  string base = trojan_path;
  const size_t slash = base.find_last_of("/\\");
  if (slash != string::npos) {
    base = base.substr(slash + 1);
  }
  const size_t dot = base.rfind('.');
  if (dot != string::npos) {
    base = base.substr(0, dot);
  }
  return "groundtruth/" + base + "_error_patterns.json";
}

bool build_stats_from_groundtruth(const circuit& golden,
                                  const circuit& trojan,
                                  const string& log_path,
                                  PatternStats* stats,
                                  string* error) {
  if (error) {
    error->clear();
  }
  if (!stats) {
    if (error) {
      *error = "Stats output pointer is null";
    }
    return false;
  }

  *stats = PatternStats{};
  ParallelCollectLog log(log_path);

  const auto& log_pi_order = log.pi_order();
  if (log_pi_order.empty()) {
    if (error) {
      *error = "pi_order not available in groundtruth log";
    }
    return false;
  }

  const auto& pi_indices = trojan.pi_indices();
  unordered_map<string, size_t> pi_name_to_pos;
  pi_name_to_pos.reserve(pi_indices.size());
  for (size_t pos = 0; pos < pi_indices.size(); ++pos) {
    pi_name_to_pos[trojan.node_name(pi_indices[pos])] = pos;
  }

  vector<size_t> log_to_circuit;
  log_to_circuit.reserve(log_pi_order.size());
  vector<int> seen_pos(pi_indices.size(), 0);
  for (const auto& name : log_pi_order) {
    auto it = pi_name_to_pos.find(name);
    if (it == pi_name_to_pos.end()) {
      if (error) {
        *error = "pi_order entry not found in circuit: " + name;
      }
      return false;
    }
    log_to_circuit.push_back(it->second);
    if (it->second < seen_pos.size()) {
      seen_pos[it->second] += 1;
    }
  }
  for (size_t pos = 0; pos < seen_pos.size(); ++pos) {
    if (seen_pos[pos] == 0) {
      if (error) {
        *error = "circuit PI missing from groundtruth pi_order: " +
                 trojan.node_name(pi_indices[pos]);
      }
      return false;
    }
  }

  unordered_set<string> unique_bits;
  vector<string> ordered_bits;
  unique_bits.reserve(log.size());
  ordered_bits.reserve(log.size());
  for (size_t i = 0; i < log.size(); ++i) {
    auto bits = log.get_pattern_bits(static_cast<int>(i));
    if (!bits) {
      continue;
    }
    if (unique_bits.insert(*bits).second) {
      ordered_bits.push_back(*bits);
    }
  }

  if (ordered_bits.empty()) {
    if (error) {
      *error = "No pattern_bits found in groundtruth log";
    }
    return false;
  }

  stats->trigger_patterns.reserve(ordered_bits.size());
  for (const auto& bits : ordered_bits) {
    if (bits.size() != log_to_circuit.size()) {
      if (error) {
        *error = "pattern_bits length does not match pi_order";
      }
      return false;
    }
    vector<int> pi_values(pi_indices.size(), 0);
    for (size_t i = 0; i < log_to_circuit.size(); ++i) {
      char bit = bits[i];
      if (bit != '0' && bit != '1') {
        if (error) {
          *error = "pattern_bits contains invalid character";
        }
        return false;
      }
      pi_values[log_to_circuit[i]] = (bit == '1') ? 1 : 0;
    }
    stats->trigger_patterns.push_back(std::move(pi_values));
  }

  stats->trigger_patterns_total = stats->trigger_patterns.size();
  stats->mismatch_patterns = stats->trigger_patterns_total;

  stats->gate_indices.reserve(trojan.node_count());
  for (size_t i = 0; i < trojan.node_count(); ++i) {
    const auto& c = trojan.get_cell(static_cast<int>(i));
    if (c.ctype == CType::GATE) {
      stats->gate_indices.push_back(static_cast<int>(i));
    }
  }

  stats->ones_total.assign(stats->gate_indices.size(), 0);
  stats->ones_trigger.assign(stats->gate_indices.size(), 0);
  stats->ones_notrigger.assign(stats->gate_indices.size(), 0);

  circuit trojan_trigger = trojan;
  for (const auto& pattern : stats->trigger_patterns) {
    try {
      trojan_trigger.simulate(pattern);
    } catch (const std::exception& e) {
      if (error) {
        *error = string("Trigger simulation error: ") + e.what();
      }
      return false;
    }
    for (size_t g = 0; g < stats->gate_indices.size(); ++g) {
      const int idx = stats->gate_indices[g];
      const int val = trojan_trigger.get_cell(idx).val;
      const std::uint64_t one = (val == 1) ? 1 : 0;
      stats->ones_trigger[g] += one;
      stats->ones_total[g] += one;
    }
  }

  const size_t target_notrigger = stats->trigger_patterns_total;
  stats->notrigger_patterns_total = 0;
  stats->total_patterns = stats->trigger_patterns_total;

  if (target_notrigger == 0) {
    if (error) {
      *error = "No trigger patterns available";
    }
    return false;
  }

  circuit golden_eval = golden;
  circuit trojan_eval = trojan;
  packed_circuit golden_packed(golden_eval);
  packed_circuit trojan_packed(trojan_eval);
  mt19937 rng(1337);
  uniform_int_distribution<int> dist(0, 1);
  size_t attempts = 0;
  const size_t max_attempts = target_notrigger * 50 + 1000;
  const size_t block_bits = packed_circuit::kWordBits;

  while (stats->notrigger_patterns_total < target_notrigger &&
         attempts < max_attempts) {
    const size_t remaining_attempts = max_attempts - attempts;
    const size_t block_size = min(block_bits, remaining_attempts);
    if (block_size == 0) {
      break;
    }

    vector<vector<int>> patterns;
    patterns.reserve(block_size);
    for (size_t p = 0; p < block_size; ++p) {
      vector<int> pi_values;
      pi_values.reserve(golden_eval.pi_count());
      for (size_t i = 0; i < golden_eval.pi_count(); ++i) {
        pi_values.push_back(dist(rng));
      }
      patterns.push_back(std::move(pi_values));
    }

    try {
      golden_packed.simulate(patterns);
      trojan_packed.simulate(patterns);
    } catch (const std::exception&) {
      attempts += block_size;
      continue;
    }

    const packed_circuit::word_t mask =
        packed_circuit::mask_for_count(block_size);
    packed_circuit::word_t diff_mask = 0;
    for (size_t o = 0; o < trojan_eval.po_count(); ++o) {
      diff_mask |= (golden_packed.po_bits(o) ^ trojan_packed.po_bits(o));
    }
    diff_mask &= mask;
    packed_circuit::word_t notrigger_mask = mask & ~diff_mask;

    const size_t remaining_needed =
        target_notrigger - stats->notrigger_patterns_total;
    const size_t available = popcount_ull(notrigger_mask);
    const size_t take = min(remaining_needed, available);
    packed_circuit::word_t accept_mask =
        (take == available) ? notrigger_mask
                            : take_first_bits(notrigger_mask, take);

    if (take > 0) {
      stats->notrigger_patterns_total += take;
      stats->total_patterns += take;
      for (size_t g = 0; g < stats->gate_indices.size(); ++g) {
        const int idx = stats->gate_indices[g];
        const packed_circuit::word_t bits =
            trojan_packed.node_bits(idx) & accept_mask;
        const std::uint64_t ones = popcount_ull(bits);
        stats->ones_notrigger[g] += ones;
        stats->ones_total[g] += ones;
      }
    }

    attempts += block_size;
  }

  if (stats->notrigger_patterns_total < target_notrigger) {
    if (error) {
      *error = "Not enough non-trigger patterns collected: " +
               to_string(stats->notrigger_patterns_total) + "/" +
               to_string(target_notrigger);
    }
    return false;
  }

  return true;
}

}  // namespace

int main(int argc, char** argv) {
  AppOptions options;
  string error;
  const ParseStatus status = parse_cli_options(argc, argv, &options, &error);
  if (status == ParseStatus::help) {
    print_usage(argv[0]);
    return 0;
  }
  if (status == ParseStatus::error) {
    if (!error.empty()) {
      cerr << error << "\n";
    }
    print_usage(argv[0]);
    return 1;
  }

  circuit golden;
  circuit trojan;
  if (!bench_io::parse_bench_file(options.golden_path, golden, &error)) {
    cerr << "Golden parse error: " << error << "\n";
    return 1;
  }
  if (!bench_io::parse_bench_file(options.trojan_path, trojan, &error)) {
    cerr << "Trojan parse error: " << error << "\n";
    return 1;
  }

  if (!align_circuits(golden, trojan, &error)) {
    cerr << "Circuit alignment error: " << error << "\n";
    return 1;
  }

  const string groundtruth_path = options.groundtruth_path.empty()
                                      ? derive_groundtruth_path(options.trojan_path)
                                      : options.groundtruth_path;
  cout << "groundtruth " << groundtruth_path << "\n";

  cout << "patterns " << options.pattern_count
       << " depth " << options.max_depth
       << " eval " << options.eval_count
       << " neg_ratio " << options.neg_ratio
       << " mine_rounds " << options.mine_rounds
       << " mine_max " << options.mine_max << "\n";
  cout << "p1_trigger " << options.p1_trigger_threshold
       << " p1_notrigger " << options.p1_notrigger_threshold
       << " include_pi " << (options.include_pi ? 1 : 0)
       << " no_filter " << (options.no_filter ? 1 : 0)
       << " force_split " << (options.force_split ? 1 : 0)
       << " strict_retry " << (options.strict_retry ? 1 : 0) << "\n";

  PatternStats stats;
  try {
    if (!build_stats_from_groundtruth(golden, trojan, groundtruth_path, &stats, &error)) {
      cerr << "Groundtruth error: " << error << "\n";
      return 1;
    }
  } catch (const std::exception& e) {
    cerr << "Groundtruth parse error: " << e.what() << "\n";
    return 1;
  }

  cout << "pattern_total " << stats.total_patterns << "\n";
  cout << "trigger_patterns " << stats.trigger_patterns_total << "\n";
  cout << "notrigger_patterns " << stats.notrigger_patterns_total << "\n";
  const double trojan_rate = compute_trojan_rate(stats);
  cout << "trojan_rates " << trojan_rate << '\n';

  cout << "gate_zero_ratio\n";
  cout << fixed << setprecision(4);

  vector<CandidateInfo> candidates;
  if (!build_candidates(stats,
                        options.p1_trigger_threshold,
                        options.p1_notrigger_threshold,
                        options.no_filter,
                        &candidates,
                        &error)) {
    cerr << error << "\n";
    return 1;
  }

  // cout << "trigger_candidates\n";
  // for (const auto& cand : candidates) {
  //   cout << trojan.node_name(cand.gate_idx)
  //        << " p1_trigger=" << cand.p1_trigger
  //        << " p1_notrigger=" << cand.p1_notrigger << '\n';
  // }

  vector<int> candidate_indices = candidate_gate_indices(candidates);

  unordered_set<string> groundtruth_bits;
  groundtruth_bits.reserve(stats.trigger_patterns.size() * 2);
  for (const auto& pattern : stats.trigger_patterns) {
    groundtruth_bits.insert(pi_values_to_bits(pattern));
  }

  MiningResult result;
  vector<vector<int>> sat_neg_patterns;
  unordered_set<string> sat_seen_bits;
  size_t sat_rounds = options.mine_rounds;
  if (sat_rounds == 0) {
    sat_rounds = 1;
  }
  const size_t sat_max_new = options.mine_max;
  const size_t sat_max_models =
      (options.eval_count > 0) ? options.eval_count
                               : (sat_max_new * 20 + 1000);

  for (size_t round = 0; round < sat_rounds; ++round) {
    MiningOptions mining_options;
    mining_options.max_depth = options.max_depth;
    mining_options.neg_ratio = options.neg_ratio;
    mining_options.eval_count = 0;
    mining_options.mine_rounds = 1;
    mining_options.mine_max = 0;
    mining_options.include_pi = options.include_pi;
    mining_options.force_split = options.force_split;
    mining_options.strict_retry = options.strict_retry;

    if (!run_mining(golden,
                    trojan,
                    stats.trigger_patterns,
                    candidate_indices,
                    mining_options,
                    trojan_rate,
                    &sat_neg_patterns,
                    &result,
                    &error)) {
      if (!error.empty()) {
        cerr << error << "\n";
      }
      return 1;
    }

    const size_t rules_before = result.model.rules.size();
    simplify_rules(&result.model.rules);
    if (result.model.rules.size() != rules_before) {
      result.model.leaf_count = result.model.rules.size();
      cout << "rule_simplify " << rules_before
           << " -> " << result.model.rules.size() << "\n";
    }

    if (sat_max_new == 0 || sat_max_models == 0) {
      cout << "sat_refine_skipped 1\n";
      break;
    }

    cout << "sat_refine_round_start " << (round + 1)
         << " max_models " << sat_max_models
         << " max_new " << sat_max_new << "\n";

    vector<vector<int>> new_negatives;
    if (!collect_rule_counterexamples(golden,
                                      trojan,
                                      result,
                                      round + 1,
                                      groundtruth_bits,
                                      &sat_seen_bits,
                                      sat_max_models,
                                      sat_max_new,
                                      &new_negatives,
                                      &error)) {
      if (!error.empty()) {
        cerr << "SAT rule check error: " << error << "\n";
      }
      return 1;
    }

    if (new_negatives.empty()) {
      cout << "sat_refine_round " << (round + 1)
           << " sat_new_neg 0\n";
      break;
    }

    for (auto& pattern : new_negatives) {
      sat_neg_patterns.push_back(std::move(pattern));
    }
    cout << "sat_refine_round " << (round + 1)
         << " sat_new_neg " << new_negatives.size()
         << " sat_total_neg " << sat_neg_patterns.size() << "\n";
  }

  cout << "training_set pos=" << result.data_pos
       << " neg=" << result.data_neg << '\n';
  cout << "hard_mined " << result.hard_added
       << " rounds " << result.rounds_used << '\n';

  cout << "decision_tree_rules " << result.model.rules.size()
       << " depth_used " << result.model.max_depth_used
       << " leaf_count " << result.model.leaf_count << '\n';

  for (size_t i = 0; i < result.model.rules.size(); ++i) {
    const auto& rule = result.model.rules[i];
    cout << "rule " << (i + 1) << ": ";
    if (rule.terms.empty()) {
      cout << "TRUE\n";
      continue;
    }
    for (size_t t = 0; t < rule.terms.size(); ++t) {
      if (t > 0) {
        cout << " & ";
      }
      const size_t feature_idx = rule.terms[t].first;
      const int value = rule.terms[t].second;
      if (feature_idx < result.feature_nodes.size()) {
        cout << trojan.node_name(result.feature_nodes[feature_idx]) << '=' << value;
      } else {
        cout << "f" << feature_idx << '=' << value;
      }
    }
    cout << '\n';
  }

  cout << "train_pos " << result.train_pos << " train_neg " << result.train_neg << '\n';
  cout << "train_false_neg " << result.train_false_neg
       << " train_false_pos " << result.train_false_pos << '\n';

  cout << "eval_normal " << result.eval_checked
       << " eval_false_pos " << result.eval_false_pos;
  if (result.eval_checked > 0) {
    const double rate =
        static_cast<double>(result.eval_false_pos) /
        static_cast<double>(result.eval_checked);
    cout << " rate " << rate;
  }
  cout << '\n';

  cout << "mis match " << stats.mismatch_patterns << '\n';

  std::vector<int> payload_fix_nodes;
  analyze_payload_nodes(golden, trojan, stats, result, &payload_fix_nodes);

  if (!payload_fix_nodes.empty()) {
    circuit base_eval = trojan;
    std::size_t base_area = 0;
    std::size_t base_level = 0;
    try {
      base_eval.ensure_eval_order();
      base_area = base_eval.area();
      base_level = base_eval.level();
    } catch (const std::exception& e) {
      cerr << "Payload fix baseline error: " << e.what() << "\n";
      return 1;
    }

    std::size_t best_area = std::numeric_limits<std::size_t>::max();
    std::size_t best_level = std::numeric_limits<std::size_t>::max();
    int best_idx = -1;

    for (int fix_idx : payload_fix_nodes) {
      std::size_t cand_area = 0;
      std::size_t cand_level = 0;
      if (!evaluate_fix_candidate(trojan,
                                  result.feature_nodes,
                                  result.model,
                                  fix_idx,
                                  &cand_area,
                                  &cand_level,
                                  &error)) {
        cerr << "Payload fix candidate error: " << error << "\n";
        continue;
      }
      const std::size_t delta_area =
          (cand_area >= base_area) ? (cand_area - base_area) : 0;
      const std::size_t delta_level =
          (cand_level >= base_level) ? (cand_level - base_level) : 0;
      cout << "payload_fix_candidate " << trojan.node_name(fix_idx)
           << " area " << cand_area
           << " level " << cand_level
           << " area_delta " << delta_area
           << " level_delta " << delta_level << "\n";

      if (delta_level < best_level ||
          (delta_level == best_level && delta_area < best_area)) {
        best_level = delta_level;
        best_area = delta_area;
        best_idx = fix_idx;
      }
    }

    if (best_idx >= 0) {
      circuit patched = trojan;
      const std::size_t base_nodes = patched.node_count();
      if (!apply_rule_inversion(patched,
                                result.feature_nodes,
                                result.model,
                                best_idx,
                                base_nodes,
                                &error)) {
        cerr << "Payload fix apply error: " << error << "\n";
        return 1;
      }

      const string output_path = options.output_path.empty()
                                     ? derive_patched_path(options.trojan_path)
                                     : options.output_path;
      if (!bench_io::write_bench_file(output_path, patched, &error)) {
        cerr << "Write error: " << error << "\n";
        return 1;
      }
      cout << "payload_fix_selected " << patched.node_name(best_idx)
           << " area_delta " << best_area
           << " level_delta " << best_level << "\n";
      cout << "payload_fix_bench " << output_path << "\n";
    } else {
      cout << "payload_fix_apply skipped: no viable candidate\n";
    }
  } else {
    cout << "payload_fix_apply skipped: no fix nodes\n";
  }

  // FixResult fix_result;
  // if (!apply_rule_fix(golden,
  //                     trojan,
  //                     stats.trigger_patterns,
  //                     result.feature_nodes,
  //                     result.model,
  //                     &fix_result,
  //                     &error)) {
  //   if (!error.empty()) {
  //     cerr << "Trigger fix error: " << error << "\n";
  //   }
  //   return 1;
  // }

  // cout << "trigger_fix rules_total " << fix_result.rules_total
  //      << " rules_applied " << fix_result.rules_applied
  //      << " rules_skipped " << fix_result.rules_skipped
  //      << " po_candidates " << fix_result.po_candidates
  //      << " po_fixed " << fix_result.po_fixed
  //      << " po_xor " << fix_result.po_fixed_xor
  //      << " po_mux " << fix_result.po_fixed_mux << '\n';

  // PatternStats stats_after = sample_patterns(golden, trojan, options.pattern_count, 1337);
  // const double trojan_rate_after = compute_trojan_rate(stats_after);
  // cout << "trigger_patterns_after " << stats_after.trigger_patterns_total << '\n';
  // const ios_base::fmtflags prev_flags = cout.flags();
  // const streamsize prev_precision = cout.precision();
  // cout << defaultfloat << setprecision(6);
  // cout << "trojan_rates_after " << trojan_rate_after << '\n';
  // cout.flags(prev_flags);
  // cout.precision(prev_precision);

  // if (!options.output_path.empty()) {
  //   error.clear();
  //   if (!bench_io::write_bench_file(options.output_path, trojan, &error)) {
  //     cerr << "Write error: " << error << "\n";
  //     return 1;
  //   }
  // }

  return 0;
}
