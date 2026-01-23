#include "payload_analysis.hpp"

#include <atomic>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

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
          throw std::runtime_error("NOT gate expects 1 input: " +
                                   c.node_name(idx));
        }
        out = read_input(gate.inputs[0]) ? 0 : 1;
        break;
      }
      case GType::BUFF: {
        if (gate.inputs.size() != 1U) {
          throw std::runtime_error("BUFF gate expects 1 input: " +
                                   c.node_name(idx));
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

}  // namespace

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
