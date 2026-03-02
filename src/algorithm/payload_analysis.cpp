#include "payload_analysis.hpp"

#include <algorithm>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include <z3++.h>

#include "../core/batch_simulator.hpp"

namespace {

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

bool build_gate_expr_z3(const cell& gate,
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

bool add_circuit_constraints_with_flips(z3::context& ctx,
                                        const circuit& c,
                                        const std::vector<int>& pi_values,
                                        const std::vector<z3::expr>& vars,
                                        const std::vector<int>& flip_index_by_node,
                                        const std::vector<z3::expr>& flip_vars,
                                        z3::optimize& solver,
                                        std::string* error) {
  if (vars.size() != c.node_count()) {
    if (error) {
      *error = "Variable count mismatch with circuit nodes";
    }
    return false;
  }

  std::vector<int> pi_pos_by_idx(c.node_count(), -1);
  const auto& pi_indices = c.pi_indices();
  if (pi_indices.size() != pi_values.size()) {
    if (error) {
      *error = "PI value count mismatch";
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
    const cell& node = c.get_cell(static_cast<int>(idx));
    switch (node.ctype) {
      case CType::CONST: {
        solver.add(vars[idx] == ctx.bool_val(node.val != 0));
        break;
      }
      case CType::PI: {
        const int pos = pi_pos_by_idx[idx];
        if (pos < 0 || static_cast<std::size_t>(pos) >= pi_values.size()) {
          if (error) {
            *error = "PI position not found";
          }
          return false;
        }
        solver.add(vars[idx] == ctx.bool_val(pi_values[static_cast<std::size_t>(pos)] != 0));
        break;
      }
      case CType::GATE: {
        z3::expr gate_expr = ctx.bool_val(false);
        try {
          if (!build_gate_expr_z3(node, vars, &gate_expr, error)) {
            return false;
          }
        } catch (const std::exception& e) {
          if (error) {
            *error = e.what();
          }
          return false;
        }
        int flip_idx = -1;
        if (idx < flip_index_by_node.size()) {
          flip_idx = flip_index_by_node[idx];
        }
        if (flip_idx >= 0 &&
            static_cast<std::size_t>(flip_idx) < flip_vars.size()) {
          gate_expr = (gate_expr != flip_vars[static_cast<std::size_t>(flip_idx)]);
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

std::vector<int> collect_candidate_nodes(
    const circuit& trojan,
    const std::vector<std::vector<int>>& patterns,
    const std::vector<std::vector<int>>& golden_outputs_list,
    const std::vector<std::size_t>& sample_indices,
    const std::vector<std::vector<char>>& po_cones,
    const std::vector<char>& forbidden_mask,
    const std::vector<char>& forced_mask,
    std::string* error) {
  if (error) {
    error->clear();
  }
  const std::size_t node_count = trojan.node_count();
  std::vector<char> union_cone(node_count, 0);
  bool any_mismatch = false;

  circuit trojan_eval = trojan;
  for (std::size_t idx : sample_indices) {
    if (idx >= patterns.size() || idx >= golden_outputs_list.size()) {
      if (error) {
        *error = "pattern index out of range";
      }
      return {};
    }
    const auto& pattern = patterns[idx];
    std::vector<int> trojan_outputs;
    try {
      trojan_outputs = trojan_eval.simulate(pattern);
    } catch (const std::exception& e) {
      if (error) {
        *error = e.what();
      }
      return {};
    }
    const auto& golden_outputs = golden_outputs_list[idx];
    if (trojan_outputs.size() != golden_outputs.size()) {
      if (error) {
        *error = "PO count mismatch during candidate collection";
      }
      return {};
    }
    for (std::size_t pos = 0; pos < trojan_outputs.size(); ++pos) {
      if (trojan_outputs[pos] != golden_outputs[pos]) {
        any_mismatch = true;
        if (pos >= po_cones.size()) {
          if (error) {
            *error = "PO cone index out of range";
          }
          return {};
        }
        const auto& cone = po_cones[pos];
        if (cone.size() != union_cone.size()) {
          if (error) {
            *error = "PO cone size mismatch";
          }
          return {};
        }
        for (std::size_t i = 0; i < union_cone.size(); ++i) {
          if (cone[i]) {
            union_cone[i] = 1;
          }
        }
      }
    }
  }

  for (std::size_t i = 0; i < forced_mask.size(); ++i) {
    if (forced_mask[i]) {
      union_cone[i] = 1;
    }
  }

  if (!any_mismatch && std::all_of(forced_mask.begin(), forced_mask.end(),
                                   [](char v) { return v == 0; })) {
    return {};
  }

  std::vector<int> candidate_nodes;
  for (std::size_t i = 0; i < union_cone.size(); ++i) {
    if (!union_cone[i]) {
      continue;
    }
    if (i < forbidden_mask.size() && forbidden_mask[i]) {
      continue;
    }
    const cell& cnode = trojan.get_cell(static_cast<int>(i));
    if (cnode.ctype != CType::GATE) {
      continue;
    }
    candidate_nodes.push_back(static_cast<int>(i));
  }
  return candidate_nodes;
}

bool solve_maxsat_batch(const circuit& trojan,
                        const std::vector<std::vector<int>>& patterns,
                        const std::vector<std::vector<int>>& golden_outputs_list,
                        const std::vector<std::size_t>& sample_indices,
                        const std::vector<int>& candidate_nodes,
                        const std::vector<char>& forced_mask,
                        std::vector<int>* selected_nodes,
                        std::string* error) {
  if (error) {
    error->clear();
  }
  if (!selected_nodes) {
    if (error) {
      *error = "selected_nodes output is null";
    }
    return false;
  }
  selected_nodes->clear();
  if (candidate_nodes.empty()) {
    if (error) {
      *error = "no candidate nodes";
    }
    return false;
  }

  const std::size_t node_count = trojan.node_count();
  const auto& po_indices = trojan.po_indices();

  z3::context ctx;
  z3::optimize opt(ctx);

  std::vector<int> flip_index_by_node(node_count, -1);
  std::vector<z3::expr> flip_vars;
  flip_vars.reserve(candidate_nodes.size());
  for (std::size_t i = 0; i < candidate_nodes.size(); ++i) {
    const int node_idx = candidate_nodes[i];
    if (node_idx < 0 || static_cast<std::size_t>(node_idx) >= node_count) {
      if (error) {
        *error = "candidate node index out of range";
      }
      return false;
    }
    flip_index_by_node[static_cast<std::size_t>(node_idx)] =
        static_cast<int>(flip_vars.size());
    flip_vars.push_back(ctx.bool_const(("flip_" + std::to_string(node_idx)).c_str()));
    if (forced_mask[static_cast<std::size_t>(node_idx)]) {
      opt.add(flip_vars.back());
    }
  }

  if (!flip_vars.empty()) {
    z3::expr_vector costs(ctx);
    for (const auto& flip_var : flip_vars) {
      costs.push_back(z3::ite(flip_var, ctx.int_val(1), ctx.int_val(0)));
    }
    opt.minimize(z3::sum(costs));
  }

  for (std::size_t idx : sample_indices) {
    if (idx >= patterns.size() || idx >= golden_outputs_list.size()) {
      if (error) {
        *error = "pattern index out of range";
      }
      return false;
    }
    const auto& pattern = patterns[idx];
    const auto& golden_outputs = golden_outputs_list[idx];
    if (pattern.size() != trojan.pi_count()) {
      if (error) {
        *error = "pattern size mismatch with PI count";
      }
      return false;
    }
    if (golden_outputs.size() != po_indices.size()) {
      if (error) {
        *error = "golden output size mismatch with PO count";
      }
      return false;
    }

    const std::string prefix = "p" + std::to_string(idx) + "_";
    std::vector<z3::expr> vars = make_node_vars(ctx, prefix, node_count);
    if (!add_circuit_constraints_with_flips(ctx,
                                            trojan,
                                            pattern,
                                            vars,
                                            flip_index_by_node,
                                            flip_vars,
                                            opt,
                                            error)) {
      return false;
    }

    for (std::size_t pos = 0; pos < po_indices.size(); ++pos) {
      const int po_idx = po_indices[pos];
      if (po_idx < 0 || static_cast<std::size_t>(po_idx) >= vars.size()) {
        if (error) {
          *error = "PO index out of range";
        }
        return false;
      }
      opt.add(vars[static_cast<std::size_t>(po_idx)] ==
              ctx.bool_val(golden_outputs[pos] != 0));
    }
  }

  const z3::check_result res = opt.check();
  if (res == z3::unsat) {
    if (error) {
      *error = "MAXSAT unsat";
    }
    return false;
  }
  if (res == z3::unknown) {
    if (error) {
      *error = "MAXSAT unknown";
    }
    return false;
  }

  z3::model model = opt.get_model();
  for (std::size_t i = 0; i < flip_vars.size(); ++i) {
    z3::expr val = model.eval(flip_vars[i], true);
    if (val.is_true()) {
      selected_nodes->push_back(candidate_nodes[i]);
    }
  }

  return true;
}

}  // namespace

void analyze_payload_nodes(const circuit& golden,
                           const circuit& trojan,
                           const PatternStats& stats,
                           const MiningResult& result,
                           int rule_match_node_idx,
                           std::vector<int>* fix_nodes_out) {
  if (stats.trigger_patterns.empty()) {
    std::cout << "payload_analysis skipped: no error patterns\n";
    return;
  }
  if (trojan.po_count() == 0) {
    std::cout << "payload_analysis skipped: no PO\n";
    return;
  }
  if (result.model.rules.empty()) {
    std::cout << "payload_rule_check skipped: no rules\n";
    return;
  }

  const std::size_t node_count = trojan.node_count();
  const std::size_t po_count = trojan.po_count();
  const auto& po_indices = trojan.po_indices();
  const std::size_t pattern_count = stats.trigger_patterns.size();

  std::vector<char> forbidden_mask(node_count, 0);
  if (!result.model.rules.empty()) {
    std::vector<char> feature_used(result.feature_nodes.size(), 0);
    for (const auto& rule : result.model.rules) {
      for (const auto& term : rule.terms) {
        if (term.first < feature_used.size()) {
          feature_used[term.first] = 1;
        }
      }
    }
    std::vector<char> is_used_feature(node_count, 0);
    for (std::size_t i = 0; i < feature_used.size(); ++i) {
      if (!feature_used[i]) {
        continue;
      }
      const int node_idx = result.feature_nodes[i];
      if (node_idx >= 0 && static_cast<std::size_t>(node_idx) < node_count) {
        is_used_feature[static_cast<std::size_t>(node_idx)] = 1;
      }
    }
    std::vector<char> feeds_other(node_count, 0);
    std::vector<char> cone(node_count, 0);
    for (std::size_t i = 0; i < feature_used.size(); ++i) {
      if (!feature_used[i]) {
        continue;
      }
      const int node_idx = result.feature_nodes[i];
      if (node_idx < 0 || static_cast<std::size_t>(node_idx) >= node_count) {
        std::cerr << "payload_analysis feature node out of range\n";
        return;
      }
      std::fill(cone.begin(), cone.end(), 0);
      mark_fanin_cone(trojan, node_idx, &cone);
      for (std::size_t n = 0; n < node_count; ++n) {
        if (cone[n]) {
          forbidden_mask[n] = 1;
        }
      }
      for (std::size_t n = 0; n < node_count; ++n) {
        if (cone[n] && is_used_feature[n] && n != static_cast<std::size_t>(node_idx)) {
          feeds_other[n] = 1;
        }
      }
    }
    for (std::size_t i = 0; i < feature_used.size(); ++i) {
      if (!feature_used[i]) {
        continue;
      }
      const int node_idx = result.feature_nodes[i];
      if (node_idx >= 0 && static_cast<std::size_t>(node_idx) < node_count &&
          !feeds_other[static_cast<std::size_t>(node_idx)]) {
        // Allow direct rule gates as candidates if they do not feed other rule features.
        forbidden_mask[static_cast<std::size_t>(node_idx)] = 0;
      }
    }
  }
  std::size_t forbidden_count = 0;
  for (char v : forbidden_mask) {
    if (v) {
      forbidden_count += 1;
    }
  }
  std::cout << "payload_forbidden_nodes " << forbidden_count << "\n";

  std::vector<std::vector<int>> golden_outputs_list;
  {
    circuit golden_eval = golden;
    batch_compute_po(golden_eval, stats.trigger_patterns, golden_outputs_list);
  }

  std::vector<std::vector<char>> po_cones(
      po_count, std::vector<char>(node_count, 0));
  for (std::size_t i = 0; i < po_count; ++i) {
    mark_fanin_cone(trojan, po_indices[i], &po_cones[i]);
  }

  std::vector<std::size_t> remaining_indices(pattern_count);
  for (std::size_t i = 0; i < pattern_count; ++i) {
    remaining_indices[i] = i;
  }

  std::vector<char> flip_mask(node_count, 0);
  std::vector<char> forced_mask(node_count, 0);
  std::vector<int> fix_nodes;
  fix_nodes.reserve(node_count);
  std::vector<std::size_t> sample_pool;
  sample_pool.reserve(remaining_indices.size());
  std::vector<char> in_sample_pool(stats.trigger_patterns.size(), 0);

  std::mt19937 rng(1337);
  std::size_t round = 0;

  circuit trojan_eval = trojan;
  while (!remaining_indices.empty()) {
    round += 1;
    std::shuffle(remaining_indices.begin(), remaining_indices.end(), rng);
    const std::size_t sample_size =
        std::min<std::size_t>(5, remaining_indices.size());
    std::size_t newly_sampled = 0;
    for (std::size_t i = 0;
         i < remaining_indices.size() && newly_sampled < sample_size;
         ++i) {
      const std::size_t idx = remaining_indices[i];
      if (idx >= in_sample_pool.size()) {
        continue;
      }
      if (in_sample_pool[idx]) {
        continue;
      }
      in_sample_pool[idx] = 1;
      sample_pool.push_back(idx);
      newly_sampled += 1;
    }
    if (sample_pool.empty()) {
      std::cout << "payload_maxsat_round " << round
                << " sample 0\n";
      break;
    }

    std::string error;
    std::vector<int> candidate_nodes =
        collect_candidate_nodes(trojan,
                                stats.trigger_patterns,
                                golden_outputs_list,
                                sample_pool,
                                po_cones,
                                forbidden_mask,
                                forced_mask,
                                &error);
    if (!error.empty()) {
      std::cerr << "payload_maxsat candidate error: " << error << "\n";
      break;
    }
    if (candidate_nodes.empty()) {
      std::cout << "payload_maxsat_round " << round
                << " candidates 0\n";
      break;
    }

    std::cout << "payload_maxsat_round " << round
              << " sample " << sample_pool.size()
              << " candidates " << candidate_nodes.size()
              << " remaining " << remaining_indices.size() << "\n";

    std::vector<int> batch_nodes;
    if (!solve_maxsat_batch(trojan,
                            stats.trigger_patterns,
                            golden_outputs_list,
                            sample_pool,
                            candidate_nodes,
                            forced_mask,
                            &batch_nodes,
                            &error)) {
      if (!error.empty()) {
        std::cerr << "payload_maxsat error: " << error << "\n";
      }
      break;
    }

    std::fill(flip_mask.begin(), flip_mask.end(), 0);
    fix_nodes.clear();
    for (int node_idx : batch_nodes) {
      if (node_idx < 0 ||
          static_cast<std::size_t>(node_idx) >= flip_mask.size()) {
        continue;
      }
      if (forbidden_mask[static_cast<std::size_t>(node_idx)]) {
        std::cout << "payload_maxsat_skip_forbidden "
                  << trojan.node_name(node_idx) << "\n";
        continue;
      }
      flip_mask[static_cast<std::size_t>(node_idx)] = 1;
      fix_nodes.push_back(node_idx);
    }

    std::cout << "payload_maxsat_round " << round
              << " flips " << batch_nodes.size()
              << " new " << fix_nodes.size() << "\n";

    // ── Phase 1: Batch simulate trojan to determine rule matches ──────────
    std::vector<std::size_t> rule_matched;
    std::size_t rule_miss = 0;
    {
      batch_simulator sim_t(trojan_eval);
      const std::size_t mwb = sim_t.max_wb();
      std::size_t off = 0;
      while (off < remaining_indices.size()) {
        const std::size_t cnt = std::min(mwb * batch_simulator::kBits,
                                         remaining_indices.size() - off);
        const std::size_t cwb = sim_t.pack_indexed_patterns(
            stats.trigger_patterns, remaining_indices.data() + off, cnt);
        sim_t.simulate(cwb, cnt);

        for (std::size_t p = 0; p < cnt; ++p) {
          bool match = false;
          if (rule_match_node_idx >= 0) {
            match = sim_t.node_value(rule_match_node_idx, p) != 0;
          } else {
            std::vector<int> features(result.feature_nodes.size());
            for (std::size_t f = 0; f < result.feature_nodes.size(); ++f) {
              features[f] = sim_t.node_value(result.feature_nodes[f], p);
            }
            match = eval_rules(result.model.rules, features);
          }
          if (match) {
            rule_matched.push_back(remaining_indices[off + p]);
          } else {
            rule_miss += 1;
          }
        }
        off += cnt;
      }
    }

    // ── Phase 2: Batch simulate flipped circuit on ALL patterns ──────────
    std::vector<std::size_t> new_remaining;
    std::size_t fixed_count = 0;
    if (!fix_nodes.empty()) {
      circuit flipped = trojan;
      for (int idx : fix_nodes) {
        flipped.invert_gate_type(idx);
      }
      batch_simulator sim_flip(flipped, golden.node_count());
      const std::size_t mwb = sim_flip.max_wb();
      std::size_t off = 0;
      while (off < pattern_count) {
        const std::size_t cnt = std::min(mwb * batch_simulator::kBits,
                                         pattern_count - off);
        const std::size_t cwb = sim_flip.pack_patterns(
            stats.trigger_patterns, off, cnt);
        sim_flip.simulate(cwb, cnt);

        for (std::size_t p = 0; p < cnt; ++p) {
          const std::size_t pat_idx = off + p;
          const auto& golden_out = golden_outputs_list[pat_idx];
          bool match = true;
          for (std::size_t o = 0; o < po_count && match; ++o) {
            if (sim_flip.po_value(o, p) != golden_out[o]) {
              match = false;
            }
          }
          if (match) {
            fixed_count += 1;
          } else {
            new_remaining.push_back(pat_idx);
          }
        }
        off += cnt;
      }
    }

    std::cout << "payload_maxsat_round " << round
              << " fixed " << fixed_count
              << " rule_unmatched " << rule_miss
              << " remaining " << new_remaining.size() << "\n";

    if (new_remaining.size() == remaining_indices.size() &&
        newly_sampled == 0) {
      std::cout << "payload_maxsat_stuck round " << round << "\n";
      break;
    }
    remaining_indices.swap(new_remaining);
  }

  std::cout << "payload_fix_nodes " << fix_nodes.size() << "\n";
  for (int idx : fix_nodes) {
    std::cout << "payload_fix_node " << trojan.node_name(idx) << "\n";
  }
  if (!remaining_indices.empty()) {
    std::cout << "payload_fix_incomplete remaining "
              << remaining_indices.size() << "\n";
  }

  if (fix_nodes_out) {
    *fix_nodes_out = fix_nodes;
  }
}
