#include "sat_refine.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <z3++.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "../core/packed_circuit.hpp"

namespace {

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

}  // namespace

namespace {

using RuleMiterClock = std::chrono::steady_clock;

constexpr std::size_t kRuleMiterHardCounterexampleLimit = 5;

struct RuleMiterAlignment {
  // For each Trojan PI position, the corresponding Golden PI position.
  std::vector<std::size_t> trojan_pi_to_golden_pos;
  // Golden/Trojan PO node indices paired by output name, in Golden PO order.
  std::vector<std::pair<int, int>> po_node_pairs;
};

struct ScalarRuleResult {
  bool error_pattern = false;
  bool rule_matches = false;
};

bool validate_rule_miter_dag(const circuit& net,
                             const char* circuit_name,
                             std::string* error) {
  const std::size_t node_count = net.node_count();
  std::vector<std::size_t> indegree(node_count, 0);
  std::vector<std::vector<int>> fanout(node_count);
  std::size_t gate_count = 0;

  for (std::size_t idx = 0; idx < node_count; ++idx) {
    const cell& node = net.get_cell(static_cast<int>(idx));
    if (node.ctype == CType::UNDEF) {
      if (error) {
        *error = std::string(circuit_name) + " contains undefined node: " +
                 net.node_name(static_cast<int>(idx));
      }
      return false;
    }
    if (node.ctype != CType::GATE) continue;
    gate_count += 1;
    if (node.inputs.empty()) {
      if (error) {
        *error = std::string(circuit_name) + " gate has no inputs: " +
                 net.node_name(static_cast<int>(idx));
      }
      return false;
    }
    for (int input_idx : node.inputs) {
      if (input_idx < 0 ||
          static_cast<std::size_t>(input_idx) >= node_count) {
        if (error) {
          *error = std::string(circuit_name) +
                   " gate input index out of range: " +
                   net.node_name(static_cast<int>(idx));
        }
        return false;
      }
      const cell& input = net.get_cell(input_idx);
      if (input.ctype == CType::UNDEF) {
        if (error) {
          *error = std::string(circuit_name) +
                   " gate references undefined input: " +
                   net.node_name(static_cast<int>(idx));
        }
        return false;
      }
      if (input.ctype == CType::GATE) {
        indegree[idx] += 1;
        fanout[static_cast<std::size_t>(input_idx)].push_back(
            static_cast<int>(idx));
      }
    }
  }

  std::queue<int> ready;
  for (std::size_t idx = 0; idx < node_count; ++idx) {
    if (net.get_cell(static_cast<int>(idx)).ctype == CType::GATE &&
        indegree[idx] == 0) {
      ready.push(static_cast<int>(idx));
    }
  }

  std::size_t visited_gates = 0;
  while (!ready.empty()) {
    const int node_idx = ready.front();
    ready.pop();
    visited_gates += 1;
    for (int next_idx : fanout[static_cast<std::size_t>(node_idx)]) {
      std::size_t& next_indegree =
          indegree[static_cast<std::size_t>(next_idx)];
      if (next_indegree == 0) {
        if (error) {
          *error = std::string(circuit_name) +
                   " DAG validation encountered invalid indegree";
        }
        return false;
      }
      next_indegree -= 1;
      if (next_indegree == 0) ready.push(next_idx);
    }
  }

  if (visited_gates != gate_count) {
    if (error) {
      *error = std::string(circuit_name) +
               " combinational cycle detected";
    }
    return false;
  }
  return true;
}

double rule_miter_elapsed_ms(RuleMiterClock::time_point start) {
  return std::chrono::duration<double, std::milli>(
             RuleMiterClock::now() - start)
      .count();
}

bool rule_miter_budget_expired(RuleMiterClock::time_point start,
                               std::uint64_t timeout_ms) {
  if (timeout_ms == 0) return true;
  const long double elapsed = static_cast<long double>(
      rule_miter_elapsed_ms(start));
  return elapsed >= static_cast<long double>(timeout_ms);
}

unsigned rule_miter_remaining_timeout_ms(
    RuleMiterClock::time_point start,
    std::uint64_t timeout_ms) {
  const long double elapsed = static_cast<long double>(
      rule_miter_elapsed_ms(start));
  const long double remaining =
      static_cast<long double>(timeout_ms) - elapsed;
  if (remaining <= 0.0L) return 0;
  const long double rounded = std::ceil(remaining);
  const long double max_unsigned = static_cast<long double>(
      std::numeric_limits<unsigned>::max());
  return static_cast<unsigned>(std::max<long double>(
      1.0L, std::min(rounded, max_unsigned)));
}

bool build_named_node_map(const circuit& net,
                          const std::vector<int>& indices,
                          const char* kind,
                          std::unordered_map<std::string, int>* by_name,
                          std::string* error) {
  if (!by_name) {
    if (error) *error = std::string("null ") + kind + " name map";
    return false;
  }
  by_name->clear();
  by_name->reserve(indices.size());
  for (int node_idx : indices) {
    if (node_idx < 0 ||
        static_cast<std::size_t>(node_idx) >= net.node_count()) {
      if (error) *error = std::string(kind) + " node index out of range";
      return false;
    }
    const std::string& name = net.node_name(node_idx);
    if (name.empty()) {
      if (error) *error = std::string(kind) + " has an empty name";
      return false;
    }
    if (!by_name->emplace(name, node_idx).second) {
      if (error) {
        *error = std::string("duplicate ") + kind + " name: " + name;
      }
      return false;
    }
  }
  return true;
}

bool build_rule_miter_alignment(const circuit& golden,
                                const circuit& trojan,
                                RuleMiterAlignment* alignment,
                                std::string* error) {
  if (!alignment) {
    if (error) *error = "null rule-miter alignment output";
    return false;
  }

  std::unordered_map<std::string, int> golden_pi_by_name;
  std::unordered_map<std::string, int> trojan_pi_by_name;
  if (!build_named_node_map(golden, golden.pi_indices(), "Golden PI",
                            &golden_pi_by_name, error) ||
      !build_named_node_map(trojan, trojan.pi_indices(), "Trojan PI",
                            &trojan_pi_by_name, error)) {
    return false;
  }
  if (golden_pi_by_name.size() != trojan_pi_by_name.size()) {
    if (error) *error = "Golden/Trojan PI count mismatch";
    return false;
  }

  std::unordered_map<std::string, std::size_t> golden_pi_pos;
  golden_pi_pos.reserve(golden.pi_count());
  for (std::size_t pos = 0; pos < golden.pi_indices().size(); ++pos) {
    golden_pi_pos.emplace(golden.node_name(golden.pi_indices()[pos]), pos);
  }

  alignment->trojan_pi_to_golden_pos.clear();
  alignment->trojan_pi_to_golden_pos.reserve(trojan.pi_count());
  for (int trojan_pi : trojan.pi_indices()) {
    const std::string& name = trojan.node_name(trojan_pi);
    const auto it = golden_pi_pos.find(name);
    if (it == golden_pi_pos.end()) {
      if (error) *error = "Trojan PI missing from Golden circuit: " + name;
      return false;
    }
    alignment->trojan_pi_to_golden_pos.push_back(it->second);
  }
  for (int golden_pi : golden.pi_indices()) {
    const std::string& name = golden.node_name(golden_pi);
    if (trojan_pi_by_name.find(name) == trojan_pi_by_name.end()) {
      if (error) *error = "Golden PI missing from Trojan circuit: " + name;
      return false;
    }
  }

  std::unordered_map<std::string, int> golden_po_by_name;
  std::unordered_map<std::string, int> trojan_po_by_name;
  if (!build_named_node_map(golden, golden.po_indices(), "Golden PO",
                            &golden_po_by_name, error) ||
      !build_named_node_map(trojan, trojan.po_indices(), "Trojan PO",
                            &trojan_po_by_name, error)) {
    return false;
  }
  if (golden_po_by_name.size() != trojan_po_by_name.size()) {
    if (error) *error = "Golden/Trojan PO count mismatch";
    return false;
  }

  alignment->po_node_pairs.clear();
  alignment->po_node_pairs.reserve(golden.po_count());
  for (int golden_po : golden.po_indices()) {
    const std::string& name = golden.node_name(golden_po);
    const auto it = trojan_po_by_name.find(name);
    if (it == trojan_po_by_name.end()) {
      if (error) *error = "Golden PO missing from Trojan circuit: " + name;
      return false;
    }
    alignment->po_node_pairs.emplace_back(golden_po, it->second);
  }
  for (int trojan_po : trojan.po_indices()) {
    const std::string& name = trojan.node_name(trojan_po);
    if (golden_po_by_name.find(name) == golden_po_by_name.end()) {
      if (error) *error = "Trojan PO missing from Golden circuit: " + name;
      return false;
    }
  }
  return true;
}

bool validate_rule_miter_model(const circuit& trojan,
                               const std::vector<int>& feature_nodes,
                               const DecisionTreeModel& model,
                               std::string* error) {
  for (int node_idx : feature_nodes) {
    if (node_idx < 0 ||
        static_cast<std::size_t>(node_idx) >= trojan.node_count()) {
      if (error) *error = "feature node index out of range";
      return false;
    }
  }
  for (const auto& rule : model.rules) {
    for (const auto& literal : rule.terms) {
      if (literal.first >= feature_nodes.size()) {
        if (error) *error = "rule feature index out of range";
        return false;
      }
      if (literal.second != 0 && literal.second != 1) {
        if (error) *error = "rule literal value must be zero or one";
        return false;
      }
    }
  }
  return true;
}

bool scalar_evaluate_rule_miter(
    const circuit& golden,
    const circuit& trojan,
    const RuleMiterAlignment& alignment,
    const std::vector<int>& feature_nodes,
    const DecisionTreeModel& model,
    const std::vector<int>& golden_pi_values,
    ScalarRuleResult* result,
    std::string* error) {
  if (!result) {
    if (error) *error = "null scalar rule-miter result";
    return false;
  }
  if (golden_pi_values.size() != golden.pi_count()) {
    if (error) *error = "scalar Golden PI value count mismatch";
    return false;
  }
  if (alignment.trojan_pi_to_golden_pos.size() != trojan.pi_count()) {
    if (error) *error = "scalar Trojan PI alignment size mismatch";
    return false;
  }

  std::vector<int> trojan_pi_values;
  trojan_pi_values.reserve(trojan.pi_count());
  for (std::size_t golden_pos : alignment.trojan_pi_to_golden_pos) {
    if (golden_pos >= golden_pi_values.size()) {
      if (error) *error = "scalar Trojan PI alignment position out of range";
      return false;
    }
    trojan_pi_values.push_back(golden_pi_values[golden_pos] ? 1 : 0);
  }

  try {
    circuit golden_eval = golden;
    circuit trojan_eval = trojan;
    (void)golden_eval.simulate(golden_pi_values);
    (void)trojan_eval.simulate(trojan_pi_values);

    result->error_pattern = false;
    for (const auto& po_pair : alignment.po_node_pairs) {
      const int golden_value = golden_eval.get_cell(po_pair.first).val;
      const int trojan_value = trojan_eval.get_cell(po_pair.second).val;
      if ((golden_value != 0) != (trojan_value != 0)) {
        result->error_pattern = true;
        break;
      }
    }

    result->rule_matches = false;
    for (const auto& rule : model.rules) {
      bool clause_matches = true;
      for (const auto& literal : rule.terms) {
        if (literal.first >= feature_nodes.size()) {
          if (error) *error = "scalar rule feature index out of range";
          return false;
        }
        const int node_idx = feature_nodes[literal.first];
        const bool value = trojan_eval.get_cell(node_idx).val != 0;
        if (value != (literal.second != 0)) {
          clause_matches = false;
          break;
        }
      }
      if (clause_matches) {
        result->rule_matches = true;
        break;
      }
    }
  } catch (const std::exception& exception) {
    if (error) {
      *error = std::string("scalar rule-miter simulation failed: ") +
               exception.what();
    }
    return false;
  }
  return true;
}

bool parse_rule_miter_bits(const std::string& bits,
                           std::size_t pi_count,
                           std::vector<int>* values,
                           std::string* error) {
  if (!values) {
    if (error) *error = "null blocked PI value output";
    return false;
  }
  if (bits.size() != pi_count) {
    if (error) *error = "blocked PI bit string has the wrong length";
    return false;
  }
  values->clear();
  values->reserve(bits.size());
  for (char bit : bits) {
    if (bit != '0' && bit != '1') {
      if (error) *error = "blocked PI bit string is not binary";
      return false;
    }
    values->push_back(bit == '1' ? 1 : 0);
  }
  return true;
}

z3::expr make_rule_miter_block(z3::context& ctx,
                               const std::vector<z3::expr>& golden_pi_vars,
                               const std::vector<int>& values) {
  z3::expr block = ctx.bool_val(false);
  for (std::size_t i = 0; i < golden_pi_vars.size(); ++i) {
    block = block ||
            (golden_pi_vars[i] != ctx.bool_val(values[i] != 0));
  }
  return block;
}

bool rule_miter_reason_is_timeout(const std::string& reason) {
  std::string lower = reason;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  return lower.find("timeout") != std::string::npos ||
         lower.find("canceled") != std::string::npos;
}

RuleMiterSideResult* rule_miter_side(RuleMiterResult* result,
                                     bool false_negative) {
  return false_negative ? &result->false_negative : &result->false_positive;
}

void finish_rule_miter_result(RuleMiterResult* result,
                              RuleMiterStatus fallback_status,
                              const std::string& reason,
                              RuleMiterClock::time_point total_start) {
  if (!result) return;
  result->status = aggregate_rule_miter_status(*result, fallback_status);
  if (!reason.empty()) {
    if (result->status == RuleMiterStatus::counterexamples &&
        fallback_status != RuleMiterStatus::counterexamples) {
      result->reason =
          "validated counterexample exists; remaining search incomplete: " +
          reason;
    } else {
      result->reason = reason;
    }
  } else {
    switch (result->status) {
      case RuleMiterStatus::proved:
        result->reason.clear();
        break;
      case RuleMiterStatus::counterexamples:
        result->reason = "rule and circuit error predicate differ";
        break;
      case RuleMiterStatus::timeout:
        result->reason = "one or more rule-miter queries timed out";
        break;
      case RuleMiterStatus::unknown:
        result->reason = "one or more rule-miter queries are unknown";
        break;
      case RuleMiterStatus::invalid:
        result->reason = "invalid rule-miter input or state";
        break;
    }
  }
  result->total_ms = rule_miter_elapsed_ms(total_start);
}

}  // namespace

const char* rule_miter_query_status_name(RuleMiterQueryStatus status) {
  switch (status) {
    case RuleMiterQueryStatus::not_checked:
      return "not_checked";
    case RuleMiterQueryStatus::sat:
      return "sat";
    case RuleMiterQueryStatus::unsat:
      return "unsat";
    case RuleMiterQueryStatus::timeout:
      return "timeout";
    case RuleMiterQueryStatus::unknown:
      return "unknown";
  }
  return "unknown";
}

RuleMiterSideResult transition_rule_miter_side(
    const RuleMiterSideResult& current,
    RuleMiterQueryStatus observed_status,
    const std::string& reason) {
  RuleMiterSideResult next = current;
  if (observed_status == RuleMiterQueryStatus::unsat) {
    next.exhausted = true;
  } else if (observed_status == RuleMiterQueryStatus::timeout ||
             observed_status == RuleMiterQueryStatus::unknown ||
             observed_status == RuleMiterQueryStatus::not_checked) {
    next.exhausted = false;
  }

  const bool has_validated_witness = next.models_found != 0;
  if (has_validated_witness &&
      observed_status != RuleMiterQueryStatus::sat) {
    next.status = RuleMiterQueryStatus::sat;
    if (!reason.empty()) {
      if (!next.reason.empty()) next.reason += "; ";
      next.reason += "remaining search ";
      next.reason += rule_miter_query_status_name(observed_status);
      next.reason += ": ";
      next.reason += reason;
    }
    return next;
  }

  next.status = observed_status;
  if (!reason.empty()) next.reason = reason;
  return next;
}

RuleMiterStatus aggregate_rule_miter_status(
    const RuleMiterResult& result,
    RuleMiterStatus fallback_status) {
  const bool has_validated_witness =
      result.false_negative.models_found != 0 ||
      result.false_positive.models_found != 0;
  if (has_validated_witness) return RuleMiterStatus::counterexamples;

  if (fallback_status == RuleMiterStatus::invalid) {
    return RuleMiterStatus::invalid;
  }
  if (fallback_status == RuleMiterStatus::timeout) {
    return RuleMiterStatus::timeout;
  }
  if (fallback_status == RuleMiterStatus::unknown) {
    return RuleMiterStatus::unknown;
  }

  const RuleMiterQueryStatus fn_status = result.false_negative.status;
  const RuleMiterQueryStatus fp_status = result.false_positive.status;
  if (fn_status == RuleMiterQueryStatus::timeout ||
      fp_status == RuleMiterQueryStatus::timeout) {
    return RuleMiterStatus::timeout;
  }
  if (fn_status == RuleMiterQueryStatus::unknown ||
      fp_status == RuleMiterQueryStatus::unknown ||
      fn_status == RuleMiterQueryStatus::not_checked ||
      fp_status == RuleMiterQueryStatus::not_checked) {
    return RuleMiterStatus::unknown;
  }
  if (fn_status == RuleMiterQueryStatus::unsat &&
      fp_status == RuleMiterQueryStatus::unsat) {
    return RuleMiterStatus::proved;
  }
  return fallback_status == RuleMiterStatus::counterexamples
             ? RuleMiterStatus::counterexamples
             : RuleMiterStatus::unknown;
}

const char* rule_miter_status_name(RuleMiterStatus status) {
  switch (status) {
    case RuleMiterStatus::proved:
      return "proved";
    case RuleMiterStatus::counterexamples:
      return "counterexamples";
    case RuleMiterStatus::timeout:
      return "timeout";
    case RuleMiterStatus::unknown:
      return "unknown";
    case RuleMiterStatus::invalid:
      return "invalid";
  }
  return "invalid";
}

RuleMiterResult check_rule_miter(
    const circuit& golden,
    const circuit& trojan,
    const std::vector<int>& feature_nodes,
    const DecisionTreeModel& model,
    const RuleMiterOptions& options,
    const std::unordered_set<std::string>* blocked_pi_bits) {
  const RuleMiterClock::time_point total_start = RuleMiterClock::now();
  RuleMiterResult result;
  result.requested_counterexample_limit = options.max_counterexamples;
  result.effective_counterexample_limit = std::min(
      options.max_counterexamples, kRuleMiterHardCounterexampleLimit);

  try {
    if (options.timeout_ms == 0) {
      result.false_negative = transition_rule_miter_side(
          result.false_negative, RuleMiterQueryStatus::timeout,
          "soft wall-clock budget is zero");
      result.false_positive = transition_rule_miter_side(
          result.false_positive, RuleMiterQueryStatus::timeout,
          "soft wall-clock budget is zero");
      finish_rule_miter_result(&result, RuleMiterStatus::timeout,
                               "rule-miter wall-clock budget is zero",
                               total_start);
      return result;
    }

    RuleMiterAlignment alignment;
    std::string error;
    if (!build_rule_miter_alignment(golden, trojan, &alignment, &error) ||
        !validate_rule_miter_model(trojan, feature_nodes, model, &error)) {
      finish_rule_miter_result(&result, RuleMiterStatus::invalid, error,
                               total_start);
      return result;
    }

    // Validate from the live graph instead of trusting circuit's cached
    // eval_order: replace_gate_inputs() can change topology without
    // invalidating that cache.
    if (!validate_rule_miter_dag(golden, "Golden", &error) ||
        !validate_rule_miter_dag(trojan, "Trojan", &error)) {
      finish_rule_miter_result(&result, RuleMiterStatus::invalid, error,
                               total_start);
      return result;
    }

    std::vector<std::string> sorted_blocked_bits;
    if (blocked_pi_bits) {
      sorted_blocked_bits.assign(blocked_pi_bits->begin(),
                                 blocked_pi_bits->end());
      std::sort(sorted_blocked_bits.begin(), sorted_blocked_bits.end());
    }
    std::vector<std::vector<int>> blocked_patterns;
    blocked_patterns.reserve(sorted_blocked_bits.size());
    for (const std::string& bits : sorted_blocked_bits) {
      if (rule_miter_budget_expired(total_start, options.timeout_ms)) {
        result.false_negative = transition_rule_miter_side(
            result.false_negative, RuleMiterQueryStatus::timeout,
            "soft deadline expired while validating blocked patterns");
        result.false_positive = transition_rule_miter_side(
            result.false_positive, RuleMiterQueryStatus::timeout,
            "soft deadline expired while validating blocked patterns");
        finish_rule_miter_result(
            &result, RuleMiterStatus::timeout,
            "rule-miter deadline expired while validating blocked patterns",
            total_start);
        return result;
      }
      std::vector<int> values;
      if (!parse_rule_miter_bits(bits, golden.pi_count(), &values, &error)) {
        finish_rule_miter_result(&result, RuleMiterStatus::invalid, error,
                                 total_start);
        return result;
      }
      const RuleMiterClock::time_point validation_start = RuleMiterClock::now();
      ScalarRuleResult scalar;
      if (!scalar_evaluate_rule_miter(golden, trojan, alignment, feature_nodes,
                                      model, values, &scalar, &error)) {
        result.validation_ms += rule_miter_elapsed_ms(validation_start);
        finish_rule_miter_result(&result, RuleMiterStatus::invalid, error,
                                 total_start);
        return result;
      }
      result.validation_ms += rule_miter_elapsed_ms(validation_start);
      if (scalar.error_pattern != scalar.rule_matches) {
        RuleMiterSideResult* side = rule_miter_side(
            &result, scalar.error_pattern && !scalar.rule_matches);
        side->models_found += 1;
        side->blocked_violations += 1;
        *side = transition_rule_miter_side(
            *side, RuleMiterQueryStatus::sat,
            "blocked assignment remains a validated counterexample");
      }
      blocked_patterns.push_back(std::move(values));
    }

    if (rule_miter_budget_expired(total_start, options.timeout_ms)) {
      result.false_negative = transition_rule_miter_side(
          result.false_negative, RuleMiterQueryStatus::timeout,
          "soft deadline expired before circuit encoding");
      result.false_positive = transition_rule_miter_side(
          result.false_positive, RuleMiterQueryStatus::timeout,
          "soft deadline expired before circuit encoding");
      finish_rule_miter_result(
          &result, RuleMiterStatus::timeout,
          "rule-miter deadline expired before circuit encoding", total_start);
      return result;
    }

    const RuleMiterClock::time_point encode_start = RuleMiterClock::now();
    z3::context ctx;
    z3::solver solver(ctx);

    std::vector<z3::expr> golden_pi_vars;
    golden_pi_vars.reserve(golden.pi_count());
    for (std::size_t i = 0; i < golden.pi_count(); ++i) {
      golden_pi_vars.push_back(
          ctx.bool_const(("rule_miter_pi_" + std::to_string(i)).c_str()));
    }

    std::vector<z3::expr> trojan_pi_vars;
    trojan_pi_vars.reserve(trojan.pi_count());
    for (std::size_t golden_pos : alignment.trojan_pi_to_golden_pos) {
      trojan_pi_vars.push_back(golden_pi_vars[golden_pos]);
    }

    std::vector<z3::expr> golden_vars =
        make_node_vars(ctx, "rule_miter_g_", golden.node_count());
    std::vector<z3::expr> trojan_vars =
        make_node_vars(ctx, "rule_miter_t_", trojan.node_count());
    if (!add_circuit_constraints(ctx, golden, golden_vars, golden_pi_vars,
                                 solver, -1, nullptr, &error) ||
        !add_circuit_constraints(ctx, trojan, trojan_vars, trojan_pi_vars,
                                 solver, -1, nullptr, &error)) {
      result.encode_ms = rule_miter_elapsed_ms(encode_start);
      finish_rule_miter_result(&result, RuleMiterStatus::invalid, error,
                               total_start);
      return result;
    }

    z3::expr error_expr = ctx.bool_val(false);
    for (const auto& po_pair : alignment.po_node_pairs) {
      error_expr =
          error_expr ||
          (golden_vars[static_cast<std::size_t>(po_pair.first)] !=
           trojan_vars[static_cast<std::size_t>(po_pair.second)]);
    }

    z3::expr rule_expr = ctx.bool_val(false);
    for (const auto& rule : model.rules) {
      z3::expr clause_expr = ctx.bool_val(true);
      for (const auto& literal : rule.terms) {
        const int node_idx = feature_nodes[literal.first];
        clause_expr =
            clause_expr &&
            (trojan_vars[static_cast<std::size_t>(node_idx)] ==
             ctx.bool_val(literal.second != 0));
      }
      rule_expr = rule_expr || clause_expr;
    }

    for (const auto& values : blocked_patterns) {
      solver.add(make_rule_miter_block(ctx, golden_pi_vars, values));
    }
    result.encode_ms = rule_miter_elapsed_ms(encode_start);

    if (rule_miter_budget_expired(total_start, options.timeout_ms)) {
      result.false_negative = transition_rule_miter_side(
          result.false_negative, RuleMiterQueryStatus::timeout,
          "soft deadline expired during circuit encoding");
      result.false_positive = transition_rule_miter_side(
          result.false_positive, RuleMiterQueryStatus::timeout,
          "soft deadline expired during circuit encoding");
      finish_rule_miter_result(
          &result, RuleMiterStatus::timeout,
          "rule-miter deadline expired during circuit encoding", total_start);
      return result;
    }

    const z3::expr false_negative_expr = error_expr && !rule_expr;
    const z3::expr false_positive_expr = !error_expr && rule_expr;
    bool closed[2] = {false, false};
    bool attempted[2] = {false, false};
    bool take_false_negative = true;

    while (!(closed[0] && closed[1])) {
      const bool capacity_available =
          result.counterexamples.size() <
          result.effective_counterexample_limit;
      if (!capacity_available && attempted[0] && attempted[1]) break;

      int side_index = take_false_negative ? 0 : 1;
      if (closed[side_index] ||
          (!capacity_available && attempted[side_index])) {
        side_index = 1 - side_index;
      }
      if (closed[side_index] ||
          (!capacity_available && attempted[side_index])) {
        break;
      }
      take_false_negative = side_index != 0;
      const bool is_false_negative = side_index == 0;
      RuleMiterSideResult* side =
          rule_miter_side(&result, is_false_negative);
      attempted[side_index] = true;

      const unsigned remaining = rule_miter_remaining_timeout_ms(
          total_start, options.timeout_ms);
      if (remaining == 0) {
        *side = transition_rule_miter_side(
            *side, RuleMiterQueryStatus::timeout,
            "shared soft rule-miter deadline expired");
        closed[side_index] = true;
        break;
      }
      z3::params params(ctx);
      params.set("timeout", remaining);
      params.set("random_seed", 0U);
      solver.set(params);

      solver.push();
      solver.add(is_false_negative ? false_negative_expr
                                   : false_positive_expr);
      const RuleMiterClock::time_point solver_start = RuleMiterClock::now();
      result.solver_checks += 1;
      const z3::check_result check = solver.check();
      result.solver_ms += rule_miter_elapsed_ms(solver_start);

      if (rule_miter_budget_expired(total_start, options.timeout_ms)) {
        solver.pop();
        *side = transition_rule_miter_side(
            *side, RuleMiterQueryStatus::timeout,
            "shared soft rule-miter deadline expired during SAT check");
        closed[side_index] = true;
        break;
      }

      if (check == z3::unsat) {
        solver.pop();
        *side = transition_rule_miter_side(
            *side, RuleMiterQueryStatus::unsat,
            "all remaining assignments are exhausted");
        closed[side_index] = true;
        continue;
      }
      if (check == z3::unknown) {
        const std::string reason = solver.reason_unknown();
        solver.pop();
        const bool timed_out =
            rule_miter_reason_is_timeout(reason) ||
            rule_miter_budget_expired(total_start, options.timeout_ms);
        *side = transition_rule_miter_side(
            *side,
            timed_out ? RuleMiterQueryStatus::timeout
                      : RuleMiterQueryStatus::unknown,
            reason.empty() ? "Z3 returned unknown" : reason);
        closed[side_index] = true;
        continue;
      }

      const z3::model z3_model = solver.get_model();
      std::vector<int> golden_pi_values;
      golden_pi_values.reserve(golden_pi_vars.size());
      bool model_value_error = false;
      for (const z3::expr& pi_var : golden_pi_vars) {
        const z3::expr value = z3_model.eval(pi_var, true);
        if (value.is_true()) {
          golden_pi_values.push_back(1);
        } else if (value.is_false()) {
          golden_pi_values.push_back(0);
        } else {
          model_value_error = true;
          break;
        }
      }
      solver.pop();
      if (model_value_error) {
        finish_rule_miter_result(
            &result, RuleMiterStatus::invalid,
            "Z3 returned a non-Boolean PI value for the rule miter",
            total_start);
        return result;
      }

      const RuleMiterClock::time_point validation_start =
          RuleMiterClock::now();
      ScalarRuleResult scalar;
      if (!scalar_evaluate_rule_miter(golden, trojan, alignment,
                                      feature_nodes, model,
                                      golden_pi_values, &scalar, &error)) {
        result.validation_ms += rule_miter_elapsed_ms(validation_start);
        finish_rule_miter_result(&result, RuleMiterStatus::invalid, error,
                                 total_start);
        return result;
      }
      result.validation_ms += rule_miter_elapsed_ms(validation_start);
      const bool scalar_false_negative =
          scalar.error_pattern && !scalar.rule_matches;
      const bool scalar_false_positive =
          !scalar.error_pattern && scalar.rule_matches;
      if ((is_false_negative && !scalar_false_negative) ||
          (!is_false_negative && !scalar_false_positive)) {
        finish_rule_miter_result(
            &result, RuleMiterStatus::invalid,
            "Z3 rule-miter model disagrees with scalar circuit validation",
            total_start);
        return result;
      }

      side->models_found += 1;
      *side = transition_rule_miter_side(
          *side, RuleMiterQueryStatus::sat,
          "Z3 witness passed scalar circuit validation");
      const bool can_return =
          result.counterexamples.size() <
          result.effective_counterexample_limit;
      if (can_return) {
        RuleMiterCounterexample counterexample;
        counterexample.pi_values = golden_pi_values;
        counterexample.kind =
            is_false_negative
                ? RuleMiterCounterexampleKind::false_negative
                : RuleMiterCounterexampleKind::false_positive;
        result.counterexamples.push_back(std::move(counterexample));
        side->counterexamples_returned += 1;
        solver.add(make_rule_miter_block(ctx, golden_pi_vars,
                                         golden_pi_values));
      } else {
        // The query has been checked and is SAT, but the hard batch cap means
        // there is no room to return or enumerate another assignment.
        closed[side_index] = true;
      }
      if (rule_miter_budget_expired(total_start, options.timeout_ms)) {
        *side = transition_rule_miter_side(
            *side, RuleMiterQueryStatus::timeout,
            "shared soft deadline expired after scalar validation");
        finish_rule_miter_result(
            &result, RuleMiterStatus::timeout,
            "shared soft deadline expired after scalar validation",
            total_start);
        return result;
      }
    }

    const bool any_timeout =
        result.false_negative.status == RuleMiterQueryStatus::timeout ||
        result.false_positive.status == RuleMiterQueryStatus::timeout;
    const bool any_unknown =
        result.false_negative.status == RuleMiterQueryStatus::unknown ||
        result.false_positive.status == RuleMiterQueryStatus::unknown ||
        result.false_negative.status == RuleMiterQueryStatus::not_checked ||
        result.false_positive.status == RuleMiterQueryStatus::not_checked;
    const bool any_counterexample =
        result.false_negative.models_found != 0 ||
        result.false_positive.models_found != 0;
    const bool both_unsat =
        result.false_negative.status == RuleMiterQueryStatus::unsat &&
        result.false_positive.status == RuleMiterQueryStatus::unsat;

    if (any_timeout) {
      finish_rule_miter_result(&result, RuleMiterStatus::timeout,
                               "one or more rule-miter queries timed out",
                               total_start);
    } else if (any_unknown) {
      finish_rule_miter_result(&result, RuleMiterStatus::unknown,
                               "one or more rule-miter queries are unknown",
                               total_start);
    } else if (any_counterexample) {
      finish_rule_miter_result(&result, RuleMiterStatus::counterexamples,
                               "rule and circuit error predicate differ",
                               total_start);
    } else if (both_unsat) {
      finish_rule_miter_result(&result, RuleMiterStatus::proved, "",
                               total_start);
    } else {
      finish_rule_miter_result(&result, RuleMiterStatus::unknown,
                               "rule-miter search ended without a proof",
                               total_start);
    }
  } catch (const z3::exception& exception) {
    const bool timed_out =
        rule_miter_budget_expired(total_start, options.timeout_ms);
    const RuleMiterQueryStatus query_status =
        timed_out ? RuleMiterQueryStatus::timeout
                  : RuleMiterQueryStatus::unknown;
    const std::string reason =
        std::string("Z3 rule-miter exception: ") + exception.what();
    result.false_negative = transition_rule_miter_side(
        result.false_negative, query_status, reason);
    result.false_positive = transition_rule_miter_side(
        result.false_positive, query_status, reason);
    finish_rule_miter_result(
        &result,
        timed_out ? RuleMiterStatus::timeout : RuleMiterStatus::unknown,
        reason, total_start);
  } catch (const std::exception& exception) {
    const std::string reason =
        std::string("rule-miter exception: ") + exception.what();
    result.false_negative = transition_rule_miter_side(
        result.false_negative, RuleMiterQueryStatus::unknown, reason);
    result.false_positive = transition_rule_miter_side(
        result.false_positive, RuleMiterQueryStatus::unknown, reason);
    finish_rule_miter_result(
        &result, RuleMiterStatus::invalid, reason, total_start);
  }
  return result;
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
