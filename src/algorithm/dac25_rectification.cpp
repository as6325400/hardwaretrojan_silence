#include "dac25_rectification.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <limits>
#include <queue>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <z3++.h>

namespace {

using Clock = std::chrono::steady_clock;

double elapsed_ms(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start)
      .count();
}

bool deadline_expired(Clock::time_point start, std::uint64_t timeout_ms) {
  if (timeout_ms == 0) return true;
  return elapsed_ms(start) >= static_cast<double>(timeout_ms);
}

unsigned remaining_timeout_ms(Clock::time_point start,
                              std::uint64_t timeout_ms) {
  if (timeout_ms == 0) return 0;
  const double remaining =
      static_cast<double>(timeout_ms) - elapsed_ms(start);
  if (remaining <= 0.0) return 0;
  const double capped = std::min(
      remaining, static_cast<double>(std::numeric_limits<unsigned>::max()));
  return std::max(1U, static_cast<unsigned>(std::ceil(capped)));
}

bool reason_is_timeout(const std::string& reason) {
  std::string lower = reason;
  std::transform(lower.begin(), lower.end(), lower.begin(), [](char c) {
    return static_cast<char>(
        std::tolower(static_cast<unsigned char>(c)));
  });
  return lower.find("timeout") != std::string::npos ||
         lower.find("canceled") != std::string::npos;
}

std::vector<z3::expr> make_vars(z3::context& ctx,
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
  if (!out || gate.inputs.empty()) {
    if (error) *error = !out ? "null gate expression output"
                             : "gate has no inputs";
    return false;
  }
  auto input = [&](std::size_t position) -> z3::expr {
    const int idx = gate.inputs.at(position);
    if (idx < 0 || static_cast<std::size_t>(idx) >= vars.size()) {
      throw std::runtime_error("gate input index out of range");
    }
    return vars[static_cast<std::size_t>(idx)];
  };

  z3::expr acc = input(0);
  switch (gate.gtype) {
    case GType::AND:
    case GType::NAND:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        acc = acc && input(i);
      }
      *out = gate.gtype == GType::NAND ? !acc : acc;
      return true;
    case GType::OR:
    case GType::NOR:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        acc = acc || input(i);
      }
      *out = gate.gtype == GType::NOR ? !acc : acc;
      return true;
    case GType::NOT:
      if (gate.inputs.size() != 1U) {
        if (error) *error = "NOT gate expects one input";
        return false;
      }
      *out = !acc;
      return true;
    case GType::BUFF:
      if (gate.inputs.size() != 1U) {
        if (error) *error = "BUFF gate expects one input";
        return false;
      }
      *out = acc;
      return true;
    case GType::XOR:
    case GType::XNOR:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        acc = (acc != input(i));
      }
      *out = gate.gtype == GType::XNOR ? !acc : acc;
      return true;
  }
  if (error) *error = "unsupported gate type";
  return false;
}

bool build_name_index(const circuit& net,
                      const std::vector<int>& indices,
                      std::unordered_map<std::string, int>* out,
                      std::string* error) {
  if (!out) return false;
  out->clear();
  for (int idx : indices) {
    if (idx < 0 || static_cast<std::size_t>(idx) >= net.node_count()) {
      if (error) *error = "signal index out of range";
      return false;
    }
    const std::string& name = net.node_name(idx);
    if (!out->emplace(name, idx).second) {
      if (error) *error = "duplicate signal name: " + name;
      return false;
    }
  }
  return true;
}

struct Alignment {
  std::vector<std::string> pi_names;
  std::vector<int> golden_po;
  std::vector<int> trojan_po;
};

bool build_alignment(const circuit& golden,
                     const circuit& trojan,
                     Alignment* alignment,
                     std::string* error) {
  if (!alignment) return false;
  std::unordered_map<std::string, int> golden_pi;
  std::unordered_map<std::string, int> trojan_pi;
  std::unordered_map<std::string, int> golden_po;
  std::unordered_map<std::string, int> trojan_po;
  if (!build_name_index(golden, golden.pi_indices(), &golden_pi, error) ||
      !build_name_index(trojan, trojan.pi_indices(), &trojan_pi, error) ||
      !build_name_index(golden, golden.po_indices(), &golden_po, error) ||
      !build_name_index(trojan, trojan.po_indices(), &trojan_po, error)) {
    return false;
  }
  if (golden_pi.size() != trojan_pi.size() ||
      golden_po.size() != trojan_po.size()) {
    if (error) *error = "PI/PO name-set size mismatch";
    return false;
  }

  alignment->pi_names.clear();
  alignment->golden_po.clear();
  alignment->trojan_po.clear();
  alignment->pi_names.reserve(golden.pi_count());
  for (int idx : golden.pi_indices()) {
    const std::string& name = golden.node_name(idx);
    if (trojan_pi.find(name) == trojan_pi.end()) {
      if (error) *error = "Trojan is missing PI named " + name;
      return false;
    }
    alignment->pi_names.push_back(name);
  }
  alignment->golden_po.reserve(golden.po_count());
  alignment->trojan_po.reserve(golden.po_count());
  for (int idx : golden.po_indices()) {
    const std::string& name = golden.node_name(idx);
    auto found = trojan_po.find(name);
    if (found == trojan_po.end()) {
      if (error) *error = "Trojan is missing PO named " + name;
      return false;
    }
    alignment->golden_po.push_back(idx);
    alignment->trojan_po.push_back(found->second);
  }
  return true;
}

bool add_circuit_constraints(
    z3::context& ctx,
    const circuit& net,
    const std::vector<z3::expr>& vars,
    const std::unordered_map<std::string, z3::expr>& shared_pi,
    const std::unordered_map<int, bool>& target_values,
    z3::solver& solver,
    std::string* error) {
  if (vars.size() != net.node_count()) {
    if (error) *error = "variable count does not match circuit";
    return false;
  }
  for (std::size_t i = 0; i < net.node_count(); ++i) {
    const int idx = static_cast<int>(i);
    auto override_it = target_values.find(idx);
    if (override_it != target_values.end()) {
      solver.add(vars[i] == ctx.bool_val(override_it->second));
      continue;
    }
    const cell& node = net.get_cell(idx);
    switch (node.ctype) {
      case CType::CONST:
        solver.add(vars[i] == ctx.bool_val(node.val != 0));
        break;
      case CType::PI: {
        auto found = shared_pi.find(net.node_name(idx));
        if (found == shared_pi.end()) {
          if (error) *error = "shared PI variable not found";
          return false;
        }
        solver.add(vars[i] == found->second);
        break;
      }
      case CType::GATE: {
        z3::expr expression = ctx.bool_val(false);
        try {
          if (!build_gate_expr(node, vars, &expression, error)) return false;
        } catch (const std::exception& e) {
          if (error) *error = e.what();
          return false;
        }
        solver.add(vars[i] == expression);
        break;
      }
      case CType::UNDEF:
        if (error) *error = "undefined circuit node: " + net.node_name(idx);
        return false;
    }
  }
  return true;
}

z3::expr mismatch_expr(z3::context& ctx,
                       const std::vector<z3::expr>& golden_vars,
                       const std::vector<z3::expr>& trojan_vars,
                       const Alignment& alignment) {
  z3::expr mismatch = ctx.bool_val(false);
  for (std::size_t i = 0; i < alignment.golden_po.size(); ++i) {
    mismatch = mismatch ||
               (golden_vars[static_cast<std::size_t>(alignment.golden_po[i])] !=
                trojan_vars[static_cast<std::size_t>(alignment.trojan_po[i])]);
  }
  return mismatch;
}

struct ObservedMismatch {
  Dac25ValidationStatus status = Dac25ValidationStatus::invalid;
  std::string reason;
  std::vector<int> pi_values;
  std::vector<int> trojan_po_nodes;
  std::vector<std::string> po_names;
  double solver_ms = 0.0;
};

ObservedMismatch find_observed_mismatch(const circuit& golden,
                                        const circuit& trojan,
                                        std::uint64_t timeout_ms) {
  ObservedMismatch result;
  const auto start = Clock::now();
  if (timeout_ms == 0) {
    result.status = Dac25ValidationStatus::timeout;
    result.reason = "zero mismatch-query budget";
    return result;
  }
  try {
    Alignment alignment;
    std::string error;
    if (!build_alignment(golden, trojan, &alignment, &error)) {
      result.status = Dac25ValidationStatus::invalid;
      result.reason = error;
      return result;
    }
    z3::context ctx;
    z3::solver solver(ctx);
    std::unordered_map<std::string, z3::expr> shared_pi;
    for (std::size_t i = 0; i < alignment.pi_names.size(); ++i) {
      shared_pi.emplace(alignment.pi_names[i],
                        ctx.bool_const(("dac25_pi_" + std::to_string(i)).c_str()));
    }
    auto golden_vars = make_vars(ctx, "dac25_obs_g_", golden.node_count());
    auto trojan_vars = make_vars(ctx, "dac25_obs_t_", trojan.node_count());
    const std::unordered_map<int, bool> no_targets;
    if (!add_circuit_constraints(ctx, golden, golden_vars, shared_pi,
                                 no_targets, solver, &error) ||
        !add_circuit_constraints(ctx, trojan, trojan_vars, shared_pi,
                                 no_targets, solver, &error)) {
      result.status = Dac25ValidationStatus::invalid;
      result.reason = error;
      return result;
    }
    solver.add(mismatch_expr(ctx, golden_vars, trojan_vars, alignment));
    const unsigned remaining = remaining_timeout_ms(start, timeout_ms);
    if (remaining == 0) {
      result.status = Dac25ValidationStatus::timeout;
      result.reason = "observed-mismatch encoding exhausted the deadline";
      return result;
    }
    z3::params params(ctx);
    params.set("timeout", remaining);
    params.set("random_seed", 0U);
    solver.set(params);
    const auto solve_start = Clock::now();
    const z3::check_result checked = solver.check();
    result.solver_ms = elapsed_ms(solve_start);
    if (checked == z3::unsat) {
      result.status = Dac25ValidationStatus::feasible;
      result.reason = "circuits are already equivalent";
      return result;
    }
    if (checked == z3::unknown) {
      result.reason = solver.reason_unknown();
      result.status = reason_is_timeout(result.reason) ||
                              deadline_expired(start, timeout_ms)
                          ? Dac25ValidationStatus::timeout
                          : Dac25ValidationStatus::unknown;
      return result;
    }
    const z3::model model = solver.get_model();
    result.pi_values.reserve(alignment.pi_names.size());
    for (const std::string& name : alignment.pi_names) {
      result.pi_values.push_back(model.eval(shared_pi.at(name), true).is_true()
                                     ? 1
                                     : 0);
    }
    for (std::size_t i = 0; i < alignment.golden_po.size(); ++i) {
      const bool golden_value =
          model.eval(golden_vars[static_cast<std::size_t>(alignment.golden_po[i])],
                     true)
              .is_true();
      const bool trojan_value =
          model.eval(trojan_vars[static_cast<std::size_t>(alignment.trojan_po[i])],
                     true)
              .is_true();
      if (golden_value != trojan_value) {
        result.trojan_po_nodes.push_back(alignment.trojan_po[i]);
        result.po_names.push_back(golden.node_name(alignment.golden_po[i]));
      }
    }
    if (result.po_names.empty()) {
      result.status = Dac25ValidationStatus::invalid;
      result.reason = "SAT mismatch model had no mismatching PO";
      return result;
    }
    result.status = Dac25ValidationStatus::infeasible;
    result.reason = "observed golden/Trojan mismatch";
    return result;
  } catch (const z3::exception& e) {
    result.reason = e.msg();
    result.status = reason_is_timeout(result.reason)
                        ? Dac25ValidationStatus::timeout
                        : Dac25ValidationStatus::unknown;
    return result;
  } catch (const std::exception& e) {
    result.status = Dac25ValidationStatus::invalid;
    result.reason = e.what();
    return result;
  }
}

bool same_gate_structure(const circuit& golden,
                         int golden_idx,
                         const circuit& trojan,
                         int trojan_idx) {
  const cell& lhs = golden.get_cell(golden_idx);
  const cell& rhs = trojan.get_cell(trojan_idx);
  if (lhs.ctype != rhs.ctype) return false;
  if (lhs.ctype == CType::CONST) return lhs.val == rhs.val;
  if (lhs.ctype != CType::GATE) return true;
  if (lhs.gtype != rhs.gtype || lhs.inputs.size() != rhs.inputs.size()) {
    return false;
  }
  std::vector<std::string> lhs_inputs;
  std::vector<std::string> rhs_inputs;
  lhs_inputs.reserve(lhs.inputs.size());
  rhs_inputs.reserve(rhs.inputs.size());
  for (int idx : lhs.inputs) lhs_inputs.push_back(golden.node_name(idx));
  for (int idx : rhs.inputs) rhs_inputs.push_back(trojan.node_name(idx));
  std::sort(lhs_inputs.begin(), lhs_inputs.end());
  std::sort(rhs_inputs.begin(), rhs_inputs.end());
  return lhs_inputs == rhs_inputs;
}

bool eval_gate_scalar(const cell& gate,
                      const std::vector<int>& values,
                      int* out) {
  if (!out || gate.inputs.empty()) return false;
  auto input = [&](std::size_t position, int* value) {
    const int idx = gate.inputs.at(position);
    if (idx < 0 || static_cast<std::size_t>(idx) >= values.size()) {
      return false;
    }
    *value = values[static_cast<std::size_t>(idx)] != 0 ? 1 : 0;
    return true;
  };
  int acc = 0;
  if (!input(0, &acc)) return false;
  switch (gate.gtype) {
    case GType::AND:
    case GType::NAND:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        int value = 0;
        if (!input(i, &value)) return false;
        acc &= value;
      }
      *out = gate.gtype == GType::NAND ? 1 - acc : acc;
      return true;
    case GType::OR:
    case GType::NOR:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        int value = 0;
        if (!input(i, &value)) return false;
        acc |= value;
      }
      *out = gate.gtype == GType::NOR ? 1 - acc : acc;
      return true;
    case GType::NOT:
      if (gate.inputs.size() != 1U) return false;
      *out = 1 - acc;
      return true;
    case GType::BUFF:
      if (gate.inputs.size() != 1U) return false;
      *out = acc;
      return true;
    case GType::XOR:
    case GType::XNOR:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) {
        int value = 0;
        if (!input(i, &value)) return false;
        acc ^= value;
      }
      *out = gate.gtype == GType::XNOR ? 1 - acc : acc;
      return true;
  }
  return false;
}

bool simulate_nodes(const circuit& net,
                    const std::unordered_map<std::string, int>& pi_values,
                    int override_node,
                    int override_value,
                    std::vector<int>* values,
                    std::string* error) {
  if (!values) return false;
  values->assign(net.node_count(), 0);
  for (std::size_t i = 0; i < net.node_count(); ++i) {
    const cell& node = net.get_cell(static_cast<int>(i));
    if (node.ctype == CType::CONST) {
      (*values)[i] = node.val != 0 ? 1 : 0;
    } else if (node.ctype == CType::PI) {
      auto found = pi_values.find(net.node_name(static_cast<int>(i)));
      if (found == pi_values.end()) {
        if (error) *error = "simulation PI value is missing";
        return false;
      }
      (*values)[i] = found->second != 0 ? 1 : 0;
    } else if (node.ctype == CType::UNDEF) {
      if (error) *error = "simulation encountered undefined node";
      return false;
    }
  }
  for (int idx : net.eval_order()) {
    if (idx < 0 || static_cast<std::size_t>(idx) >= net.node_count()) {
      if (error) *error = "simulation eval-order node out of range";
      return false;
    }
    if (idx == override_node) {
      (*values)[static_cast<std::size_t>(idx)] = override_value != 0 ? 1 : 0;
      continue;
    }
    const cell& gate = net.get_cell(idx);
    int value = 0;
    if (gate.ctype != CType::GATE ||
        !eval_gate_scalar(gate, *values, &value)) {
      if (error) *error = "could not evaluate gate " + net.node_name(idx);
      return false;
    }
    (*values)[static_cast<std::size_t>(idx)] = value;
  }
  return true;
}

std::vector<Dac25Candidate> build_candidates(
    const circuit& golden,
    const circuit& trojan,
    const std::vector<int>& mismatch_po_nodes,
    const std::vector<int>& observed_pi_values,
    std::size_t* raw_count) {
  const std::size_t n = trojan.node_count();
  std::vector<std::size_t> fanout(n, 0);
  for (std::size_t i = 0; i < n; ++i) {
    const cell& node = trojan.get_cell(static_cast<int>(i));
    if (node.ctype != CType::GATE) continue;
    for (int input : node.inputs) {
      if (input < 0 || static_cast<std::size_t>(input) >= n) {
        throw std::runtime_error("candidate fanout input out of range");
      }
      fanout[static_cast<std::size_t>(input)] += 1;
    }
  }

  std::unordered_set<int> po_set(trojan.po_indices().begin(),
                                 trojan.po_indices().end());
  const std::size_t inf = std::numeric_limits<std::size_t>::max();
  std::vector<std::size_t> distance(n, inf);
  std::vector<std::size_t> cone_count(n, 0);
  std::vector<char> in_union(n, 0);
  for (int po : mismatch_po_nodes) {
    std::queue<std::pair<int, std::size_t>> frontier;
    frontier.push({po, 0});
    std::vector<char> seen(n, 0);
    while (!frontier.empty()) {
      const auto current = frontier.front();
      frontier.pop();
      const int idx = current.first;
      if (idx < 0 || static_cast<std::size_t>(idx) >= n) {
        throw std::runtime_error("candidate cone node out of range");
      }
      if (seen[static_cast<std::size_t>(idx)]) continue;
      seen[static_cast<std::size_t>(idx)] = 1;
      in_union[static_cast<std::size_t>(idx)] = 1;
      cone_count[static_cast<std::size_t>(idx)] += 1;
      distance[static_cast<std::size_t>(idx)] = std::min(
          distance[static_cast<std::size_t>(idx)], current.second);
      const cell& node = trojan.get_cell(idx);
      if (node.ctype == CType::GATE) {
        for (int input : node.inputs) {
          frontier.push({input, current.second + 1});
        }
      }
    }
  }

  Alignment alignment;
  std::string simulation_error;
  if (!build_alignment(golden, trojan, &alignment, &simulation_error)) {
    throw std::runtime_error(simulation_error);
  }
  if (observed_pi_values.size() != alignment.pi_names.size()) {
    throw std::runtime_error("observed PI pattern width mismatch");
  }
  std::unordered_map<std::string, int> pi_values;
  for (std::size_t i = 0; i < alignment.pi_names.size(); ++i) {
    pi_values.emplace(alignment.pi_names[i], observed_pi_values[i]);
  }
  std::vector<int> golden_values;
  std::vector<int> trojan_values;
  if (!simulate_nodes(golden, pi_values, -1, 0, &golden_values,
                      &simulation_error) ||
      !simulate_nodes(trojan, pi_values, -1, 0, &trojan_values,
                      &simulation_error)) {
    throw std::runtime_error(simulation_error);
  }
  std::size_t mismatches_before = 0;
  for (std::size_t i = 0; i < alignment.golden_po.size(); ++i) {
    if (golden_values[static_cast<std::size_t>(alignment.golden_po[i])] !=
        trojan_values[static_cast<std::size_t>(alignment.trojan_po[i])]) {
      mismatches_before += 1;
    }
  }
  if (mismatches_before == 0) {
    throw std::runtime_error("observed mismatch pattern simulated equivalent");
  }

  std::vector<Dac25Candidate> candidates;
  for (std::size_t i = 0; i < n; ++i) {
    if (!in_union[i]) continue;
    const cell& node = trojan.get_cell(static_cast<int>(i));
    if (node.ctype != CType::GATE) continue;
    Dac25Candidate candidate;
    candidate.node = static_cast<int>(i);
    candidate.name = trojan.node_name(candidate.node);
    candidate.primary_output = po_set.find(candidate.node) != po_set.end();
    candidate.fanout = fanout[i];
    candidate.mismatching_po_cone_count = cone_count[i];
    candidate.distance_to_observed_mismatch = distance[i];
    candidate.observed_mismatches_before = mismatches_before;
    if (!golden.has_node(candidate.name)) {
      candidate.absent_from_golden = true;
    } else {
      const int golden_idx = golden.node_index(candidate.name);
      candidate.structurally_different =
          !same_gate_structure(golden, golden_idx, trojan, candidate.node);
    }

    std::vector<int> flipped_values;
    if (!simulate_nodes(trojan, pi_values, candidate.node,
                        1 - trojan_values[i], &flipped_values,
                        &simulation_error)) {
      throw std::runtime_error(simulation_error);
    }
    for (std::size_t po = 0; po < alignment.golden_po.size(); ++po) {
      if (golden_values[static_cast<std::size_t>(alignment.golden_po[po])] !=
          flipped_values[static_cast<std::size_t>(alignment.trojan_po[po])]) {
        candidate.observed_mismatches_after_flip += 1;
      }
    }
    candidate.observed_flip_repairs =
        candidate.observed_mismatches_after_flip == 0;

    // Stable, deterministic, intervention-based heuristic.  The public
    // DAC'25 material describes grouping/ranking but does not publish its
    // exact formula.  We expose this score instead of claiming parity.  It
    // deliberately does not special-case dataset names such as r0/r1.
    std::int64_t score = 0;
    if (candidate.observed_flip_repairs) score += 8000000000LL;
    const std::int64_t reduction =
        static_cast<std::int64_t>(mismatches_before) -
        static_cast<std::int64_t>(candidate.observed_mismatches_after_flip);
    score += reduction * 100000000LL;
    if (candidate.structurally_different) score += 2000000000LL;
    if (candidate.primary_output) score -= 500000000LL;
    score += static_cast<std::int64_t>(candidate.mismatching_po_cone_count) *
             1000000LL;
    if (candidate.absent_from_golden) score += 100000LL;
    score += static_cast<std::int64_t>(candidate.distance_to_observed_mismatch) *
             1000LL;
    score -= static_cast<std::int64_t>(candidate.fanout);
    candidate.score = score;
    candidates.push_back(std::move(candidate));
  }
  if (raw_count) *raw_count = candidates.size();
  std::sort(candidates.begin(), candidates.end(),
            [](const Dac25Candidate& lhs, const Dac25Candidate& rhs) {
              if (lhs.score != rhs.score) return lhs.score > rhs.score;
              if (lhs.distance_to_observed_mismatch !=
                  rhs.distance_to_observed_mismatch) {
                return lhs.distance_to_observed_mismatch <
                       rhs.distance_to_observed_mismatch;
              }
              if (lhs.name != rhs.name) return lhs.name < rhs.name;
              return lhs.node < rhs.node;
            });

  // Keep both the intervention-ranked front and a structural frontier.  The
  // latter prevents a single SAT witness from crowding a genuinely useful
  // name-aligned changed net out of a bounded candidate pool.  This is an
  // explicit V0 structural-matching mode and is reported through each
  // candidate's structurally_different field.
  std::vector<Dac25Candidate> interleaved;
  interleaved.reserve(candidates.size());
  std::vector<char> emitted(candidates.size(), 0);
  std::size_t structural_position = 0;
  std::size_t rank_position = 0;
  while (interleaved.size() < candidates.size()) {
    while (structural_position < candidates.size() &&
           (!candidates[structural_position].structurally_different ||
            emitted[structural_position])) {
      ++structural_position;
    }
    if (structural_position < candidates.size()) {
      interleaved.push_back(candidates[structural_position]);
      emitted[structural_position] = 1;
      ++structural_position;
    }
    while (rank_position < candidates.size() && emitted[rank_position]) {
      ++rank_position;
    }
    if (rank_position < candidates.size()) {
      interleaved.push_back(candidates[rank_position]);
      emitted[rank_position] = 1;
      ++rank_position;
    }
  }
  candidates = std::move(interleaved);
  return candidates;
}

template <typename Callback>
bool enumerate_combinations(std::size_t n,
                            std::size_t k,
                            Callback callback) {
  if (k == 0 || k > n) return true;
  std::vector<std::size_t> combination(k);
  for (std::size_t i = 0; i < k; ++i) combination[i] = i;
  while (true) {
    if (!callback(combination)) return false;
    std::size_t pos = k;
    while (pos > 0) {
      --pos;
      if (combination[pos] < n - k + pos) break;
    }
    if (pos == 0 && combination[0] == n - k) break;
    combination[pos] += 1;
    for (std::size_t j = pos + 1; j < k; ++j) {
      combination[j] = combination[j - 1] + 1;
    }
  }
  return true;
}

}  // namespace

const char* dac25_validation_status_name(Dac25ValidationStatus status) {
  switch (status) {
    case Dac25ValidationStatus::feasible:
      return "feasible";
    case Dac25ValidationStatus::infeasible:
      return "infeasible";
    case Dac25ValidationStatus::timeout:
      return "timeout";
    case Dac25ValidationStatus::unknown:
      return "unknown";
    case Dac25ValidationStatus::invalid:
      return "invalid";
  }
  return "invalid";
}

Dac25ValidationResult validate_dac25_rectification_targets(
    const circuit& golden,
    const circuit& trojan,
    const std::vector<int>& target_nodes,
    const Dac25ValidationOptions& options) {
  Dac25ValidationResult result;
  const auto total_start = Clock::now();
  result.target_nodes = target_nodes;
  if (options.timeout_ms == 0) {
    result.status = Dac25ValidationStatus::timeout;
    result.reason = "zero validation budget";
    return result;
  }
  if (target_nodes.size() > options.max_targets || target_nodes.size() >= 63) {
    result.status = Dac25ValidationStatus::invalid;
    result.reason = "target set exceeds configured/exact-expansion limit";
    return result;
  }
  std::unordered_set<int> unique_targets;
  std::unordered_set<int> po_nodes(trojan.po_indices().begin(),
                                   trojan.po_indices().end());
  for (int target : target_nodes) {
    if (target < 0 || static_cast<std::size_t>(target) >= trojan.node_count()) {
      result.status = Dac25ValidationStatus::invalid;
      result.reason = "target node index out of range";
      return result;
    }
    if (!unique_targets.insert(target).second) {
      result.status = Dac25ValidationStatus::invalid;
      result.reason = "duplicate target node";
      return result;
    }
    if (trojan.get_cell(target).ctype != CType::GATE) {
      result.status = Dac25ValidationStatus::invalid;
      result.reason = "target must be a gate node";
      return result;
    }
    (void)po_nodes;
  }

  try {
    const auto encode_start = Clock::now();
    Alignment alignment;
    std::string error;
    if (!build_alignment(golden, trojan, &alignment, &error)) {
      result.status = Dac25ValidationStatus::invalid;
      result.reason = error;
      result.total_ms = elapsed_ms(total_start);
      return result;
    }

    z3::context ctx;
    z3::solver solver(ctx);
    std::unordered_map<std::string, z3::expr> shared_pi;
    for (std::size_t i = 0; i < alignment.pi_names.size(); ++i) {
      shared_pi.emplace(alignment.pi_names[i],
                        ctx.bool_const(("dac25_qe_pi_" + std::to_string(i)).c_str()));
    }
    auto golden_vars = make_vars(ctx, "dac25_qe_g_", golden.node_count());
    const std::unordered_map<int, bool> no_targets;
    if (!add_circuit_constraints(ctx, golden, golden_vars, shared_pi,
                                 no_targets, solver, &error)) {
      result.status = Dac25ValidationStatus::invalid;
      result.reason = error;
      result.total_ms = elapsed_ms(total_start);
      return result;
    }

    const std::size_t assignment_count =
        static_cast<std::size_t>(1ULL << target_nodes.size());
    result.target_assignments = assignment_count;
    result.encoded_circuit_copies = assignment_count + 1;
    z3::expr all_assignments_mismatch = ctx.bool_val(true);
    for (std::size_t assignment = 0; assignment < assignment_count;
         ++assignment) {
      if (deadline_expired(total_start, options.timeout_ms)) {
        result.status = Dac25ValidationStatus::timeout;
        result.reason = "validation deadline expired during encoding";
        result.encode_ms = elapsed_ms(encode_start);
        result.total_ms = elapsed_ms(total_start);
        return result;
      }
      std::unordered_map<int, bool> target_values;
      for (std::size_t i = 0; i < target_nodes.size(); ++i) {
        target_values.emplace(target_nodes[i],
                              ((assignment >> i) & 1U) != 0U);
      }
      auto trojan_vars = make_vars(
          ctx, "dac25_qe_t_" + std::to_string(assignment) + "_",
          trojan.node_count());
      if (!add_circuit_constraints(ctx, trojan, trojan_vars, shared_pi,
                                   target_values, solver, &error)) {
        result.status = Dac25ValidationStatus::invalid;
        result.reason = error;
        result.encode_ms = elapsed_ms(encode_start);
        result.total_ms = elapsed_ms(total_start);
        return result;
      }
      all_assignments_mismatch =
          all_assignments_mismatch &&
          mismatch_expr(ctx, golden_vars, trojan_vars, alignment);
    }
    solver.add(all_assignments_mismatch);
    result.encode_ms = elapsed_ms(encode_start);

    const unsigned remaining =
        remaining_timeout_ms(total_start, options.timeout_ms);
    if (remaining == 0) {
      result.status = Dac25ValidationStatus::timeout;
      result.reason = "validation deadline expired before SAT check";
      result.total_ms = elapsed_ms(total_start);
      return result;
    }
    z3::params params(ctx);
    params.set("timeout", remaining);
    params.set("random_seed", 0U);
    solver.set(params);
    const auto solver_start = Clock::now();
    result.solver_checks = 1;
    const z3::check_result checked = solver.check();
    result.solver_ms = elapsed_ms(solver_start);
    if (checked == z3::unsat) {
      result.status = Dac25ValidationStatus::feasible;
      result.reason = "Shannon-QE counterexample formula is UNSAT";
    } else if (checked == z3::sat) {
      result.status = Dac25ValidationStatus::infeasible;
      result.reason = "an unrepairable PI assignment exists";
      const z3::model model = solver.get_model();
      result.counterexample_pi_values.reserve(alignment.pi_names.size());
      for (const std::string& name : alignment.pi_names) {
        result.counterexample_pi_values.push_back(
            model.eval(shared_pi.at(name), true).is_true() ? 1 : 0);
      }
    } else {
      result.reason = solver.reason_unknown();
      result.status = reason_is_timeout(result.reason) ||
                              deadline_expired(total_start, options.timeout_ms)
                          ? Dac25ValidationStatus::timeout
                          : Dac25ValidationStatus::unknown;
    }
  } catch (const z3::exception& e) {
    result.reason = e.msg();
    result.status = reason_is_timeout(result.reason)
                        ? Dac25ValidationStatus::timeout
                        : Dac25ValidationStatus::unknown;
  } catch (const std::exception& e) {
    result.status = Dac25ValidationStatus::invalid;
    result.reason = e.what();
  }
  result.total_ms = elapsed_ms(total_start);
  return result;
}

const char* dac25_plan_status_name(Dac25PlanStatus status) {
  switch (status) {
    case Dac25PlanStatus::selected:
      return "selected";
    case Dac25PlanStatus::infeasible:
      return "infeasible";
    case Dac25PlanStatus::timeout:
      return "timeout";
    case Dac25PlanStatus::unknown:
      return "unknown";
    case Dac25PlanStatus::invalid:
      return "invalid";
  }
  return "invalid";
}

Dac25PlanResult plan_dac25_rectification(
    const circuit& golden,
    const circuit& trojan,
    const Dac25PlanOptions& options) {
  Dac25PlanResult result;
  const auto total_start = Clock::now();
  if (options.timeout_ms == 0 || options.candidate_limit == 0 ||
      options.max_targets == 0 || options.max_feasible_sets == 0) {
    result.status = options.timeout_ms == 0 ? Dac25PlanStatus::timeout
                                            : Dac25PlanStatus::invalid;
    result.reason = "invalid/zero planner limit";
    return result;
  }

  const ObservedMismatch observed =
      find_observed_mismatch(golden, trojan, options.timeout_ms);
  result.solver_ms += observed.solver_ms;
  result.observed_counterexample_pi_values = observed.pi_values;
  result.observed_mismatching_outputs = observed.po_names;
  if (observed.status == Dac25ValidationStatus::feasible) {
    result.status = Dac25PlanStatus::selected;
    result.reason = "circuits are already equivalent";
    result.total_ms = elapsed_ms(total_start);
    return result;
  }
  if (observed.status != Dac25ValidationStatus::infeasible) {
    result.status = observed.status == Dac25ValidationStatus::timeout
                        ? Dac25PlanStatus::timeout
                        : observed.status == Dac25ValidationStatus::unknown
                              ? Dac25PlanStatus::unknown
                              : Dac25PlanStatus::invalid;
    result.reason = observed.reason;
    result.total_ms = elapsed_ms(total_start);
    return result;
  }

  const auto candidate_start = Clock::now();
  try {
    result.candidates = build_candidates(
        golden, trojan, observed.trojan_po_nodes, observed.pi_values,
        &result.raw_candidates);
  } catch (const std::exception& e) {
    result.status = Dac25PlanStatus::invalid;
    result.reason = e.what();
    result.candidate_ms = elapsed_ms(candidate_start);
    result.total_ms = elapsed_ms(total_start);
    return result;
  }
  result.candidate_ms = elapsed_ms(candidate_start);
  if (result.candidates.size() > options.candidate_limit) {
    result.candidates.resize(options.candidate_limit);
  }
  if (result.candidates.empty()) {
    result.status = Dac25PlanStatus::infeasible;
    result.reason = "no gate candidate exists in observed mismatch cones";
    result.total_ms = elapsed_ms(total_start);
    return result;
  }

  // From this point onward, `invalid` is reserved for an explicit validation
  // error.  Starting the search in the neutral infeasible state lets the
  // finalizer distinguish timeout/unknown/exhaustion from the struct default.
  result.status = Dac25PlanStatus::infeasible;
  result.reason.clear();

  bool stopped_by_timeout = false;
  bool stopped_by_unknown = false;
  for (std::size_t cardinality = 1;
       cardinality <= options.max_targets &&
       cardinality <= result.candidates.size();
       ++cardinality) {
    const bool completed = enumerate_combinations(
        result.candidates.size(), cardinality,
        [&](const std::vector<std::size_t>& positions) {
          if (deadline_expired(total_start, options.timeout_ms)) {
            stopped_by_timeout = true;
            return false;
          }
          std::vector<int> targets;
          targets.reserve(positions.size());
          for (std::size_t pos : positions) {
            targets.push_back(result.candidates[pos].node);
          }
          Dac25ValidationOptions validation_options;
          validation_options.timeout_ms = static_cast<std::uint64_t>(
              remaining_timeout_ms(total_start, options.timeout_ms));
          validation_options.max_targets = options.max_targets;
          const Dac25ValidationResult validation =
              validate_dac25_rectification_targets(
                  golden, trojan, targets, validation_options);
          result.sets_checked += 1;
          result.solver_ms += validation.solver_ms;
          switch (validation.status) {
            case Dac25ValidationStatus::feasible:
              result.feasible_sets += 1;
              result.feasible_target_sets.push_back(std::move(targets));
              return result.feasible_target_sets.size() <
                     options.max_feasible_sets;
            case Dac25ValidationStatus::infeasible:
              result.infeasible_sets += 1;
              return true;
            case Dac25ValidationStatus::timeout:
              stopped_by_timeout = true;
              return false;
            case Dac25ValidationStatus::unknown:
              result.unknown_sets += 1;
              stopped_by_unknown = true;
              return false;
            case Dac25ValidationStatus::invalid:
              result.status = Dac25PlanStatus::invalid;
              result.reason = validation.reason;
              return false;
          }
          return false;
        });
    if (!result.feasible_target_sets.empty()) {
      // Cardinality is the primary objective.  Once any feasible set exists,
      // larger sets cannot improve it.
      break;
    }
    if (!completed || stopped_by_timeout || stopped_by_unknown ||
        result.status == Dac25PlanStatus::invalid) {
      break;
    }
  }

  if (!result.feasible_target_sets.empty()) {
    result.selected_targets = result.feasible_target_sets.front();
    result.status = Dac25PlanStatus::selected;
    result.reason =
        "minimum-cardinality feasible set selected within retained pool";
  } else if (result.status == Dac25PlanStatus::invalid) {
    // Preserve detailed reason above.
  } else if (stopped_by_timeout) {
    result.status = Dac25PlanStatus::timeout;
    result.reason = "planner shared deadline exhausted";
  } else if (stopped_by_unknown) {
    result.status = Dac25PlanStatus::unknown;
    result.reason = "SAT solver returned unknown";
  } else {
    result.status = Dac25PlanStatus::infeasible;
    result.reason = "no feasible set found within candidate/target bounds";
  }
  result.total_ms = elapsed_ms(total_start);
  return result;
}
