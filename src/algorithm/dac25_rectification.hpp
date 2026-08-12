#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "../core/circuit.hpp"

// This module is a literature-informed reimplementation based only on the
// publicly available description of the DAC 2025 rectification-signal flow.
// It is intentionally named "DAC25-inspired"; it is not the authors' code.

enum class Dac25ValidationStatus {
  feasible,
  infeasible,
  timeout,
  unknown,
  invalid
};

const char* dac25_validation_status_name(Dac25ValidationStatus status);

struct Dac25ValidationOptions {
  // Soft in-process deadline shared by encoding and the SAT check.
  std::uint64_t timeout_ms = 30000;
  std::size_t max_targets = 3;
};

struct Dac25ValidationResult {
  Dac25ValidationStatus status = Dac25ValidationStatus::invalid;
  std::string reason;
  std::vector<int> target_nodes;
  std::vector<int> counterexample_pi_values;
  std::size_t target_assignments = 0;
  std::size_t encoded_circuit_copies = 0;
  std::size_t solver_checks = 0;
  double encode_ms = 0.0;
  double solver_ms = 0.0;
  double total_ms = 0.0;

  bool feasible() const {
    return status == Dac25ValidationStatus::feasible;
  }
};

// Check
//   forall PI x, exists target values u:
//       Trojan_with_targets_cut(x, u) == Golden(x).
//
// For the bounded target set this is reduced exactly by Shannon expansion:
// SAT is asked whether there exists an x for which every target assignment
// still mismatches.  UNSAT therefore proves feasibility for all PI inputs.
Dac25ValidationResult validate_dac25_rectification_targets(
    const circuit& golden,
    const circuit& trojan,
    const std::vector<int>& target_nodes,
    const Dac25ValidationOptions& options = {});

struct Dac25Candidate {
  int node = -1;
  std::string name;
  bool absent_from_golden = false;
  bool structurally_different = false;
  bool primary_output = false;
  std::size_t mismatching_po_cone_count = 0;
  std::size_t fanout = 0;
  std::size_t distance_to_observed_mismatch = 0;
  std::int64_t score = 0;
};

struct Dac25PlanOptions {
  std::uint64_t timeout_ms = 30000;
  std::size_t candidate_limit = 64;
  std::size_t max_targets = 3;
  std::size_t max_feasible_sets = 16;
};

enum class Dac25PlanStatus {
  selected,
  infeasible,
  timeout,
  unknown,
  invalid
};

const char* dac25_plan_status_name(Dac25PlanStatus status);

struct Dac25PlanResult {
  Dac25PlanStatus status = Dac25PlanStatus::invalid;
  std::string reason;
  std::vector<Dac25Candidate> candidates;
  std::vector<int> selected_targets;
  std::vector<std::vector<int>> feasible_target_sets;
  std::vector<int> observed_counterexample_pi_values;
  std::vector<std::string> observed_mismatching_outputs;
  std::size_t raw_candidates = 0;
  std::size_t sets_checked = 0;
  std::size_t feasible_sets = 0;
  std::size_t infeasible_sets = 0;
  std::size_t unknown_sets = 0;
  double candidate_ms = 0.0;
  double solver_ms = 0.0;
  double total_ms = 0.0;
};

// Discover and cardinality-minimize a bounded rectification target set.  The
// candidate ranking is deterministic and intentionally exposed in telemetry;
// exact feasibility is always decided by validate_dac25_rectification_targets.
Dac25PlanResult plan_dac25_rectification(
    const circuit& golden,
    const circuit& trojan,
    const Dac25PlanOptions& options = {});
