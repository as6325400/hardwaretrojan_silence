#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "decision_tree.hpp"

// Exact bounded-DNF rule optimization over Boolean (0-1) variables.  The
// implementation uses Z3 Optimize as a pseudo-Boolean / MaxSMT backend; it is
// ILP-equivalent for this Boolean model, but it is not an LP-relaxation MILP
// solver and therefore does not expose a MILP optimality gap.
struct RuleOptimizerOptions {
  // Total solver wall-clock budget shared by every CEGIS Optimize check.
  // A value of zero is an immediate, deterministic timeout.
  unsigned timeout_ms = 10000;

  // Maximum number of Optimize checks, including the initial check.
  std::size_t max_rounds = 100;

  // Maximum number of newly discovered, genuinely misclassified signatures
  // added after each full-table scan.  Initial constraints are stratified and
  // may contain up to this many signatures from each class.
  std::size_t counterexample_batch_size = 5;

  // Zero means use the number of clauses in baseline_model.
  std::size_t max_clauses = 0;

  // Zero means use the largest baseline clause, with a minimum cap of one.
  std::size_t max_literals_per_clause = 0;
};

struct RuleOptimizerStats {
  // Stable machine-readable status: accepted, invalid, infeasible, timeout,
  // unknown, max_rounds, or verification_failed.
  std::string status = "invalid";
  std::string reason;

  bool accepted = false;
  bool optimal = false;
  bool verified = false;

  std::size_t input_rows = 0;
  std::size_t positive_rows = 0;
  std::size_t negative_rows = 0;

  std::size_t raw_candidate_features = 0;
  std::size_t unique_candidate_features = 0;
  std::size_t duplicate_candidate_features = 0;
  std::size_t candidate_literals = 0;

  std::size_t unique_pattern_signatures = 0;
  std::size_t positive_signatures = 0;
  std::size_t negative_signatures = 0;
  std::size_t duplicate_pattern_rows = 0;
  std::size_t conflicting_signatures = 0;

  std::size_t clause_limit = 0;
  std::size_t literal_limit = 0;
  std::size_t initial_constraints = 0;
  std::size_t constraints_added = 0;
  std::size_t counterexamples_added = 0;
  std::size_t solver_checks = 0;
  std::size_t rounds_used = 0;

  std::size_t rules_before = 0;
  std::size_t rules_after = 0;
  std::size_t literals_before = 0;
  std::size_t literals_after = 0;

  std::size_t verification_false_positive = 0;
  std::size_t verification_false_negative = 0;

  double preprocessing_ms = 0.0;
  double solver_ms = 0.0;
  double total_ms = 0.0;
};

struct RuleOptimizationResult {
  // Always initialized to baseline_model.  It is replaced by the optimized
  // model only when stats.accepted is true.
  DecisionTreeModel model;
  RuleOptimizerStats stats;
};

RuleOptimizationResult optimize_dnf_rules_z3_pb(
    const PackedFeatureMatrix& features,
    const std::vector<int>& labels,
    const std::vector<std::size_t>& raw_dt_candidate_features,
    const DecisionTreeModel& baseline_model,
    const RuleOptimizerOptions& options = RuleOptimizerOptions{});

