#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "decision_tree.hpp"

// Shared bounds for exact finite-table bounded-DNF rule optimization.  The
// Z3 path uses pseudo-Boolean / MaxSMT variables; the set-cover path builds an
// explicit prime-implicant pool and solves LP/MIP masters with HiGHS.
struct RuleOptimizerOptions {
  // Backend wall-clock budget.  Z3-PB shares it across CEGIS Optimize checks;
  // HiGHS set-cover shares it across term generation and all LP/MIP phases.
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

  // Maximum number of unique prime-implicant terms generated for the
  // weighted set-cover backend.  Zero disables this guard.  The backend only
  // reports a globally optimal bounded-DNF result when term enumeration is
  // complete.
  std::size_t max_pool_terms = 200000;

  // Guard for partial states explored while enumerating prime implicants.
  // A state cap is needed in addition to max_pool_terms because an
  // exponential search may visit many internal states before producing a
  // single term.  Zero disables this guard.
  std::size_t max_pool_states = 2000000;
};

struct RuleOptimizerStats {
  // Stable machine-readable status.  Common values are accepted, invalid,
  // infeasible, timeout, unknown, max_rounds, and verification_failed.  An
  // optional backend can additionally report backend_unavailable or a safe
  // resource guard such as pool_limit.
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

  // Optional backend-specific telemetry.  The Z3-PB path may leave these at
  // their defaults; the HiGHS set-cover path fills them explicitly.
  std::string solver_backend;
  std::string solver_version;
  bool backend_available = false;
  bool pool_complete = false;
  bool rules_optimal = false;
  bool literals_optimal = false;

  std::size_t pool_hyperedges = 0;
  std::size_t pool_redundant_hyperedges = 0;
  std::size_t pool_terms_generated = 0;
  std::size_t pool_terms_unique = 0;
  std::size_t pool_terms_coverage_deduplicated = 0;
  std::size_t pool_terms_final = 0;
  std::size_t pool_terms_unsafe = 0;
  std::size_t pool_states_explored = 0;
  bool pool_state_limit_hit = false;
  bool pool_depth_limit_hit = false;
  std::size_t master_variables = 0;
  std::size_t master_constraints = 0;
  std::size_t master_nonzeros = 0;

  std::string lp1_status;
  std::string mip1_status;
  std::string lp2_status;
  std::string mip2_status;
  double lp1_objective = 0.0;
  double mip1_objective = 0.0;
  double mip1_dual_bound = 0.0;
  double mip1_gap = 0.0;
  double lp2_objective = 0.0;
  double mip2_objective = 0.0;
  double mip2_dual_bound = 0.0;
  double mip2_gap = 0.0;
  std::size_t lp1_iterations = 0;
  std::size_t mip1_nodes = 0;
  std::size_t lp2_iterations = 0;
  std::size_t mip2_nodes = 0;
  std::size_t lp1_dual_nonzero = 0;
  std::size_t lp2_dual_nonzero = 0;
  double lp1_dual_min = 0.0;
  double lp1_dual_max = 0.0;
  double lp1_dual_sum_abs = 0.0;
  double lp2_dual_min = 0.0;
  double lp2_dual_max = 0.0;
  double lp2_dual_sum_abs = 0.0;
  double term_generation_ms = 0.0;
  double lp1_ms = 0.0;
  double mip1_ms = 0.0;
  double lp2_ms = 0.0;
  double mip2_ms = 0.0;
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
