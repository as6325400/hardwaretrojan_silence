#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "decision_tree.hpp"

// Optional objective applied only after the exact rule and literal counts are
// fixed by the weighted set-cover backend.
enum class RuleCoverThirdObjective {
  none,
  unique_inverters
};

// Optional circuit-derived metadata for the final logic-risk tie-break.  The
// values are deliberately technology independent: base_fanout counts current
// graph consumers and arrival_level is a unit-gate topological level.  They
// are proxies, not cell-library area, delay, capacitance, or STA slack.
struct RuleCoverFeatureMetric {
  std::size_t base_fanout = 0;
  std::size_t arrival_level = 0;
};

struct RuleCoverCostContext {
  // Indexed exactly like PackedFeatureMatrix columns.  A context is usable
  // only when this vector covers every matrix feature.
  std::vector<RuleCoverFeatureMetric> features;
  std::size_t circuit_level = 0;
};

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

  // Optional third lexicographic objective for the set-cover backend.  The
  // default preserves the original two-objective, four-phase behavior.
  RuleCoverThirdObjective cover_third_objective =
      RuleCoverThirdObjective::none;

  // Optional wall-clock sub-budget for the third objective.  The default
  // shares the remaining global optimizer deadline.  Zero deterministically
  // accepts the already verified MIP2 model without starting LP3.
  std::uint64_t phase3_timeout_ms =
      std::numeric_limits<std::uint64_t>::max();

  // Optional fourth lexicographic objective.  It fixes the exact rule,
  // literal, and unique-inverter optima before minimizing a normalized sum of
  // distinct feature taps, fanout-load stress, and unit-gate logical depth.
  // The objective is intentionally described as a logic-risk proxy: it is not
  // physical area or static timing analysis.
  bool cover_logic_risk_proxy = false;
  double logic_risk_unique_feature_weight = 0.25;
  double logic_risk_fanout_weight = 0.25;
  double logic_risk_timing_weight = 0.50;

  // Optional wall-clock sub-budget for LP4/MIP4.  The default shares the
  // remaining global deadline.  Zero accepts the already full-table-verified
  // MIP3 result without claiming proxy or overall optimality.
  std::uint64_t phase4_timeout_ms =
      std::numeric_limits<std::uint64_t>::max();
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
  // hardware_optimal is meaningful only when a requested third objective
  // reached MIP optimality and its extracted model passed full verification.
  bool hardware_optimal = false;
  // logic_risk_optimal is meaningful only for a requested fourth objective
  // with a valid RuleCoverCostContext and a verified optimal MIP4 result.
  bool logic_risk_optimal = false;
  // A true value means the accepted model is the independently verified MIP2
  // incumbent; rules/literals remain optimal, but stats.optimal is false.
  bool phase3_timeout_fallback = false;
  bool phase4_timeout_fallback = false;
  bool phase4_unavailable_fallback = false;
  std::string third_objective;
  std::string fourth_objective;
  std::uint64_t phase3_timeout_ms =
      std::numeric_limits<std::uint64_t>::max();
  std::uint64_t phase4_timeout_ms =
      std::numeric_limits<std::uint64_t>::max();
  bool logic_risk_context_available = false;
  std::string logic_risk_context_reason;
  double logic_risk_unique_feature_weight = 0.0;
  double logic_risk_fanout_weight = 0.0;
  double logic_risk_timing_weight = 0.0;
  double logic_risk_max_fanout_log = 0.0;
  double logic_risk_unique_denominator = 1.0;
  double logic_risk_fanout_denominator = 1.0;
  double logic_risk_timing_denominator = 1.0;
  std::size_t logic_risk_or_depth = 0;

  std::size_t pool_hyperedges = 0;
  std::size_t pool_redundant_hyperedges = 0;
  std::size_t pool_terms_generated = 0;
  std::size_t pool_terms_unique = 0;
  std::size_t pool_terms_coverage_deduplicated = 0;
  std::size_t pool_terms_coverage_alternatives = 0;
  std::size_t pool_terms_final = 0;
  std::size_t pool_terms_unsafe = 0;
  std::size_t pool_states_explored = 0;
  bool pool_state_limit_hit = false;
  bool pool_depth_limit_hit = false;
  std::size_t master_variables = 0;
  std::size_t master_constraints = 0;
  std::size_t master_nonzeros = 0;
  std::size_t inverter_features = 0;
  std::size_t inverter_link_constraints = 0;
  std::size_t unique_inverters_before = 0;
  std::size_t unique_inverters_after = 0;
  std::size_t logic_risk_feature_variables = 0;
  std::size_t logic_risk_feature_link_constraints = 0;
  std::size_t unique_features_before = 0;
  std::size_t unique_features_after = 0;
  std::size_t feature_loads_before = 0;
  std::size_t feature_loads_after = 0;
  double fanout_stress_before = 0.0;
  double fanout_stress_after = 0.0;
  std::size_t max_term_arrival_before = 0;
  std::size_t max_term_arrival_after = 0;
  std::size_t match_depth_proxy_before = 0;
  std::size_t match_depth_proxy_after = 0;
  double logic_risk_unique_component_before = 0.0;
  double logic_risk_unique_component_after = 0.0;
  double logic_risk_fanout_component_before = 0.0;
  double logic_risk_fanout_component_after = 0.0;
  double logic_risk_timing_component_before = 0.0;
  double logic_risk_timing_component_after = 0.0;
  double logic_risk_objective_before = 0.0;
  double logic_risk_objective_after = 0.0;

  std::string lp1_status;
  std::string mip1_status;
  std::string lp2_status;
  std::string mip2_status;
  std::string lp3_status;
  std::string mip3_status;
  std::string lp4_status;
  std::string mip4_status;
  double lp1_objective = 0.0;
  double mip1_objective = 0.0;
  double mip1_dual_bound = 0.0;
  double mip1_gap = 0.0;
  double lp2_objective = 0.0;
  double mip2_objective = 0.0;
  double mip2_dual_bound = 0.0;
  double mip2_gap = 0.0;
  double lp3_objective = 0.0;
  double mip3_objective = 0.0;
  double mip3_dual_bound = 0.0;
  double mip3_gap = 0.0;
  double lp4_objective = 0.0;
  double mip4_objective = 0.0;
  double mip4_dual_bound = 0.0;
  double mip4_gap = 0.0;
  std::size_t lp1_iterations = 0;
  std::size_t mip1_nodes = 0;
  std::size_t lp2_iterations = 0;
  std::size_t mip2_nodes = 0;
  std::size_t lp3_iterations = 0;
  std::size_t mip3_nodes = 0;
  std::size_t lp4_iterations = 0;
  std::size_t mip4_nodes = 0;
  std::size_t lp1_dual_nonzero = 0;
  std::size_t lp2_dual_nonzero = 0;
  std::size_t lp3_dual_nonzero = 0;
  std::size_t lp4_dual_nonzero = 0;
  double lp1_dual_min = 0.0;
  double lp1_dual_max = 0.0;
  double lp1_dual_sum_abs = 0.0;
  double lp2_dual_min = 0.0;
  double lp2_dual_max = 0.0;
  double lp2_dual_sum_abs = 0.0;
  double lp3_dual_min = 0.0;
  double lp3_dual_max = 0.0;
  double lp3_dual_sum_abs = 0.0;
  double lp4_dual_min = 0.0;
  double lp4_dual_max = 0.0;
  double lp4_dual_sum_abs = 0.0;
  double term_generation_ms = 0.0;
  double lp1_ms = 0.0;
  double mip1_ms = 0.0;
  double lp2_ms = 0.0;
  double mip2_ms = 0.0;
  double lp3_ms = 0.0;
  double mip3_ms = 0.0;
  double lp4_ms = 0.0;
  double mip4_ms = 0.0;
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
