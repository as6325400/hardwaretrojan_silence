#pragma once

#include "rule_optimizer.hpp"

// Returns whether this build contains the HiGHS C++ backend.  Keeping this a
// runtime query makes tests and callers explicit about the safe fallback
// provided by builds compiled without USE_HIGHS.
bool highs_set_cover_backend_available();

// Exact bounded-DNF synthesis through an exhaustive prime-implicant pool and
// a two-stage weighted set-cover MILP:
//   1. minimize the number of clauses;
//   2. fix that optimum and minimize literal occurrences.
//
// The result is accepted only after both MILPs are optimal and the extracted
// model classifies the complete finite feature matrix with zero error.  On any
// failure, timeout, incomplete term pool, or unavailable backend, result.model
// remains baseline_model.
RuleOptimizationResult optimize_dnf_rules_highs_set_cover(
    const PackedFeatureMatrix& features,
    const std::vector<int>& labels,
    const std::vector<std::size_t>& raw_dt_candidate_features,
    const DecisionTreeModel& baseline_model,
    const RuleOptimizerOptions& options = RuleOptimizerOptions{});
