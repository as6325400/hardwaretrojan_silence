#pragma once

#include "rule_optimizer.hpp"

// Returns whether this build contains the HiGHS C++ backend.  Keeping this a
// runtime query makes tests and callers explicit about the safe fallback
// provided by builds compiled without USE_HIGHS.
bool highs_set_cover_backend_available();

// Exact bounded-DNF synthesis through an exhaustive prime-implicant pool and
// a lexicographic weighted set-cover MILP:
//   1. minimize the number of clauses;
//   2. fix that optimum and minimize literal occurrences.
// When cover_third_objective is unique_inverters, a third LP/MIP pair fixes
// both preceding optima and minimizes the number of distinct features used by
// expected-zero literals.
//
// An extracted model is accepted only after it classifies the complete finite
// feature matrix with zero error.  A phase-3 timeout may safely retain the
// already verified MIP2 model, but does not claim hardware or overall
// optimality.  phase3_timeout_ms may impose a smaller phase-3 deadline while
// its default shares the remaining global deadline.  Other failures, an
// incomplete term pool, or an unavailable backend preserve baseline_model.
RuleOptimizationResult optimize_dnf_rules_highs_set_cover(
    const PackedFeatureMatrix& features,
    const std::vector<int>& labels,
    const std::vector<std::size_t>& raw_dt_candidate_features,
    const DecisionTreeModel& baseline_model,
    const RuleOptimizerOptions& options = RuleOptimizerOptions{});
