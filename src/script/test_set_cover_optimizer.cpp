#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "../algorithm/set_cover_optimizer.hpp"

namespace {

int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    failures += 1;
  }
}

PackedFeatureMatrix make_matrix(const std::vector<std::vector<int>>& rows,
                                std::size_t capacity = 0) {
  PackedFeatureMatrix matrix;
  const std::size_t feature_count = rows.empty() ? 0 : rows.front().size();
  matrix.allocate(feature_count, capacity == 0 ? rows.size() : capacity);
  for (std::size_t row = 0; row < rows.size(); ++row) {
    expect(rows[row].size() == feature_count,
           "test matrix rows have consistent widths");
    for (std::size_t feature = 0; feature < feature_count; ++feature) {
      if (rows[row][feature] != 0) {
        matrix.col_ptr_mut(feature)[row / PackedFeatureMatrix::kWordBits] |=
            PackedFeatureMatrix::word_t{1}
            << (row % PackedFeatureMatrix::kWordBits);
      }
    }
  }
  matrix.row_count = rows.size();
  return matrix;
}

DecisionTreeModel make_model(
    const std::vector<std::vector<std::pair<std::size_t, int>>>& clauses) {
  DecisionTreeModel model;
  for (const auto& terms : clauses) {
    model.rules.push_back(DecisionTreeRule{terms});
    model.max_depth_used = std::max(model.max_depth_used, terms.size());
  }
  model.leaf_count = model.rules.size();
  return model;
}

RuleOptimizerOptions test_options() {
  RuleOptimizerOptions options;
  options.timeout_ms = 10000;
  options.max_clauses = 0;
  options.max_literals_per_clause = 0;
  options.max_pool_terms = 10000;
  return options;
}

bool models_equal(const DecisionTreeModel& lhs,
                  const DecisionTreeModel& rhs) {
  if (lhs.rules.size() != rhs.rules.size()) return false;
  for (std::size_t rule = 0; rule < lhs.rules.size(); ++rule) {
    if (lhs.rules[rule].terms != rhs.rules[rule].terms) return false;
  }
  return true;
}

RuleOptimizationResult optimize(
    const std::vector<std::vector<int>>& rows,
    const std::vector<int>& labels,
    const std::vector<std::size_t>& candidates,
    const DecisionTreeModel& baseline,
    RuleOptimizerOptions options = test_options(),
    std::size_t capacity = 0,
    const RuleCoverCostContext* cost_context = nullptr) {
  return optimize_dnf_rules_highs_set_cover(
      make_matrix(rows, capacity), labels, candidates, baseline, options,
      cost_context);
}

void expect_exact_success(const RuleOptimizationResult& result,
                          const std::string& label) {
  expect(result.stats.accepted, label + " is accepted");
  expect(result.stats.verified, label + " is finite-table verified");
  expect(result.stats.optimal && result.stats.rules_optimal &&
             result.stats.literals_optimal,
         label + " is lexicographically optimal");
  expect(result.stats.pool_complete, label + " has a complete term pool");
  expect(result.stats.solver_backend == "highs-set-cover-milp",
         label + " reports the HiGHS MILP backend");
  expect(result.stats.solver_checks == 4,
         label + " runs LP1, MIP1, LP2, and MIP2");
  expect(result.stats.lp1_status == "Optimal" &&
             result.stats.mip1_status == "Optimal" &&
             result.stats.lp2_status == "Optimal" &&
             result.stats.mip2_status == "Optimal",
         label + " records four optimal HiGHS phases");
  expect(result.stats.mip1_gap <= 1.0e-9 &&
             result.stats.mip2_gap <= 1.0e-9,
         label + " closes both MIP gaps");
  expect(result.stats.lp1_objective <= result.stats.mip1_objective + 1.0e-7,
         label + " LP1 is a valid rule-count lower bound");
  expect(result.stats.lp2_objective <= result.stats.mip2_objective + 1.0e-7,
         label + " LP2 is a valid literal lower bound");
}

void expect_hardware_success(const RuleOptimizationResult& result,
                             const std::string& label) {
  expect(result.stats.accepted && result.stats.verified,
         label + " is accepted and finite-table verified");
  expect(result.stats.optimal && result.stats.rules_optimal &&
             result.stats.literals_optimal &&
             result.stats.hardware_optimal,
         label + " proves all three lexicographic objectives");
  expect(result.stats.pool_complete,
         label + " has a complete term pool");
  expect(result.stats.third_objective == "unique_inverters",
         label + " reports the inverter objective");
  expect(result.stats.solver_checks == 6,
         label + " runs LP/MIP pairs for all three objectives");
  expect(result.stats.lp1_status == "Optimal" &&
             result.stats.mip1_status == "Optimal" &&
             result.stats.lp2_status == "Optimal" &&
             result.stats.mip2_status == "Optimal" &&
             result.stats.lp3_status == "Optimal" &&
             result.stats.mip3_status == "Optimal",
         label + " records six optimal HiGHS phases");
  expect(result.stats.lp3_objective <=
             result.stats.mip3_objective + 1.0e-7,
         label + " LP3 is a valid inverter-count lower bound");
  expect(result.stats.mip3_gap <= 1.0e-9,
         label + " closes the MIP3 gap");
  expect(std::fabs(result.stats.mip3_objective -
                   static_cast<double>(
                       result.stats.unique_inverters_after)) <= 1.0e-7,
         label + " verifies the inverter proxy against extracted rules");
  expect(!result.stats.phase3_timeout_fallback,
         label + " does not use the phase-3 timeout fallback");
}

RuleOptimizerOptions logic_risk_options(double unique_weight,
                                        double fanout_weight,
                                        double timing_weight) {
  RuleOptimizerOptions options = test_options();
  options.cover_third_objective =
      RuleCoverThirdObjective::unique_inverters;
  options.cover_logic_risk_proxy = true;
  options.logic_risk_unique_feature_weight = unique_weight;
  options.logic_risk_fanout_weight = fanout_weight;
  options.logic_risk_timing_weight = timing_weight;
  return options;
}

RuleCoverCostContext make_cost_context(
    const std::vector<std::pair<std::size_t, std::size_t>>& metrics,
    std::size_t circuit_level) {
  RuleCoverCostContext context;
  context.circuit_level = circuit_level;
  for (const auto& metric : metrics) {
    context.features.push_back(
        RuleCoverFeatureMetric{metric.first, metric.second});
  }
  return context;
}

void expect_logic_risk_success(const RuleOptimizationResult& result,
                               const std::string& label) {
  expect(result.stats.accepted && result.stats.verified,
         label + " is accepted and full-table verified");
  expect(result.stats.optimal && result.stats.rules_optimal &&
             result.stats.literals_optimal &&
             result.stats.hardware_optimal &&
             result.stats.logic_risk_optimal,
         label + " proves all four lexicographic objectives");
  expect(result.stats.third_objective == "unique_inverters" &&
             result.stats.fourth_objective == "logic_risk_proxy" &&
             result.stats.logic_risk_context_available,
         label + " reports the requested graph-only proxy");
  expect(result.stats.solver_checks == 8,
         label + " runs four LP/MIP pairs");
  expect(result.stats.lp4_status == "Optimal" &&
             result.stats.mip4_status == "Optimal" &&
             result.stats.mip4_gap <= 1.0e-9,
         label + " records an optimal final LP/MIP pair");
  expect(result.stats.lp4_objective <=
             result.stats.mip4_objective +
                 1.0e-7 * (1.0 + std::fabs(result.stats.mip4_objective)),
         label + " LP4 is a valid proxy lower bound");
  expect(std::fabs(result.stats.mip4_objective -
                   result.stats.logic_risk_objective_after) <=
             1.0e-6 *
                 (1.0 + std::fabs(result.stats.mip4_objective)),
         label + " recomputes the proxy from extracted rules");
  expect(!result.stats.phase4_timeout_fallback &&
             !result.stats.phase4_unavailable_fallback,
         label + " does not use a phase-4 fallback");
}

std::size_t model_unique_features(const DecisionTreeModel& model) {
  std::vector<std::size_t> features;
  for (const auto& rule : model.rules) {
    for (const auto& literal : rule.terms) {
      features.push_back(literal.first);
    }
  }
  std::sort(features.begin(), features.end());
  features.erase(std::unique(features.begin(), features.end()),
                 features.end());
  return features.size();
}

void test_logic_risk_unique_feature_and_exact_or() {
  // f2 duplicates f0 and f3 duplicates f1.  XOR fixes R*=2, L*=4, I*=2;
  // phase 4 must retain all truth-equivalent gate alternatives and use the
  // same two feature nodes in both polarities, minimizing exact OR(q_f).
  const std::vector<std::vector<int>> rows = {
      {0, 0, 0, 0}, {0, 1, 0, 1},
      {1, 0, 1, 0}, {1, 1, 1, 1}};
  const DecisionTreeModel baseline =
      make_model({{{0, 0}, {1, 1}}, {{0, 1}, {1, 0}}});
  RuleOptimizerOptions options = logic_risk_options(1.0, 0.0, 0.0);
  options.max_clauses = 2;
  options.max_literals_per_clause = 2;
  const RuleCoverCostContext context = make_cost_context(
      {{1, 1}, {1, 1}, {1, 1}, {1, 1}}, 4);
  const RuleOptimizationResult result = optimize(
      rows, {0, 1, 1, 0}, {0, 1, 2, 3}, baseline, options, 0, &context);
  expect_logic_risk_success(result, "logic-risk unique-feature tie");
  expect(result.stats.unique_candidate_features == 4 &&
             result.stats.pool_terms_coverage_alternatives >= 4,
         "logic-risk retains truth/coverage-equivalent feature alternatives");
  expect(model_unique_features(result.model) == 2 &&
             result.stats.unique_features_after == 2,
         "unique-feature objective shares exactly two feature taps");
  expect(result.stats.logic_risk_feature_variables == 4 &&
             result.stats.logic_risk_feature_link_constraints > 4,
         "q_f master telemetry contains exact lower and upper OR links");
  expect(std::fabs(result.stats.logic_risk_unique_component_after - 0.5) <=
             1.0e-7,
         "unique-feature component uses the documented L* normalization");
}

void test_logic_risk_fanout_tie_and_full_rows() {
  // Both features have the same finite truth signature.  The second feature
  // has no existing consumers, so the fanout-load proxy must choose it.
  const std::vector<std::vector<int>> rows = {{0, 0}, {1, 1}};
  const DecisionTreeModel baseline = make_model({{{0, 1}}});
  RuleOptimizerOptions options = logic_risk_options(0.0, 1.0, 0.0);
  options.max_clauses = 1;
  options.max_literals_per_clause = 1;
  const RuleCoverCostContext context = make_cost_context({{31, 1}, {0, 1}}, 3);
  const RuleOptimizationResult result = optimize(
      rows, {0, 1}, {0, 1}, baseline, options, 130, &context);
  expect_logic_risk_success(result, "logic-risk fanout tie");
  expect(result.model.rules.size() == 1 &&
             result.model.rules[0].terms ==
                 std::vector<std::pair<std::size_t, int>>{{1, 1}},
         "fanout proxy chooses the lower-load truth-equivalent feature");
  expect(result.stats.feature_loads_after == 1 &&
             std::fabs(result.stats.fanout_stress_after) <= 1.0e-9 &&
             result.stats.verification_false_positive == 0 &&
             result.stats.verification_false_negative == 0,
         "fanout winner is recomputed and verified over active packed rows");
}

void test_logic_risk_timing_tie() {
  const std::vector<std::vector<int>> rows = {{0, 0}, {1, 1}};
  const DecisionTreeModel baseline = make_model({{{0, 1}}});
  RuleOptimizerOptions options = logic_risk_options(0.0, 0.0, 1.0);
  options.max_clauses = 1;
  options.max_literals_per_clause = 1;
  const RuleCoverCostContext context = make_cost_context({{1, 9}, {1, 2}}, 10);
  const RuleOptimizationResult result = optimize(
      rows, {0, 1}, {0, 1}, baseline, options, 0, &context);
  expect_logic_risk_success(result, "logic-risk timing tie");
  expect(result.model.rules.size() == 1 &&
             result.model.rules[0].terms ==
                 std::vector<std::pair<std::size_t, int>>{{1, 1}},
         "timing proxy chooses the shallower truth-equivalent feature");
  expect(result.stats.max_term_arrival_after == 2 &&
             result.stats.match_depth_proxy_after == 2 &&
             result.stats.max_term_arrival_before == 9,
         "timing telemetry follows the balanced unit-level recurrence");
}

void test_phase4_safe_fallbacks_and_validation() {
  const std::vector<std::vector<int>> rows = {{0, 1}, {1, 0}};
  const DecisionTreeModel baseline = make_model({{{0, 0}}});
  const RuleCoverCostContext context = make_cost_context({{2, 3}, {1, 1}}, 4);

  RuleOptimizerOptions timeout = logic_risk_options(1.0, 1.0, 1.0);
  timeout.max_clauses = 1;
  timeout.max_literals_per_clause = 1;
  timeout.phase4_timeout_ms = 0;
  const RuleOptimizationResult timed_out = optimize(
      rows, {1, 0}, {0, 1}, baseline, timeout, 0, &context);
  expect(timed_out.stats.status == "accepted_phase4_timeout" &&
             timed_out.stats.accepted && timed_out.stats.verified &&
             timed_out.stats.hardware_optimal &&
             !timed_out.stats.logic_risk_optimal &&
             !timed_out.stats.optimal &&
             timed_out.stats.phase4_timeout_fallback &&
             timed_out.stats.solver_checks == 6,
         "zero phase-4 budget safely retains the verified MIP3 optimum");

  RuleOptimizerOptions unavailable = logic_risk_options(1.0, 0.0, 0.0);
  unavailable.max_clauses = 1;
  unavailable.max_literals_per_clause = 1;
  const RuleOptimizationResult missing = optimize(
      rows, {1, 0}, {0, 1}, baseline, unavailable);
  expect(missing.stats.status == "accepted_phase4_unavailable" &&
             missing.stats.accepted && missing.stats.verified &&
             missing.stats.hardware_optimal &&
             !missing.stats.logic_risk_optimal &&
             missing.stats.phase4_unavailable_fallback &&
             !missing.stats.logic_risk_context_available &&
             missing.stats.solver_checks == 6,
         "missing context safely retains the verified MIP3 optimum");

  const RuleCoverCostContext short_context = make_cost_context({{1, 1}}, 2);
  const RuleOptimizationResult mismatched = optimize(
      rows, {1, 0}, {0, 1}, baseline, unavailable, 0, &short_context);
  expect(mismatched.stats.status == "accepted_phase4_unavailable" &&
             mismatched.stats.accepted && mismatched.stats.verified &&
             mismatched.stats.hardware_optimal &&
             !mismatched.stats.logic_risk_optimal &&
             mismatched.stats.phase4_unavailable_fallback &&
             mismatched.stats.logic_risk_context_reason.find("size") !=
                 std::string::npos,
         "mismatched context safely retains the verified MIP3 optimum");

  RuleOptimizerOptions invalid = logic_risk_options(1.0, -1.0, 0.0);
  invalid.max_clauses = 1;
  invalid.max_literals_per_clause = 1;
  const RuleOptimizationResult rejected = optimize(
      rows, {1, 0}, {0, 1}, baseline, invalid, 0, &context);
  expect(!rejected.stats.accepted && rejected.stats.status == "invalid" &&
             models_equal(rejected.model, baseline),
         "negative logic-risk weights are rejected before optimization");
}

void test_unique_inverter_tie_and_default_compatibility() {
  // Both one-literal rules classify the finite table exactly.  The default
  // path keeps the lexical !f0 representative, while phase 3 recognizes that
  // f1=1 implements the same R*=1, L*=1 solution without an inverter.
  const std::vector<std::vector<int>> rows = {{0, 1}, {1, 0}};
  const std::vector<int> labels = {1, 0};
  const DecisionTreeModel baseline = make_model({{{0, 0}}});
  RuleOptimizerOptions none = test_options();
  none.max_clauses = 1;
  none.max_literals_per_clause = 1;
  const RuleOptimizationResult original =
      optimize(rows, labels, {0, 1}, baseline, none);
  expect_exact_success(original, "default inverter tie");
  expect(original.stats.third_objective == "none" &&
             !original.stats.hardware_optimal &&
             original.stats.lp3_status.empty() &&
             original.stats.mip3_status.empty(),
         "default objective preserves the four-phase behavior");
  expect(original.model.rules.size() == 1 &&
             original.model.rules[0].terms ==
                 std::vector<std::pair<std::size_t, int>>{{0, 0}},
         "default objective preserves the lexical negative-literal rule");
  expect(original.stats.unique_inverters_before == 1 &&
             original.stats.unique_inverters_after == 1,
         "default path reports unchanged baseline/output inverter counts");

  RuleOptimizerOptions hardware = none;
  hardware.cover_third_objective =
      RuleCoverThirdObjective::unique_inverters;
  const RuleOptimizationResult optimized =
      optimize(rows, labels, {0, 1}, baseline, hardware);
  expect_hardware_success(optimized, "unique-inverter tie");
  expect(optimized.model.rules.size() == 1 &&
             optimized.model.rules[0].terms ==
                 std::vector<std::pair<std::size_t, int>>{{1, 1}},
         "unique-inverter tie selects the all-positive rule");
  expect(optimized.stats.rules_after == original.stats.rules_after &&
             optimized.stats.literals_after ==
                 original.stats.literals_after,
         "third objective does not change the R* or L* optima");
  expect(optimized.stats.unique_inverters_after == 0 &&
             optimized.stats.unique_inverters_before == 1 &&
             optimized.stats.mip3_objective == 0.0,
         "all-positive tie has zero unique inverter cost");
}

void test_incomparable_coverage_alternatives() {
  // The two shortest prime implicants !a&b and b&!c cover exactly the same
  // positive signature.  Their negative-feature sets {a} and {c} are
  // incomparable, so phase-3 exactness requires retaining both columns.
  const std::vector<std::vector<int>> rows = {
      {0, 1, 0}, {1, 1, 1}, {0, 0, 1}, {1, 0, 0}};
  const DecisionTreeModel baseline = make_model({{{0, 0}, {1, 1}}});
  RuleOptimizerOptions options = test_options();
  options.max_clauses = 1;
  options.max_literals_per_clause = 2;
  options.cover_third_objective =
      RuleCoverThirdObjective::unique_inverters;
  const RuleOptimizationResult result =
      optimize(rows, {1, 0, 0, 0}, {0, 1, 2}, baseline, options);
  expect_hardware_success(result, "incomparable alternatives");
  expect(result.stats.pool_terms_coverage_alternatives >= 1,
         "incomparable negative-feature alternatives survive coverage dedup");
  expect(result.stats.pool_terms_final >= 2,
         "phase-3 master receives both incomparable alternatives");
  expect(result.stats.inverter_features == 2 &&
             result.stats.inverter_link_constraints == 4,
         "inverter OR telemetry counts feature and link rows");
  expect(result.stats.unique_inverters_after == 1,
         "incomparable-alternative optimum uses one inverter");
}

void test_phase3_deadline_safe_fallback() {
  const std::vector<std::vector<int>> rows = {{0, 1}, {1, 0}};
  const DecisionTreeModel baseline = make_model({{{0, 0}}});
  RuleOptimizerOptions options = test_options();
  options.max_clauses = 1;
  options.max_literals_per_clause = 1;
  options.cover_third_objective =
      RuleCoverThirdObjective::unique_inverters;
  options.phase3_timeout_ms = 0;
  const RuleOptimizationResult fallback =
      optimize(rows, {1, 0}, {0, 1}, baseline, options);
  expect(fallback.stats.status == "accepted_phase3_timeout",
         "zero phase-3 sub-budget exercises the verified MIP2 fallback");
  expect(fallback.stats.accepted && fallback.stats.verified &&
             fallback.stats.phase3_timeout_fallback &&
             fallback.stats.phase3_timeout_ms == 0,
         "phase-3 timeout safely accepts the previously verified MIP2 model");
  expect(fallback.stats.rules_optimal && fallback.stats.literals_optimal &&
             !fallback.stats.hardware_optimal && !fallback.stats.optimal,
         "phase-3 timeout preserves R*/L* but makes no hardware optimum claim");
  expect(fallback.stats.rules_after == 1 &&
             fallback.stats.literals_after == 1 &&
             fallback.stats.solver_checks == 4,
         "phase-3 fallback retains the fixed MIP2 objective values");
  expect(!fallback.stats.reason.empty(),
         "phase-3 timeout records a diagnostic reason");
}

void test_single_cube() {
  const DecisionTreeModel baseline = make_model({{{0, 1}, {1, 1}}});
  const RuleOptimizationResult result = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 0, 0, 1}, {0, 1}, baseline);
  expect_exact_success(result, "single cube");
  expect(result.model.rules.size() == 1 &&
             result.model.rules[0].terms ==
                 std::vector<std::pair<std::size_t, int>>{{0, 1}, {1, 1}},
         "single cube extracts the expected conjunction");
  expect(result.stats.pool_terms_unique == 1 &&
             result.stats.pool_terms_final == 1,
         "single cube generates one prime implicant");
}

void test_xor_two_cubes() {
  const DecisionTreeModel baseline =
      make_model({{{0, 0}, {1, 1}}, {{0, 1}, {1, 0}}});
  RuleOptimizerOptions options = test_options();
  options.max_clauses = 2;
  options.max_literals_per_clause = 2;
  const RuleOptimizationResult result = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 1, 1, 0}, {0, 1}, baseline, options);
  expect_exact_success(result, "XOR");
  expect(result.model.rules.size() == 2 &&
             result.stats.literals_after == 4,
         "XOR requires two two-literal clauses");
}

void test_multi_trigger_dnf() {
  std::vector<std::vector<int>> rows;
  std::vector<int> labels;
  for (int value = 0; value < 8; ++value) {
    const int a = (value >> 2) & 1;
    const int b = (value >> 1) & 1;
    const int c = value & 1;
    rows.push_back({a, b, c});
    labels.push_back((a && b) || (!a && c));
  }
  const DecisionTreeModel baseline =
      make_model({{{0, 1}, {1, 1}}, {{0, 0}, {2, 1}}});
  RuleOptimizerOptions options = test_options();
  options.max_clauses = 2;
  options.max_literals_per_clause = 2;
  const RuleOptimizationResult result =
      optimize(rows, labels, {0, 1, 2}, baseline, options);
  expect_exact_success(result, "multi-trigger DNF");
  expect(result.model.rules.size() == 2 &&
             result.stats.literals_after == 4,
         "multi-trigger function keeps two compact clauses");
}

void test_global_simplification() {
  const DecisionTreeModel baseline =
      make_model({{{0, 1}, {1, 0}}, {{0, 1}, {1, 1}}});
  RuleOptimizerOptions options = test_options();
  options.max_clauses = 2;
  options.max_literals_per_clause = 2;
  const RuleOptimizationResult result = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 0, 1, 1}, {0, 1}, baseline, options);
  expect_exact_success(result, "global simplification");
  expect(result.stats.rules_before == 2 &&
             result.stats.literals_before == 4 &&
             result.stats.rules_after == 1 &&
             result.stats.literals_after == 1,
         "global simplification improves both objectives");
  expect(result.model.rules[0].terms ==
             std::vector<std::pair<std::size_t, int>>{{0, 1}},
         "global simplification learns f0=1");
}

void test_lexicographic_rule_priority() {
  // One two-literal term (a=1 & b=1) covers both positives.  Two separate
  // one-literal terms (d=1, e=1) use fewer total literals, but lexicographic
  // optimization must prefer the single rule.
  const std::vector<std::vector<int>> rows = {
      {1, 1, 1, 0}, {1, 1, 0, 1},
      {1, 0, 0, 0}, {0, 1, 0, 0}};
  const DecisionTreeModel baseline =
      make_model({{{2, 1}}, {{3, 1}}});
  RuleOptimizerOptions options = test_options();
  options.max_clauses = 2;
  options.max_literals_per_clause = 2;
  const RuleOptimizationResult result =
      optimize(rows, {1, 1, 0, 0}, {0, 1, 2, 3}, baseline, options);
  expect_exact_success(result, "lexicographic priority");
  expect(result.model.rules.size() == 1 &&
             result.model.rules[0].terms.size() == 2,
         "rule count is minimized before total literals");
  expect(result.model.rules[0].terms ==
             std::vector<std::pair<std::size_t, int>>{{0, 1}, {1, 1}},
         "lexicographic priority selects the shared two-literal term");
}

void test_projection_conflict() {
  const PackedFeatureMatrix matrix = make_matrix({{0, 0}, {0, 1}});
  const DecisionTreeModel baseline = make_model({{{0, 0}}});
  const RuleOptimizationResult result =
      optimize_dnf_rules_highs_set_cover(
          matrix, {0, 1}, {0}, baseline, test_options());
  expect(!result.stats.accepted && result.stats.status == "infeasible",
         "conflicting projected signatures are infeasible");
  expect(result.stats.conflicting_signatures == 1,
         "projection conflicts are counted");
  expect(models_equal(result.model, baseline),
         "projection conflict preserves baseline fallback");
}

void test_clause_and_literal_limits() {
  const DecisionTreeModel xor_baseline =
      make_model({{{0, 0}, {1, 1}}, {{0, 1}, {1, 0}}});
  RuleOptimizerOptions one_clause = test_options();
  one_clause.max_clauses = 1;
  one_clause.max_literals_per_clause = 2;
  const RuleOptimizationResult xor_result = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 1, 1, 0}, {0, 1}, xor_baseline, one_clause);
  expect(!xor_result.stats.accepted &&
             xor_result.stats.status == "infeasible",
         "XOR is infeasible with one clause");

  const DecisionTreeModel and_baseline = make_model({{{0, 1}, {1, 1}}});
  RuleOptimizerOptions one_literal = test_options();
  one_literal.max_clauses = 1;
  one_literal.max_literals_per_clause = 1;
  const RuleOptimizationResult and_result = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 0, 0, 1}, {0, 1}, and_baseline, one_literal);
  expect(!and_result.stats.accepted &&
             and_result.stats.status == "infeasible",
         "AND is infeasible with a one-literal term cap");
}

void test_packed_tail_and_feature_deduplication() {
  std::vector<std::vector<int>> rows;
  std::vector<int> labels;
  for (std::size_t row = 0; row < 130; ++row) {
    const int a = static_cast<int>(row & 1U);
    const int b = static_cast<int>((row >> 1U) & 1U);
    rows.push_back({a, b, a});
    labels.push_back(a && b);
  }
  const DecisionTreeModel baseline = make_model({{{0, 1}, {1, 1}}});
  const RuleOptimizationResult result = optimize(
      rows, labels, {2, 1, 0, 2}, baseline, test_options(), 200);
  expect_exact_success(result, "packed-tail deduplication");
  expect(result.stats.unique_candidate_features == 2,
         "duplicate feature truth signatures are removed");
  expect(result.stats.unique_pattern_signatures == 4 &&
             result.stats.duplicate_pattern_rows == 126,
         "pattern dedup handles >64 rows and spare packed capacity");
}

void test_pool_limit_timeout_and_invalid() {
  const DecisionTreeModel xor_baseline =
      make_model({{{0, 0}, {1, 1}}, {{0, 1}, {1, 0}}});
  RuleOptimizerOptions pool_limit = test_options();
  pool_limit.max_clauses = 2;
  pool_limit.max_literals_per_clause = 2;
  pool_limit.max_pool_terms = 1;
  const RuleOptimizationResult limited = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 1, 1, 0}, {0, 1}, xor_baseline, pool_limit);
  expect(!limited.stats.accepted && limited.stats.status == "pool_limit" &&
             !limited.stats.pool_complete,
         "term-pool truncation safely falls back without optimality claim");
  expect(models_equal(limited.model, xor_baseline),
         "term-pool limit preserves baseline model");

  RuleOptimizerOptions state_limit = test_options();
  state_limit.max_pool_states = 1;
  const DecisionTreeModel and_baseline = make_model({{{0, 1}, {1, 1}}});
  const RuleOptimizationResult state_limited = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 0, 0, 1}, {0, 1}, and_baseline, state_limit);
  expect(!state_limited.stats.accepted &&
             state_limited.stats.status == "pool_limit" &&
             state_limited.stats.pool_state_limit_hit,
         "partial-state guard safely stops pre-leaf enumeration growth");

  RuleOptimizerOptions timeout = test_options();
  timeout.timeout_ms = 0;
  timeout.cover_third_objective =
      RuleCoverThirdObjective::unique_inverters;
  const RuleOptimizationResult timed_out = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 0, 0, 1}, {0, 1}, and_baseline, timeout);
  expect(!timed_out.stats.accepted && timed_out.stats.status == "timeout",
         "zero deadline is a deterministic timeout");
  expect(!timed_out.stats.phase3_timeout_fallback &&
             timed_out.stats.third_objective == "unique_inverters",
         "timeout before a verified MIP2 model uses the baseline fallback");
  expect(models_equal(timed_out.model, and_baseline),
         "timeout preserves baseline model");

  const PackedFeatureMatrix matrix =
      make_matrix({{0, 0}, {0, 1}, {1, 0}, {1, 1}});
  const RuleOptimizationResult invalid =
      optimize_dnf_rules_highs_set_cover(
          matrix, {0, 0, 1}, {0, 1}, and_baseline, test_options());
  expect(!invalid.stats.accepted && invalid.stats.status == "invalid",
         "invalid label length is rejected");
  expect(models_equal(invalid.model, and_baseline),
         "invalid input preserves baseline model");

  PackedFeatureMatrix short_capacity = matrix;
  short_capacity.capacity_rows = 1;
  const RuleOptimizationResult malformed_capacity =
      optimize_dnf_rules_highs_set_cover(
          short_capacity, {0, 0, 0, 1}, {0, 1}, and_baseline,
          test_options());
  expect(!malformed_capacity.stats.accepted &&
             malformed_capacity.stats.status == "invalid",
         "row count larger than packed capacity is rejected safely");

  PackedFeatureMatrix overflowing_dimensions;
  overflowing_dimensions.feature_count =
      std::numeric_limits<std::size_t>::max() / 2U + 1U;
  overflowing_dimensions.row_count = 1;
  overflowing_dimensions.capacity_rows = 65;
  const RuleOptimizationResult overflow =
      optimize_dnf_rules_highs_set_cover(
          overflowing_dimensions, {1}, {0}, and_baseline, test_options());
  expect(!overflow.stats.accepted && overflow.stats.status == "invalid",
         "overflowing packed dimensions are rejected safely");
}

void test_enumeration_depth_guard() {
  constexpr std::size_t feature_count = 257;
  std::vector<std::vector<int>> rows(
      feature_count + 1, std::vector<int>(feature_count, 1));
  // Each negative differs from the positive in exactly one distinct feature,
  // forcing the only hitting set to exceed the implementation's safe
  // recursive depth.  It must fall back rather than risking stack overflow.
  for (std::size_t feature = 0; feature < feature_count; ++feature) {
    rows[feature + 1][feature] = 0;
  }
  std::vector<int> labels(feature_count + 1, 0);
  labels[0] = 1;
  std::vector<std::size_t> candidates(feature_count);
  DecisionTreeRule baseline_rule;
  for (std::size_t feature = 0; feature < feature_count; ++feature) {
    candidates[feature] = feature;
    baseline_rule.terms.push_back({feature, 1});
  }
  DecisionTreeModel baseline;
  baseline.rules.push_back(std::move(baseline_rule));
  baseline.leaf_count = 1;
  baseline.max_depth_used = feature_count;
  RuleOptimizerOptions options = test_options();
  options.max_literals_per_clause = feature_count;
  options.max_pool_states = 10000;
  const RuleOptimizationResult result =
      optimize(rows, labels, candidates, baseline, options);
  expect(!result.stats.accepted && result.stats.status == "pool_limit" &&
             result.stats.pool_depth_limit_hit,
         "safe DFS-depth guard preserves fallback for adversarial clauses");
  expect(models_equal(result.model, baseline),
         "DFS-depth guard preserves the baseline model");
}

void test_determinism() {
  const std::vector<std::vector<int>> rows = {
      {1, 1, 1, 0}, {1, 1, 0, 1},
      {1, 0, 0, 0}, {0, 1, 0, 0}};
  const DecisionTreeModel baseline =
      make_model({{{2, 1}}, {{3, 1}}});
  RuleOptimizerOptions options = test_options();
  options.max_clauses = 2;
  options.max_literals_per_clause = 2;
  const RuleOptimizationResult first =
      optimize(rows, {1, 1, 0, 0}, {3, 1, 0, 2}, baseline, options);
  const RuleOptimizationResult second =
      optimize(rows, {1, 1, 0, 0}, {3, 1, 0, 2}, baseline, options);
  expect(first.stats.accepted && second.stats.accepted,
         "determinism runs are accepted");
  expect(models_equal(first.model, second.model),
         "set-cover output is deterministic");
}

std::pair<std::size_t, std::size_t> brute_force_three_feature_optimum(
    unsigned positive_mask) {
  struct ReferenceTerm {
    unsigned cover = 0;
    std::size_t literals = 0;
  };
  std::vector<ReferenceTerm> terms;
  // Ternary digit: 0 absent, 1 expects zero, 2 expects one.
  for (unsigned encoding = 1; encoding < 27; ++encoding) {
    unsigned state = encoding;
    std::size_t literals = 0;
    unsigned cover = 0;
    for (unsigned row = 0; row < 8; ++row) {
      unsigned digits = state;
      bool matches = true;
      std::size_t row_literals = 0;
      for (unsigned feature = 0; feature < 3; ++feature) {
        const unsigned digit = digits % 3;
        digits /= 3;
        if (digit == 0) continue;
        row_literals += 1;
        const unsigned expected = digit - 1;
        if (((row >> feature) & 1U) != expected) matches = false;
      }
      literals = row_literals;
      if (matches) cover |= 1U << row;
    }
    if (cover != 0 && (cover & ~positive_mask) == 0) {
      terms.push_back(ReferenceTerm{cover, literals});
    }
  }

  const std::pair<std::size_t, std::size_t> infinity = {
      1000, 1000};
  std::vector<std::pair<std::size_t, std::size_t>> best(256, infinity);
  best[0] = {0, 0};
  for (unsigned cardinality = 0; cardinality <= 8; ++cardinality) {
    for (unsigned covered = 0; covered < 256; ++covered) {
      if (static_cast<unsigned>(__builtin_popcount(covered)) != cardinality ||
          best[covered] == infinity) {
        continue;
      }
      for (const auto& term : terms) {
        const unsigned next = covered | term.cover;
        if (next == covered) continue;
        const std::pair<std::size_t, std::size_t> candidate = {
            best[covered].first + 1,
            best[covered].second + term.literals};
        if (candidate < best[next]) best[next] = candidate;
      }
    }
  }
  return best[positive_mask];
}

void test_all_three_feature_truth_tables() {
  std::vector<std::vector<int>> rows;
  for (unsigned row = 0; row < 8; ++row) {
    rows.push_back({static_cast<int>(row & 1U),
                    static_cast<int>((row >> 1U) & 1U),
                    static_cast<int>((row >> 2U) & 1U)});
  }

  // Exhaustively cross-check every nonconstant three-input truth table
  // against a direct ternary-clause dynamic program.  This is a compact
  // property test for minimal-hitting-set completeness and both MILP
  // objectives, rather than just a collection of hand-picked functions.
  for (unsigned positive_mask = 1; positive_mask < 255; ++positive_mask) {
    std::vector<int> labels;
    DecisionTreeModel baseline;
    for (unsigned row = 0; row < 8; ++row) {
      const bool positive = ((positive_mask >> row) & 1U) != 0;
      labels.push_back(positive ? 1 : 0);
      if (!positive) continue;
      DecisionTreeRule minterm;
      for (std::size_t feature = 0; feature < 3; ++feature) {
        minterm.terms.push_back(
            {feature, static_cast<int>((row >> feature) & 1U)});
      }
      baseline.rules.push_back(std::move(minterm));
    }
    baseline.leaf_count = baseline.rules.size();
    baseline.max_depth_used = 3;

    const auto expected =
        brute_force_three_feature_optimum(positive_mask);
    const RuleOptimizationResult result =
        optimize(rows, labels, {0, 1, 2}, baseline);
    const std::string label =
        "three-feature truth table " + std::to_string(positive_mask);
    expect(result.stats.accepted && result.stats.optimal,
           label + " is solved exactly");
    expect(result.model.rules.size() == expected.first,
           label + " matches brute-force rule optimum");
    expect(result.stats.literals_after == expected.second,
           label + " matches brute-force literal optimum");
  }
}

void test_no_backend_fallback() {
  const DecisionTreeModel baseline = make_model({{{0, 1}, {1, 1}}});
  const RuleOptimizationResult result = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 0, 0, 1}, {0, 1}, baseline);
  expect(!result.stats.accepted &&
             result.stats.status == "backend_unavailable",
         "build without USE_HIGHS reports backend_unavailable");
  expect(!result.stats.backend_available && models_equal(result.model, baseline),
         "unavailable backend safely preserves the baseline model");

  RuleOptimizerOptions p4 = logic_risk_options(1.0, 1.0, 1.0);
  const RuleCoverCostContext context = make_cost_context({{1, 1}, {1, 1}}, 2);
  const RuleOptimizationResult p4_result = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 0, 0, 1}, {0, 1}, baseline, p4, 0, &context);
  expect(!p4_result.stats.accepted &&
             p4_result.stats.status == "backend_unavailable" &&
             p4_result.stats.fourth_objective == "logic_risk_proxy" &&
             models_equal(p4_result.model, baseline),
         "no-backend phase-4 request preserves the baseline safely");
}

}  // namespace

int main() {
  if (!highs_set_cover_backend_available()) {
    test_no_backend_fallback();
  } else {
    test_logic_risk_unique_feature_and_exact_or();
    test_logic_risk_fanout_tie_and_full_rows();
    test_logic_risk_timing_tie();
    test_phase4_safe_fallbacks_and_validation();
    test_unique_inverter_tie_and_default_compatibility();
    test_incomparable_coverage_alternatives();
    test_phase3_deadline_safe_fallback();
    test_single_cube();
    test_xor_two_cubes();
    test_multi_trigger_dnf();
    test_global_simplification();
    test_lexicographic_rule_priority();
    test_projection_conflict();
    test_clause_and_literal_limits();
    test_packed_tail_and_feature_deduplication();
    test_pool_limit_timeout_and_invalid();
    test_enumeration_depth_guard();
    test_determinism();
    test_all_three_feature_truth_tables();
  }

  if (failures != 0) {
    std::cerr << failures << " set-cover optimizer test(s) failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "PASS: set-cover optimizer tests"
            << (highs_set_cover_backend_available() ? " (HiGHS)" :
                                                      " (fallback)")
            << '\n';
  return EXIT_SUCCESS;
}
