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
    std::size_t capacity = 0) {
  return optimize_dnf_rules_highs_set_cover(
      make_matrix(rows, capacity), labels, candidates, baseline, options);
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
  const RuleOptimizationResult timed_out = optimize(
      {{0, 0}, {0, 1}, {1, 0}, {1, 1}},
      {0, 0, 0, 1}, {0, 1}, and_baseline, timeout);
  expect(!timed_out.stats.accepted && timed_out.stats.status == "timeout",
         "zero deadline is a deterministic timeout");
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
}

}  // namespace

int main() {
  if (!highs_set_cover_backend_available()) {
    test_no_backend_fallback();
  } else {
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
