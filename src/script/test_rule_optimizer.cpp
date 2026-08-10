#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "../algorithm/rule_optimizer.hpp"

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
  matrix.allocate(feature_count,
                  capacity == 0 ? rows.size() : capacity);
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
  options.timeout_ms = 5000;
  options.max_rounds = 50;
  options.counterexample_batch_size = 1;
  return options;
}

bool models_equal(const DecisionTreeModel& a, const DecisionTreeModel& b) {
  if (a.rules.size() != b.rules.size()) return false;
  for (std::size_t i = 0; i < a.rules.size(); ++i) {
    if (a.rules[i].terms != b.rules[i].terms) return false;
  }
  return true;
}

void test_single_cube() {
  const PackedFeatureMatrix matrix =
      make_matrix({{0, 0}, {0, 1}, {1, 0}, {1, 1}});
  const std::vector<int> labels{0, 0, 0, 1};
  const DecisionTreeModel baseline = make_model({{{0, 1}, {1, 1}}});
  RuleOptimizationResult result = optimize_dnf_rules_z3_pb(
      matrix, labels, {0, 1}, baseline, test_options());
  expect(result.stats.accepted, "single cube is accepted");
  expect(result.stats.optimal && result.stats.verified,
         "single cube is optimal and verified");
  expect(result.model.rules.size() == 1,
         "single cube uses one clause");
  expect(result.stats.literals_after == 2,
         "single cube needs two literals");
}

void test_xor_two_cubes() {
  const PackedFeatureMatrix matrix =
      make_matrix({{0, 0}, {0, 1}, {1, 0}, {1, 1}});
  const std::vector<int> labels{0, 1, 1, 0};
  const DecisionTreeModel baseline =
      make_model({{{0, 0}, {1, 1}}, {{0, 1}, {1, 0}}});
  RuleOptimizerOptions options = test_options();
  options.max_clauses = 2;
  options.max_literals_per_clause = 2;
  RuleOptimizationResult result = optimize_dnf_rules_z3_pb(
      matrix, labels, {0, 1}, baseline, options);
  expect(result.stats.accepted, "XOR DNF is accepted");
  expect(result.model.rules.size() == 2, "XOR needs two clauses");
  expect(result.stats.literals_after == 4, "XOR needs four literals");
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
  RuleOptimizationResult result = optimize_dnf_rules_z3_pb(
      make_matrix(rows), labels, {0, 1, 2}, baseline, options);
  expect(result.stats.accepted, "multi-trigger DNF is accepted");
  expect(result.model.rules.size() == 2,
         "multi-trigger function uses two clauses");
  expect(result.stats.literals_after == 4,
         "multi-trigger function uses four literals");
}

void test_global_simplification_beats_baseline() {
  const PackedFeatureMatrix matrix =
      make_matrix({{0, 0}, {0, 1}, {1, 0}, {1, 1}});
  const std::vector<int> labels{0, 0, 1, 1};
  // A depth-two tree can express f0 as two adjacent cubes.  The optimizer
  // should globally merge them instead of merely deleting within each cube.
  const DecisionTreeModel baseline =
      make_model({{{0, 1}, {1, 0}}, {{0, 1}, {1, 1}}});
  RuleOptimizerOptions options = test_options();
  options.max_clauses = 2;
  options.max_literals_per_clause = 2;
  RuleOptimizationResult result = optimize_dnf_rules_z3_pb(
      matrix, labels, {0, 1}, baseline, options);
  expect(result.stats.accepted, "global simplification is accepted");
  expect(result.stats.rules_before == 2 && result.stats.literals_before == 4,
         "global simplification records baseline complexity");
  expect(result.stats.rules_after == 1 && result.stats.literals_after == 1,
         "global optimizer reduces two cubes to one literal");
  expect(result.model.rules.size() == 1 &&
             result.model.rules[0].terms ==
                 std::vector<std::pair<std::size_t, int>>{{0, 1}},
         "global optimizer learns f0=1");
}

void test_signature_conflict() {
  const PackedFeatureMatrix matrix = make_matrix({{0, 0}, {0, 1}});
  const DecisionTreeModel baseline = make_model({{{0, 0}}});
  RuleOptimizationResult result = optimize_dnf_rules_z3_pb(
      matrix, {0, 1}, {0}, baseline, test_options());
  expect(!result.stats.accepted, "conflicting projection is rejected");
  expect(result.stats.status == "infeasible",
         "conflicting projection reports infeasible");
  expect(result.stats.conflicting_signatures == 1,
         "conflicting projection is counted");
  expect(models_equal(result.model, baseline),
         "conflict preserves fallback model");
}

void test_clause_and_literal_infeasible() {
  const PackedFeatureMatrix xor_matrix =
      make_matrix({{0, 0}, {0, 1}, {1, 0}, {1, 1}});
  const DecisionTreeModel xor_baseline =
      make_model({{{0, 0}, {1, 1}}, {{0, 1}, {1, 0}}});
  RuleOptimizerOptions one_clause = test_options();
  one_clause.max_clauses = 1;
  one_clause.max_literals_per_clause = 2;
  RuleOptimizationResult xor_result = optimize_dnf_rules_z3_pb(
      xor_matrix, {0, 1, 1, 0}, {0, 1}, xor_baseline, one_clause);
  expect(!xor_result.stats.accepted &&
             xor_result.stats.status == "infeasible",
         "XOR is infeasible with one clause");

  const PackedFeatureMatrix and_matrix =
      make_matrix({{0, 0}, {0, 1}, {1, 0}, {1, 1}});
  const DecisionTreeModel and_baseline =
      make_model({{{0, 1}, {1, 1}}});
  RuleOptimizerOptions one_literal = test_options();
  one_literal.max_clauses = 1;
  one_literal.max_literals_per_clause = 1;
  RuleOptimizationResult and_result = optimize_dnf_rules_z3_pb(
      and_matrix, {0, 0, 0, 1}, {0, 1}, and_baseline, one_literal);
  expect(!and_result.stats.accepted &&
             and_result.stats.status == "infeasible",
         "AND is infeasible with one literal");
}

void test_more_than_64_rows_and_deduplication() {
  std::vector<std::vector<int>> rows;
  std::vector<int> labels;
  for (std::size_t i = 0; i < 130; ++i) {
    const int a = static_cast<int>(i & 1U);
    const int b = static_cast<int>((i >> 1U) & 1U);
    rows.push_back({a, b, a});  // feature 2 duplicates feature 0.
    labels.push_back(a && b);
  }
  const DecisionTreeModel baseline = make_model({{{0, 1}, {1, 1}}});
  RuleOptimizationResult result = optimize_dnf_rules_z3_pb(
      make_matrix(rows, 200), labels, {2, 1, 0, 2}, baseline,
      test_options());
  expect(result.stats.accepted, ">64-row packed matrix is accepted");
  expect(result.stats.unique_candidate_features == 2,
         "duplicate feature signatures are removed");
  expect(result.stats.unique_pattern_signatures == 4,
         "duplicate rows reduce to four signatures");
  expect(result.stats.duplicate_pattern_rows == 126,
         "duplicate row count handles packed tail and spare capacity");
}

void test_determinism() {
  const PackedFeatureMatrix matrix =
      make_matrix({{0, 0}, {0, 1}, {1, 0}, {1, 1}});
  const DecisionTreeModel baseline =
      make_model({{{0, 0}, {1, 1}}, {{0, 1}, {1, 0}}});
  RuleOptimizerOptions options = test_options();
  options.max_clauses = 2;
  options.max_literals_per_clause = 2;
  RuleOptimizationResult first = optimize_dnf_rules_z3_pb(
      matrix, {0, 1, 1, 0}, {1, 0}, baseline, options);
  RuleOptimizationResult second = optimize_dnf_rules_z3_pb(
      matrix, {0, 1, 1, 0}, {1, 0}, baseline, options);
  expect(first.stats.accepted && second.stats.accepted,
         "determinism runs are accepted");
  expect(models_equal(first.model, second.model),
         "optimizer output is deterministic");
}

void test_timeout_and_invalid() {
  const PackedFeatureMatrix matrix =
      make_matrix({{0, 0}, {0, 1}, {1, 0}, {1, 1}});
  const DecisionTreeModel baseline = make_model({{{0, 1}, {1, 1}}});
  RuleOptimizerOptions timeout = test_options();
  timeout.timeout_ms = 0;
  RuleOptimizationResult timeout_result = optimize_dnf_rules_z3_pb(
      matrix, {0, 0, 0, 1}, {0, 1}, baseline, timeout);
  expect(!timeout_result.stats.accepted &&
             timeout_result.stats.status == "timeout",
         "zero wall budget reports deterministic timeout");
  expect(models_equal(timeout_result.model, baseline),
         "timeout preserves fallback model");

  RuleOptimizationResult invalid_result = optimize_dnf_rules_z3_pb(
      matrix, {0, 0, 1}, {0, 1}, baseline, test_options());
  expect(!invalid_result.stats.accepted &&
             invalid_result.stats.status == "invalid",
         "invalid label length is rejected");
  expect(models_equal(invalid_result.model, baseline),
         "invalid input preserves fallback model");
}

}  // namespace

int main() {
  test_single_cube();
  test_xor_two_cubes();
  test_multi_trigger_dnf();
  test_global_simplification_beats_baseline();
  test_signature_conflict();
  test_clause_and_literal_infeasible();
  test_more_than_64_rows_and_deduplication();
  test_determinism();
  test_timeout_and_invalid();

  if (failures != 0) {
    std::cerr << failures << " rule optimizer test(s) failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "PASS: rule optimizer tests\n";
  return EXIT_SUCCESS;
}
