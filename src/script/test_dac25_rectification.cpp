#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "../algorithm/dac25_rectification.hpp"

namespace {

int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

Dac25ValidationOptions validation_options(std::size_t max_targets = 3) {
  Dac25ValidationOptions options;
  options.timeout_ms = 5000;
  options.max_targets = max_targets;
  return options;
}

circuit make_single_golden(bool reverse_pis = false) {
  circuit net;
  if (reverse_pis) {
    net.define_pi("b");
    net.define_pi("a");
  } else {
    net.define_pi("a");
    net.define_pi("b");
  }
  net.define_gate("y", GType::BUFF, {net.node_index("a")});
  net.add_output_name("y");
  net.finalize_outputs();
  return net;
}

circuit make_single_trojan() {
  circuit net;
  net.define_pi("a");
  net.define_pi("b");
  net.define_gate("q", GType::NOT, {net.node_index("a")});
  net.define_gate("y", GType::BUFF, {net.node_index("q")});
  net.add_output_name("y");
  net.finalize_outputs();
  return net;
}

void test_singleton_exact_qe() {
  const circuit golden = make_single_golden();
  const circuit trojan = make_single_trojan();
  const Dac25ValidationResult empty = validate_dac25_rectification_targets(
      golden, trojan, {}, validation_options());
  expect(empty.status == Dac25ValidationStatus::infeasible,
         "empty target set detects an unrepairable PI");
  expect(empty.counterexample_pi_values.size() == 2,
         "infeasible validation returns a complete PI assignment");

  const Dac25ValidationResult target = validate_dac25_rectification_targets(
      golden, trojan, {trojan.node_index("q")}, validation_options());
  expect(target.feasible(), "cutting q is feasible");
  expect(target.target_assignments == 2,
         "singleton validation expands both cofactors");
  expect(target.encoded_circuit_copies == 3,
         "singleton validation builds one golden plus two Trojan copies");
}

void test_irrelevant_target_is_infeasible() {
  circuit golden;
  golden.define_pi("a");
  golden.define_pi("b");
  golden.define_gate("y0", GType::BUFF, {golden.node_index("a")});
  golden.define_gate("y1", GType::BUFF, {golden.node_index("b")});
  golden.add_output_name("y0");
  golden.add_output_name("y1");
  golden.finalize_outputs();

  circuit trojan;
  trojan.define_pi("a");
  trojan.define_pi("b");
  trojan.define_gate("bad", GType::NOT, {trojan.node_index("a")});
  trojan.define_gate("q", GType::BUFF, {trojan.node_index("b")});
  trojan.define_gate("y0", GType::BUFF, {trojan.node_index("bad")});
  trojan.define_gate("y1", GType::BUFF, {trojan.node_index("q")});
  trojan.add_output_name("y0");
  trojan.add_output_name("y1");
  trojan.finalize_outputs();

  const Dac25ValidationResult result = validate_dac25_rectification_targets(
      golden, trojan, {trojan.node_index("q")}, validation_options());
  expect(result.status == Dac25ValidationStatus::infeasible,
         "an unrelated target cannot repair another output");
}

void test_pair_is_required() {
  circuit golden;
  golden.define_pi("a");
  golden.define_pi("b");
  golden.define_gate("y0", GType::BUFF, {golden.node_index("a")});
  golden.define_gate("y1", GType::BUFF, {golden.node_index("b")});
  golden.add_output_name("y0");
  golden.add_output_name("y1");
  golden.finalize_outputs();

  circuit trojan;
  trojan.define_pi("a");
  trojan.define_pi("b");
  trojan.define_gate("q0", GType::NOT, {trojan.node_index("a")});
  trojan.define_gate("q1", GType::NOT, {trojan.node_index("b")});
  trojan.define_gate("y0", GType::BUFF, {trojan.node_index("q0")});
  trojan.define_gate("y1", GType::BUFF, {trojan.node_index("q1")});
  trojan.add_output_name("y0");
  trojan.add_output_name("y1");
  trojan.finalize_outputs();

  const int q0 = trojan.node_index("q0");
  const int q1 = trojan.node_index("q1");
  expect(validate_dac25_rectification_targets(
             golden, trojan, {q0}, validation_options())
             .status == Dac25ValidationStatus::infeasible,
         "q0 alone is infeasible");
  expect(validate_dac25_rectification_targets(
             golden, trojan, {q1}, validation_options())
             .status == Dac25ValidationStatus::infeasible,
         "q1 alone is infeasible");
  const Dac25ValidationResult pair = validate_dac25_rectification_targets(
      golden, trojan, {q0, q1}, validation_options());
  expect(pair.feasible(), "q0/q1 pair is feasible");
  expect(pair.target_assignments == 4,
         "pair validation expands all four target assignments");
}

void test_target_fanouts_share_one_value() {
  circuit golden;
  golden.define_pi("a");
  golden.define_gate("y0", GType::BUFF, {golden.node_index("a")});
  golden.define_gate("y1", GType::BUFF, {golden.node_index("a")});
  golden.add_output_name("y0");
  golden.add_output_name("y1");
  golden.finalize_outputs();

  circuit trojan;
  trojan.define_pi("a");
  trojan.define_gate("q", GType::BUFF, {trojan.node_index("a")});
  trojan.define_gate("y0", GType::BUFF, {trojan.node_index("q")});
  trojan.define_gate("y1", GType::NOT, {trojan.node_index("q")});
  trojan.add_output_name("y0");
  trojan.add_output_name("y1");
  trojan.finalize_outputs();

  const Dac25ValidationResult result = validate_dac25_rectification_targets(
      golden, trojan, {trojan.node_index("q")}, validation_options());
  expect(result.status == Dac25ValidationStatus::infeasible,
         "one target value is shared consistently by all fanouts");
}

void test_name_alignment_and_input_validation() {
  const circuit golden = make_single_golden(true);
  const circuit trojan = make_single_trojan();
  const Dac25ValidationResult result = validate_dac25_rectification_targets(
      golden, trojan, {trojan.node_index("q")}, validation_options());
  expect(result.feasible(), "PI order is aligned by signal name");

  const Dac25ValidationResult duplicate =
      validate_dac25_rectification_targets(
          golden, trojan,
          {trojan.node_index("q"), trojan.node_index("q")},
          validation_options());
  expect(duplicate.status == Dac25ValidationStatus::invalid,
         "duplicate target nodes are rejected");

  Dac25ValidationOptions zero = validation_options();
  zero.timeout_ms = 0;
  const Dac25ValidationResult timeout = validate_dac25_rectification_targets(
      golden, trojan, {trojan.node_index("q")}, zero);
  expect(timeout.status == Dac25ValidationStatus::timeout,
         "zero budget deterministically returns timeout");
}

void test_planner_selects_minimum_cardinality() {
  const circuit golden = make_single_golden();
  const circuit trojan = make_single_trojan();
  Dac25PlanOptions options;
  options.timeout_ms = 5000;
  options.candidate_limit = 8;
  options.max_targets = 2;
  options.max_feasible_sets = 4;
  const Dac25PlanResult plan =
      plan_dac25_rectification(golden, trojan, options);
  expect(plan.status == Dac25PlanStatus::selected,
         "planner finds a feasible target set");
  expect(plan.selected_targets.size() == 1,
         "planner stops at minimum cardinality one");
  expect(plan.sets_checked >= 1 && plan.feasible_sets >= 1,
         "planner exposes qualification telemetry");
  expect(!plan.observed_mismatching_outputs.empty() &&
             plan.observed_mismatching_outputs.front() == "y",
         "planner records the observed mismatching PO");
}

void test_planner_zero_budget_reports_timeout() {
  const circuit golden = make_single_golden();
  const circuit trojan = make_single_trojan();
  Dac25PlanOptions options;
  options.timeout_ms = 0;
  const Dac25PlanResult plan =
      plan_dac25_rectification(golden, trojan, options);
  expect(plan.status == Dac25PlanStatus::timeout,
         "planner preserves a deterministic timeout status");
  expect(!plan.reason.empty(), "planner timeout includes a reason");
}

}  // namespace

int main() {
  test_singleton_exact_qe();
  test_irrelevant_target_is_infeasible();
  test_pair_is_required();
  test_target_fanouts_share_one_value();
  test_name_alignment_and_input_validation();
  test_planner_selects_minimum_cardinality();
  test_planner_zero_budget_reports_timeout();
  if (failures != 0) {
    std::cerr << failures << " DAC25 rectification test(s) failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "DAC25 rectification tests passed\n";
  return EXIT_SUCCESS;
}
