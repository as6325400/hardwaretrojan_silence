#include <algorithm>
#include <iostream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "../algorithm/sat_refine.hpp"

namespace {

int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    failures += 1;
  }
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

circuit make_golden_error_b(std::size_t extra_pis = 0) {
  circuit net;
  net.define_pi("a");
  net.define_pi("b");
  for (std::size_t i = 0; i < extra_pis; ++i) {
    net.define_pi("x" + std::to_string(i));
  }
  net.define_gate("y", GType::BUFF, {net.node_index("a")});
  net.add_output_name("y");
  net.finalize_outputs();
  return net;
}

circuit make_trojan_error_b(std::size_t extra_pis = 0) {
  circuit net;
  net.define_pi("a");
  net.define_pi("b");
  for (std::size_t i = 0; i < extra_pis; ++i) {
    net.define_pi("x" + std::to_string(i));
  }
  net.define_gate("y", GType::XOR,
                  {net.node_index("a"), net.node_index("b")});
  net.add_output_name("y");
  net.finalize_outputs();
  return net;
}

std::pair<circuit, circuit> make_two_output_scoped_miter() {
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
  trojan.define_gate("y0", GType::XOR,
                     {trojan.node_index("a"), trojan.node_index("b")});
  trojan.define_gate("y1", GType::XOR,
                     {trojan.node_index("b"), trojan.node_index("a")});
  trojan.add_output_name("y0");
  trojan.add_output_name("y1");
  trojan.finalize_outputs();
  return {golden, trojan};
}

RuleMiterOptions test_options(std::size_t max_counterexamples = 5) {
  RuleMiterOptions options;
  options.max_counterexamples = max_counterexamples;
  options.timeout_ms = 5000;
  return options;
}

std::size_t count_kind(const RuleMiterResult& result,
                       RuleMiterCounterexampleKind kind) {
  return static_cast<std::size_t>(std::count_if(
      result.counterexamples.begin(), result.counterexamples.end(),
      [kind](const RuleMiterCounterexample& counterexample) {
        return counterexample.kind == kind;
      }));
}

std::string pattern_bits(const std::vector<int>& pattern) {
  std::string bits;
  bits.reserve(pattern.size());
  for (int value : pattern) bits.push_back(value ? '1' : '0');
  return bits;
}

bool same_counterexamples(const RuleMiterResult& lhs,
                          const RuleMiterResult& rhs) {
  if (lhs.counterexamples.size() != rhs.counterexamples.size()) return false;
  for (std::size_t i = 0; i < lhs.counterexamples.size(); ++i) {
    if (lhs.counterexamples[i].kind != rhs.counterexamples[i].kind ||
        lhs.counterexamples[i].pi_values != rhs.counterexamples[i].pi_values) {
      return false;
    }
  }
  return true;
}

void test_exact_rule() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("b")};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, test_options());
  expect(result.proved(), "R=b proves exact equivalence with E=b");
  expect(result.false_negative.status == RuleMiterQueryStatus::unsat,
         "exact rule proves the FN side UNSAT");
  expect(result.false_positive.status == RuleMiterQueryStatus::unsat,
         "exact rule proves the FP side UNSAT");
  expect(result.counterexamples.empty(), "exact rule returns no patterns");
  expect(result.solver_checks == 2, "exact rule checks both directions");
}

void test_false_positive_only() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("a"),
                                  trojan.node_index("b")};
  // R = b OR a is a superset of E=b.
  const DecisionTreeModel model = make_model({{{1, 1}}, {{0, 1}}});
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, test_options());
  expect(result.status == RuleMiterStatus::counterexamples,
         "superset rule reports counterexamples");
  expect(count_kind(result, RuleMiterCounterexampleKind::false_negative) == 0,
         "superset rule has no FN");
  expect(count_kind(result, RuleMiterCounterexampleKind::false_positive) == 1,
         "superset rule has one FP assignment");
  expect(result.false_negative.status == RuleMiterQueryStatus::unsat,
         "superset rule proves FN side UNSAT");
  expect(result.false_positive.status == RuleMiterQueryStatus::sat,
         "superset rule marks FP side SAT");
}

void test_false_negative_only() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("a"),
                                  trojan.node_index("b")};
  // R = a AND b is a subset of E=b.
  const DecisionTreeModel model = make_model({{{0, 1}, {1, 1}}});
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, test_options());
  expect(result.status == RuleMiterStatus::counterexamples,
         "subset rule reports counterexamples");
  expect(count_kind(result, RuleMiterCounterexampleKind::false_negative) == 1,
         "subset rule has one FN assignment");
  expect(count_kind(result, RuleMiterCounterexampleKind::false_positive) == 0,
         "subset rule has no FP");
  expect(result.false_negative.status == RuleMiterQueryStatus::sat,
         "subset rule marks FN side SAT");
  expect(result.false_positive.status == RuleMiterQueryStatus::unsat,
         "subset rule proves FP side UNSAT");
}

void test_both_directions_and_alternation() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("a")};
  // E=b and R=a differ once in each direction.
  const DecisionTreeModel model = make_model({{{0, 1}}});
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, test_options());
  expect(result.counterexamples.size() == 2,
         "two-direction rule returns both mismatching assignments");
  expect(result.counterexamples.size() >= 2 &&
             result.counterexamples[0].kind ==
                 RuleMiterCounterexampleKind::false_negative &&
             result.counterexamples[1].kind ==
                 RuleMiterCounterexampleKind::false_positive,
         "enumeration starts FN then alternates to FP");
  expect(count_kind(result, RuleMiterCounterexampleKind::false_negative) == 1,
         "both-direction rule returns one FN");
  expect(count_kind(result, RuleMiterCounterexampleKind::false_positive) == 1,
         "both-direction rule returns one FP");
}

void test_empty_dnf_is_false() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("b")};
  const DecisionTreeModel empty_model;
  const RuleMiterResult result = check_rule_miter(
      golden, trojan, features, empty_model, test_options());
  expect(result.status == RuleMiterStatus::counterexamples,
         "empty DNF is checked instead of skipped");
  expect(count_kind(result, RuleMiterCounterexampleKind::false_negative) == 2,
         "R=false finds both E=b positive assignments");
  expect(count_kind(result, RuleMiterCounterexampleKind::false_positive) == 0,
         "R=false has no FP");
}

void test_empty_term_is_true() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("b")};
  const DecisionTreeModel true_model = make_model({{}});
  const RuleMiterResult result = check_rule_miter(
      golden, trojan, features, true_model, test_options());
  expect(result.status == RuleMiterStatus::counterexamples,
         "empty clause is interpreted as TRUE");
  expect(count_kind(result, RuleMiterCounterexampleKind::false_positive) == 2,
         "R=true finds both E=b safe assignments");
  expect(count_kind(result, RuleMiterCounterexampleKind::false_negative) == 0,
         "R=true has no FN");
}

void test_batch_cap_and_determinism() {
  const circuit golden = make_golden_error_b(2);
  const circuit trojan = make_trojan_error_b(2);
  const std::vector<int> features{trojan.node_index("a")};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  const RuleMiterResult first =
      check_rule_miter(golden, trojan, features, model, test_options(99));
  const RuleMiterResult second =
      check_rule_miter(golden, trojan, features, model, test_options(99));
  expect(first.requested_counterexample_limit == 99,
         "batch telemetry records requested limit");
  expect(first.effective_counterexample_limit == 5,
         "batch is hard-capped at five");
  expect(first.counterexamples.size() == 5,
         "large mismatch space returns exactly the hard cap");
  expect(count_kind(first, RuleMiterCounterexampleKind::false_negative) > 0 &&
             count_kind(first, RuleMiterCounterexampleKind::false_positive) > 0,
         "batch cap does not starve either direction");
  expect(same_counterexamples(first, second),
         "two identical runs return the same counterexample sequence");
}

void test_zero_timeout_is_not_proof() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("b")};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  RuleMiterOptions options = test_options();
  options.timeout_ms = 0;
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, options);
  expect(result.status == RuleMiterStatus::timeout,
         "zero budget deterministically reports timeout");
  expect(!result.proved(), "timeout is never a proof");
  expect(result.solver_checks == 0, "zero budget performs no SAT checks");
}

void test_witness_status_transition_priority() {
  RuleMiterSideResult witnessed;
  witnessed.status = RuleMiterQueryStatus::sat;
  witnessed.models_found = 1;

  const RuleMiterSideResult timed_out = transition_rule_miter_side(
      witnessed, RuleMiterQueryStatus::timeout, "deadline");
  expect(timed_out.status == RuleMiterQueryStatus::sat,
         "SAT witness survives a later timeout");
  expect(timed_out.reason.find("remaining search timeout") !=
             std::string::npos,
         "SAT-to-timeout transition records incomplete enumeration");

  const RuleMiterSideResult unknown = transition_rule_miter_side(
      witnessed, RuleMiterQueryStatus::unknown, "solver unknown");
  expect(unknown.status == RuleMiterQueryStatus::sat,
         "SAT witness survives a later unknown");
  expect(unknown.reason.find("remaining search unknown") !=
             std::string::npos,
         "SAT-to-unknown transition records incomplete enumeration");

  RuleMiterResult fn_sat_fp_timeout;
  fn_sat_fp_timeout.false_negative = witnessed;
  fn_sat_fp_timeout.false_positive.status = RuleMiterQueryStatus::timeout;
  expect(aggregate_rule_miter_status(fn_sat_fp_timeout,
                                     RuleMiterStatus::timeout) ==
             RuleMiterStatus::counterexamples,
         "FN SAT dominates an FP timeout overall");

  RuleMiterResult fn_sat_fp_unknown = fn_sat_fp_timeout;
  fn_sat_fp_unknown.false_positive.status = RuleMiterQueryStatus::unknown;
  expect(aggregate_rule_miter_status(fn_sat_fp_unknown,
                                     RuleMiterStatus::unknown) ==
             RuleMiterStatus::counterexamples,
         "FN SAT dominates an FP unknown overall");

  RuleMiterResult blocked_sat;
  blocked_sat.false_negative = witnessed;
  blocked_sat.false_negative.blocked_violations = 1;
  expect(aggregate_rule_miter_status(blocked_sat,
                                     RuleMiterStatus::timeout) ==
             RuleMiterStatus::counterexamples,
         "blocked validated SAT dominates a later deadline");
  expect(aggregate_rule_miter_status(blocked_sat,
                                     RuleMiterStatus::invalid) ==
             RuleMiterStatus::counterexamples,
         "blocked validated SAT dominates a later exception");

  RuleMiterResult exact;
  exact.false_negative.status = RuleMiterQueryStatus::unsat;
  exact.false_positive.status = RuleMiterQueryStatus::unsat;
  expect(aggregate_rule_miter_status(exact, RuleMiterStatus::proved) ==
             RuleMiterStatus::proved,
         "formal proof still requires both directional queries UNSAT");
}

void test_zero_counterexample_capacity_checks_both_sides() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("a")};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, test_options(0));
  expect(result.status == RuleMiterStatus::counterexamples,
         "zero output capacity still reports discovered SAT queries");
  expect(result.counterexamples.empty(),
         "zero output capacity returns no patterns");
  expect(result.false_negative.models_found == 1 &&
             result.false_positive.models_found == 1,
         "zero output capacity still checks FN and FP once");
  expect(result.solver_checks == 2,
         "zero output capacity performs both directional checks");
}

void test_invalid_feature_rejected() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> invalid_features{
      static_cast<int>(trojan.node_count())};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  const RuleMiterResult result = check_rule_miter(
      golden, trojan, invalid_features, model, test_options());
  expect(result.status == RuleMiterStatus::invalid,
         "out-of-range feature node is invalid");
  expect(!result.proved(), "invalid input is never a proof");
}

void test_invalid_literal_value_rejected() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("b")};
  const DecisionTreeModel model = make_model({{{0, 2}}});
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, test_options());
  expect(result.status == RuleMiterStatus::invalid,
         "non-binary literal value is rejected");
}

void test_reordered_pi_and_po_names() {
  circuit golden;
  golden.define_pi("a");
  golden.define_pi("b");
  golden.define_gate("y0", GType::BUFF, {golden.node_index("a")});
  golden.define_gate("y1", GType::BUFF, {golden.node_index("b")});
  golden.add_output_name("y0");
  golden.add_output_name("y1");
  golden.finalize_outputs();

  circuit trojan;
  trojan.define_pi("b");
  trojan.define_pi("a");
  trojan.define_gate("y0", GType::XOR,
                     {trojan.node_index("a"), trojan.node_index("b")});
  trojan.define_gate("y1", GType::BUFF, {trojan.node_index("b")});
  trojan.add_output_name("y1");
  trojan.add_output_name("y0");
  trojan.finalize_outputs();

  const std::vector<int> features{trojan.node_index("b")};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, test_options());
  expect(result.proved(),
         "PI and PO declaration order is aligned by signal name");
}

void test_reordered_pi_counterexample_values_use_golden_order() {
  circuit golden;
  golden.define_pi("a");
  golden.define_pi("b");
  golden.define_gate("y", GType::BUFF, {golden.node_index("a")});
  golden.add_output_name("y");
  golden.finalize_outputs();

  circuit trojan;
  trojan.define_pi("b");
  trojan.define_pi("a");
  trojan.define_gate("y", GType::XOR,
                     {trojan.node_index("a"), trojan.node_index("b")});
  trojan.add_output_name("y");
  trojan.finalize_outputs();

  const std::vector<int> features{trojan.node_index("a")};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, test_options());
  expect(result.counterexamples.size() == 2,
         "reordered PI test returns both directional witnesses");
  expect(result.counterexamples.size() >= 2 &&
             result.counterexamples[0].pi_values ==
                 std::vector<int>({0, 1}) &&
             result.counterexamples[1].pi_values ==
                 std::vector<int>({1, 0}),
         "returned values follow Golden a,b order, not Trojan b,a order");
}

void test_missing_pi_name_rejected() {
  const circuit golden = make_golden_error_b();
  circuit trojan;
  trojan.define_pi("a");
  trojan.define_pi("c");
  trojan.define_gate("y", GType::XOR,
                     {trojan.node_index("a"), trojan.node_index("c")});
  trojan.add_output_name("y");
  trojan.finalize_outputs();

  const std::vector<int> features{trojan.node_index("c")};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, test_options());
  expect(result.status == RuleMiterStatus::invalid,
         "equal PI counts with different names are rejected");
}

void test_missing_po_name_rejected() {
  const circuit golden = make_golden_error_b();
  circuit trojan;
  trojan.define_pi("a");
  trojan.define_pi("b");
  trojan.define_gate("z", GType::XOR,
                     {trojan.node_index("a"), trojan.node_index("b")});
  trojan.add_output_name("z");
  trojan.finalize_outputs();

  const std::vector<int> features{trojan.node_index("b")};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, features, model, test_options());
  expect(result.status == RuleMiterStatus::invalid,
         "equal PO counts with different names are rejected");
}

void test_invalid_blocked_bits_rejected() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("b")};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  const std::unordered_set<std::string> blocked{"0x"};
  const RuleMiterResult result = check_rule_miter(
      golden, trojan, features, model, test_options(), &blocked);
  expect(result.status == RuleMiterStatus::invalid,
         "non-binary blocked PI string is rejected");

  const std::vector<int> mismatching_features{trojan.node_index("a")};
  const DecisionTreeModel mismatching_model = make_model({{{0, 1}}});
  // Lexicographic validation sees the real blocked FN 01 before malformed 0x.
  const std::unordered_set<std::string> witness_then_invalid{"01", "0x"};
  const RuleMiterResult preserved = check_rule_miter(
      golden, trojan, mismatching_features, mismatching_model,
      test_options(), &witness_then_invalid);
  expect(preserved.status == RuleMiterStatus::counterexamples,
         "validated blocked witness dominates a later invalid input");
  expect(preserved.false_negative.status == RuleMiterQueryStatus::sat &&
             preserved.false_negative.blocked_violations == 1,
         "later invalid input cannot erase blocked FN evidence");
}

void test_cyclic_circuit_rejected() {
  circuit golden;
  golden.define_pi("a");

  circuit trojan;
  trojan.define_pi("a");
  const int first = trojan.ensure_node("cycle_first");
  const int second = trojan.ensure_node("cycle_second");
  trojan.define_gate("cycle_first", GType::BUFF, {second});
  trojan.define_gate("cycle_second", GType::BUFF, {first});

  const DecisionTreeModel model;
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, {}, model, test_options());
  expect(result.status == RuleMiterStatus::invalid,
         "cyclic Trojan circuit is rejected before Z3 encoding");
  expect(!result.proved(), "cyclic circuit can never produce a proof");
}

void test_stale_eval_order_cycle_rejected() {
  circuit golden;
  golden.define_pi("a");
  golden.define_gate("out", GType::BUFF, {golden.node_index("a")});
  golden.add_output_name("out");
  golden.finalize_outputs();

  circuit trojan;
  trojan.define_pi("a");
  const int first = trojan.ensure_node("first");
  trojan.define_gate("first", GType::BUFF, {trojan.node_index("a")});
  trojan.define_gate("out", GType::BUFF, {first});
  trojan.add_output_name("out");
  trojan.finalize_outputs();

  // finalize_outputs() populated a valid eval-order cache.  Rewiring first
  // from PI a to downstream gate out creates first <-> out without changing
  // the gate count, so circuit::ensure_eval_order() alone does not rebuild.
  const int out = trojan.node_index("out");
  trojan.replace_gate_inputs(trojan.node_index("a"), out,
                             trojan.node_count());
  trojan.ensure_eval_order();

  const DecisionTreeModel model;
  const RuleMiterResult result =
      check_rule_miter(golden, trojan, {}, model, test_options());
  expect(result.status == RuleMiterStatus::invalid,
         "independent DAG validation catches a stale-cache cycle");
  expect(!result.proved(), "stale eval-order cycle can never produce a proof");
}

void test_basic_gate_encoding_crosscheck() {
  struct GatePair {
    GType golden_type;
    GType trojan_type;
    bool unary;
    const char* name;
  };
  const std::vector<GatePair> pairs{
      {GType::AND, GType::NAND, false, "AND/NAND"},
      {GType::OR, GType::NOR, false, "OR/NOR"},
      {GType::XOR, GType::XNOR, false, "XOR/XNOR"},
      {GType::NOT, GType::BUFF, true, "NOT/BUFF"}};

  for (const GatePair& pair : pairs) {
    circuit golden;
    golden.define_pi("a");
    golden.define_pi("b");
    std::vector<int> golden_inputs{golden.node_index("a")};
    if (!pair.unary) golden_inputs.push_back(golden.node_index("b"));
    golden.define_gate("y", pair.golden_type, golden_inputs);
    golden.add_output_name("y");
    golden.finalize_outputs();

    circuit trojan;
    trojan.define_pi("a");
    trojan.define_pi("b");
    std::vector<int> trojan_inputs{trojan.node_index("a")};
    if (!pair.unary) trojan_inputs.push_back(trojan.node_index("b"));
    trojan.define_gate("y", pair.trojan_type, trojan_inputs);
    trojan.add_output_name("y");
    trojan.finalize_outputs();

    // Each pair is complementary for every assignment, so E=TRUE.  An empty
    // term is also TRUE; proving equality cross-checks Z3 gate equations
    // against scalar circuit semantics for all eight gate kinds.
    const DecisionTreeModel true_model = make_model({{}});
    const RuleMiterResult result = check_rule_miter(
        golden, trojan, {}, true_model, test_options());
    expect(result.proved(),
           std::string("gate encoding agrees for ") + pair.name);
  }
}

void test_blocked_patterns_are_checked_but_not_repeated() {
  const circuit golden = make_golden_error_b();
  const circuit trojan = make_trojan_error_b();
  const std::vector<int> features{trojan.node_index("a")};
  const DecisionTreeModel model = make_model({{{0, 1}}});
  // Golden PI order is a,b.  01 is the sole FN for E=b, R=a.
  const std::unordered_set<std::string> blocked{"01"};
  const RuleMiterResult result = check_rule_miter(
      golden, trojan, features, model, test_options(), &blocked);
  expect(result.status == RuleMiterStatus::counterexamples,
         "a still-violating blocked pattern prevents a proof");
  expect(result.false_negative.blocked_violations == 1,
         "blocked FN is independently detected");
  expect(std::none_of(
             result.counterexamples.begin(), result.counterexamples.end(),
             [](const RuleMiterCounterexample& counterexample) {
               return pattern_bits(counterexample.pi_values) == "01";
             }),
         "blocked pattern is not returned again");

  const std::vector<int> exact_features{trojan.node_index("b")};
  const DecisionTreeModel exact_model = make_model({{{0, 1}}});
  const RuleMiterResult exact = check_rule_miter(
      golden, trojan, exact_features, exact_model, test_options(), &blocked);
  expect(exact.proved(),
         "a blocked assignment that scalar-checks clean does not weaken proof");
}

void test_output_scoped_exact_rule() {
  const auto nets = make_two_output_scoped_miter();
  const circuit& golden = nets.first;
  const circuit& trojan = nets.second;
  const std::vector<int> features{trojan.node_index("a"),
                                  trojan.node_index("b")};

  RuleMiterOptions y0_options = test_options();
  y0_options.error_po_positions = {0};
  const DecisionTreeModel y0_model = make_model({{{1, 1}}});
  const RuleMiterResult y0 = check_rule_miter(
      golden, trojan, features, y0_model, y0_options);
  expect(y0.proved(), "PO 0 scope proves E0=b equals R=b");

  RuleMiterOptions y1_options = test_options();
  y1_options.error_po_positions = {1};
  const DecisionTreeModel y1_model = make_model({{{0, 1}}});
  const RuleMiterResult y1 = check_rule_miter(
      golden, trojan, features, y1_model, y1_options);
  expect(y1.proved(), "PO 1 scope proves E1=a equals R=a");

  RuleMiterOptions both_options = test_options();
  both_options.error_po_positions = {0, 1};
  const DecisionTreeModel both_model =
      make_model({{{0, 1}}, {{1, 1}}});
  const RuleMiterResult both = check_rule_miter(
      golden, trojan, features, both_model, both_options);
  expect(both.proved(), "multi-PO scope proves E0 OR E1 equals a OR b");
}

void test_output_scope_changes_error_predicate() {
  const auto nets = make_two_output_scoped_miter();
  const circuit& golden = nets.first;
  const circuit& trojan = nets.second;
  const std::vector<int> features{trojan.node_index("a"),
                                  trojan.node_index("b")};
  const DecisionTreeModel model = make_model({{{1, 1}}});

  RuleMiterOptions y0_options = test_options();
  y0_options.error_po_positions = {0};
  const RuleMiterResult y0 = check_rule_miter(
      golden, trojan, features, model, y0_options);
  expect(y0.proved(), "R=b is exact when only PO 0 contributes to E");

  RuleMiterOptions y1_options = test_options();
  y1_options.error_po_positions = {1};
  const RuleMiterResult y1 = check_rule_miter(
      golden, trojan, features, model, y1_options);
  expect(y1.status == RuleMiterStatus::counterexamples,
         "the same R=b differs from PO 1's E1=a");
  expect(count_kind(y1, RuleMiterCounterexampleKind::false_negative) == 1,
         "PO 1 scope returns its false negative");
  expect(count_kind(y1, RuleMiterCounterexampleKind::false_positive) == 1,
         "PO 1 scope returns its false positive");
}

void test_output_scoped_directional_counterexamples() {
  const auto nets = make_two_output_scoped_miter();
  const circuit& golden = nets.first;
  const circuit& trojan = nets.second;
  const std::vector<int> features{trojan.node_index("a"),
                                  trojan.node_index("b")};
  RuleMiterOptions options = test_options();
  options.error_po_positions = {0};

  const DecisionTreeModel subset = make_model({{{0, 1}, {1, 1}}});
  const RuleMiterResult false_negative = check_rule_miter(
      golden, trojan, features, subset, options);
  expect(count_kind(false_negative,
                    RuleMiterCounterexampleKind::false_negative) == 1,
         "scoped subset rule returns one false negative");
  expect(count_kind(false_negative,
                    RuleMiterCounterexampleKind::false_positive) == 0,
         "scoped subset rule returns no false positive");

  const DecisionTreeModel superset =
      make_model({{{1, 1}}, {{0, 1}}});
  const RuleMiterResult false_positive = check_rule_miter(
      golden, trojan, features, superset, options);
  expect(count_kind(false_positive,
                    RuleMiterCounterexampleKind::false_negative) == 0,
         "scoped superset rule returns no false negative");
  expect(count_kind(false_positive,
                    RuleMiterCounterexampleKind::false_positive) == 1,
         "scoped superset rule returns one false positive");
}

void test_invalid_output_scope_rejected() {
  const auto nets = make_two_output_scoped_miter();
  const circuit& golden = nets.first;
  const circuit& trojan = nets.second;
  const std::vector<int> features{trojan.node_index("b")};
  const DecisionTreeModel model = make_model({{{0, 1}}});

  RuleMiterOptions out_of_range = test_options();
  out_of_range.error_po_positions = {2};
  const RuleMiterResult bad_position = check_rule_miter(
      golden, trojan, features, model, out_of_range);
  expect(bad_position.status == RuleMiterStatus::invalid,
         "out-of-range PO scope is invalid");
  expect(bad_position.reason.find("out of range") != std::string::npos,
         "out-of-range PO scope reports its cause");

  RuleMiterOptions duplicate = test_options();
  duplicate.error_po_positions = {0, 0};
  const RuleMiterResult repeated_position = check_rule_miter(
      golden, trojan, features, model, duplicate);
  expect(repeated_position.status == RuleMiterStatus::invalid,
         "duplicate PO scope is invalid");
  expect(repeated_position.reason.find("duplicate") != std::string::npos,
         "duplicate PO scope reports its cause");
}

}  // namespace

int main() {
  test_exact_rule();
  test_false_positive_only();
  test_false_negative_only();
  test_both_directions_and_alternation();
  test_empty_dnf_is_false();
  test_empty_term_is_true();
  test_batch_cap_and_determinism();
  test_zero_timeout_is_not_proof();
  test_witness_status_transition_priority();
  test_zero_counterexample_capacity_checks_both_sides();
  test_invalid_feature_rejected();
  test_invalid_literal_value_rejected();
  test_reordered_pi_and_po_names();
  test_reordered_pi_counterexample_values_use_golden_order();
  test_missing_pi_name_rejected();
  test_missing_po_name_rejected();
  test_invalid_blocked_bits_rejected();
  test_cyclic_circuit_rejected();
  test_stale_eval_order_cycle_rejected();
  test_basic_gate_encoding_crosscheck();
  test_blocked_patterns_are_checked_but_not_repeated();
  test_output_scoped_exact_rule();
  test_output_scope_changes_error_predicate();
  test_output_scoped_directional_counterexamples();
  test_invalid_output_scope_rejected();

  if (failures != 0) {
    std::cerr << failures << " rule-miter test(s) failed\n";
    return 1;
  }
  std::cout << "PASS: rule-miter tests\n";
  return 0;
}
