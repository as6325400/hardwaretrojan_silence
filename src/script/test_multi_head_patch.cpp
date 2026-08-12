#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "../algorithm/multi_head_patch.hpp"
#include "../algorithm/sat_refine.hpp"
#include "../io/bench_writer.hpp"

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

circuit make_base() {
  circuit net;
  net.define_pi("a");
  net.define_pi("b");
  net.define_pi("c");
  const int a = net.node_index("a");
  const int b = net.node_index("b");
  const int c = net.node_index("c");
  net.define_gate("bc", GType::AND, {b, c});
  net.define_gate("y0", GType::XOR, {a, b});
  net.define_gate("y1", GType::XOR, {a, c});
  net.define_gate("y2", GType::XOR, {a, net.node_index("bc")});
  net.define_gate("keep", GType::OR, {b, c});
  net.add_output_name("y0");
  net.add_output_name("y1");
  net.add_output_name("y2");
  net.add_output_name("keep");
  net.finalize_outputs();
  return net;
}

circuit make_golden() {
  circuit net;
  net.define_pi("a");
  net.define_pi("b");
  net.define_pi("c");
  const int a = net.node_index("a");
  const int b = net.node_index("b");
  const int c = net.node_index("c");
  net.define_gate("y0", GType::BUFF, {a});
  net.define_gate("y1", GType::BUFF, {a});
  net.define_gate("y2", GType::BUFF, {a});
  net.define_gate("keep", GType::OR, {b, c});
  net.add_output_name("y0");
  net.add_output_name("y1");
  net.add_output_name("y2");
  net.add_output_name("keep");
  net.finalize_outputs();
  return net;
}

std::vector<MultiHeadPatchHead> all_heads(const circuit& base) {
  return {
      MultiHeadPatchHead{0, {base.node_index("b")},
                         make_model({{{0, 1}}})},
      MultiHeadPatchHead{1, {base.node_index("c")},
                         make_model({{{0, 1}}})},
      MultiHeadPatchHead{2,
                         {base.node_index("b"), base.node_index("c")},
                         make_model({{{0, 1}, {1, 1}}})},
  };
}

bool scalar_equivalent(const circuit& lhs, const circuit& rhs) {
  if (lhs.pi_count() != rhs.pi_count() || lhs.po_count() != rhs.po_count()) {
    return false;
  }
  const std::size_t combinations = std::size_t{1} << lhs.pi_count();
  for (std::size_t bits = 0; bits < combinations; ++bits) {
    std::vector<int> pattern(lhs.pi_count(), 0);
    for (std::size_t i = 0; i < pattern.size(); ++i) {
      pattern[i] = static_cast<int>((bits >> i) & std::size_t{1});
    }
    circuit lhs_eval = lhs;
    circuit rhs_eval = rhs;
    if (lhs_eval.simulate(pattern) != rhs_eval.simulate(pattern)) return false;
  }
  return true;
}

std::size_t po_position_by_name(const circuit& net,
                                const std::string& name) {
  for (std::size_t pos = 0; pos < net.po_count(); ++pos) {
    if (net.node_name(net.po_indices()[pos]) == name) return pos;
  }
  return net.po_count();
}

bool name_aligned_equivalent(const circuit& lhs, const circuit& rhs) {
  if (lhs.pi_count() != rhs.pi_count() || lhs.po_count() != rhs.po_count()) {
    return false;
  }
  std::vector<std::size_t> rhs_pi_for_lhs;
  rhs_pi_for_lhs.reserve(lhs.pi_count());
  for (int lhs_pi : lhs.pi_indices()) {
    const std::string& name = lhs.node_name(lhs_pi);
    std::size_t rhs_pos = rhs.pi_count();
    for (std::size_t pos = 0; pos < rhs.pi_count(); ++pos) {
      if (rhs.node_name(rhs.pi_indices()[pos]) == name) {
        rhs_pos = pos;
        break;
      }
    }
    if (rhs_pos == rhs.pi_count()) return false;
    rhs_pi_for_lhs.push_back(rhs_pos);
  }

  std::vector<std::size_t> rhs_po_for_lhs;
  rhs_po_for_lhs.reserve(lhs.po_count());
  for (int lhs_po : lhs.po_indices()) {
    const std::size_t rhs_pos =
        po_position_by_name(rhs, lhs.node_name(lhs_po));
    if (rhs_pos == rhs.po_count()) return false;
    rhs_po_for_lhs.push_back(rhs_pos);
  }

  const std::size_t combinations = std::size_t{1} << lhs.pi_count();
  for (std::size_t bits = 0; bits < combinations; ++bits) {
    std::vector<int> lhs_pattern(lhs.pi_count(), 0);
    std::vector<int> rhs_pattern(rhs.pi_count(), 0);
    for (std::size_t pos = 0; pos < lhs_pattern.size(); ++pos) {
      lhs_pattern[pos] =
          static_cast<int>((bits >> pos) & std::size_t{1});
      rhs_pattern[rhs_pi_for_lhs[pos]] = lhs_pattern[pos];
    }
    circuit lhs_eval = lhs;
    circuit rhs_eval = rhs;
    const std::vector<int> lhs_outputs = lhs_eval.simulate(lhs_pattern);
    const std::vector<int> rhs_outputs = rhs_eval.simulate(rhs_pattern);
    for (std::size_t pos = 0; pos < lhs_outputs.size(); ++pos) {
      if (lhs_outputs[pos] != rhs_outputs[rhs_po_for_lhs[pos]]) return false;
    }
  }
  return true;
}

circuit make_reordered_golden() {
  circuit net;
  net.define_pi("a");
  net.define_pi("b");
  net.define_pi("c");
  net.define_pi("d");
  net.define_gate("alpha", GType::BUFF, {net.node_index("a")});
  net.define_gate("beta", GType::BUFF, {net.node_index("b")});
  net.add_output_name("alpha");
  net.add_output_name("beta");
  net.finalize_outputs();
  return net;
}

circuit make_reordered_trojan() {
  circuit net;
  net.define_pi("a");
  net.define_pi("b");
  net.define_pi("c");
  net.define_pi("d");
  net.define_gate("alpha", GType::XOR,
                  {net.node_index("a"), net.node_index("c")});
  net.define_gate("beta", GType::XOR,
                  {net.node_index("b"), net.node_index("d")});
  // The implementation deliberately exposes the same names in the opposite
  // order from the Golden circuit.
  net.add_output_name("beta");
  net.add_output_name("alpha");
  net.finalize_outputs();
  return net;
}

void expect_output_names(const circuit& net) {
  const std::vector<std::string> expected{"y0", "y1", "y2", "keep"};
  expect(net.po_count() == expected.size(), "PO count remains unchanged");
  if (net.po_count() != expected.size()) return;
  for (std::size_t i = 0; i < expected.size(); ++i) {
    expect(net.node_name(net.po_indices()[i]) == expected[i],
           "PO interface name " + expected[i] + " is preserved");
  }
}

void test_head_counts_and_truth_table() {
  const circuit base = make_base();
  const std::vector<MultiHeadPatchHead> heads = all_heads(base);

  for (std::size_t count = 1; count <= heads.size(); ++count) {
    circuit patched;
    MultiHeadPatchMetrics metrics;
    std::string error;
    expect(compose_multi_head_po_patch(
               base,
               std::vector<MultiHeadPatchHead>(heads.begin(),
                                               heads.begin() + count),
               &patched, &metrics, &error),
           std::to_string(count) + "-head patch composes: " + error);
    if (!error.empty()) continue;
    expect(metrics.head_count == count, "metrics report head count");
    expect(metrics.output_xor_nodes_added == count,
           "one output XOR is added per head");
    expect(metrics.predicate_nodes_added >= count,
           "each head materializes a frozen predicate output");
    expect(metrics.area_delta ==
               static_cast<long long>(metrics.predicate_nodes_added + count),
           "area delta accounts for predicates and PO XORs");
    expect_output_names(patched);

    for (int a = 0; a <= 1; ++a) {
      for (int b = 0; b <= 1; ++b) {
        for (int c = 0; c <= 1; ++c) {
          circuit eval = patched;
          const std::vector<int> out = eval.simulate({a, b, c});
          expect(out.size() == 4, "patched truth table has four outputs");
          if (out.size() != 4) continue;
          const int expected0 = count >= 1 ? a : (a ^ b);
          const int expected1 = count >= 2 ? a : (a ^ c);
          const int expected2 = count >= 3 ? a : (a ^ (b & c));
          expect(out[0] == expected0, "head 0 toggles only when b is active");
          expect(out[1] == expected1, "head 1 toggles only when c is active");
          expect(out[2] == expected2,
                 "head 2 handles the simultaneous b-and-c activation");
          expect(out[3] == (b | c), "unpatched PO remains unchanged");
        }
      }
    }
  }
}

void test_invalid_heads_are_transactional() {
  const circuit base = make_base();
  std::vector<MultiHeadPatchHead> heads = all_heads(base);
  circuit output = base;
  MultiHeadPatchMetrics metrics;
  metrics.head_count = 99;
  std::string error;

  std::vector<MultiHeadPatchHead> duplicate{heads[0], heads[0]};
  expect(!compose_multi_head_po_patch(base, duplicate, &output, &metrics,
                                      &error),
         "duplicate PO heads are rejected");
  expect(error.find("duplicate") != std::string::npos,
         "duplicate rejection is diagnosed");
  expect(scalar_equivalent(output, base),
         "failed duplicate composition leaves output untouched");
  expect(metrics.head_count == 99,
         "failed duplicate composition leaves metrics untouched");

  error.clear();
  heads[0].base_po_position = base.po_count();
  expect(!compose_multi_head_po_patch(base, {heads[0]}, &output, nullptr,
                                      &error),
         "out-of-range PO head is rejected");
  expect(error.find("out of range") != std::string::npos,
         "out-of-range rejection is diagnosed");
}

std::string abc_binary() {
  const char* configured = std::getenv("ABC_BIN");
  if (configured && configured[0] != '\0' && access(configured, X_OK) == 0) {
    return configured;
  }
  for (const char* candidate : {"abc", "../abc"}) {
    if (access(candidate, X_OK) == 0) return candidate;
  }
  return {};
}

std::string shell_quote(const std::string& value) {
  std::string quoted = "'";
  for (char ch : value) {
    if (ch == '\'') quoted += "'\\''";
    else quoted.push_back(ch);
  }
  quoted.push_back('\'');
  return quoted;
}

void test_reordered_po_scope_and_patch_alignment() {
  const circuit golden = make_reordered_golden();
  const circuit trojan = make_reordered_trojan();
  const std::size_t golden_alpha = po_position_by_name(golden, "alpha");
  const std::size_t golden_beta = po_position_by_name(golden, "beta");
  const std::size_t trojan_alpha = po_position_by_name(trojan, "alpha");
  const std::size_t trojan_beta = po_position_by_name(trojan, "beta");
  expect(golden_alpha == 0 && golden_beta == 1 && trojan_alpha == 1 &&
             trojan_beta == 0,
         "regression fixture reverses Golden and Trojan PO positions");

  const DecisionTreeModel alpha_model = make_model({{{0, 1}}});
  const DecisionTreeModel beta_model = make_model({{{0, 1}}});
  const std::vector<int> alpha_features{trojan.node_index("c")};
  const std::vector<int> beta_features{trojan.node_index("d")};

  RuleMiterOptions alpha_options;
  alpha_options.max_counterexamples = 5;
  alpha_options.timeout_ms = 5000;
  alpha_options.error_po_positions = {golden_alpha};
  const RuleMiterResult alpha_miter = check_rule_miter(
      golden, trojan, alpha_features, alpha_model, alpha_options);
  expect(alpha_miter.proved(),
         "alpha predicate is proved using its Golden PO scope");

  RuleMiterOptions beta_options = alpha_options;
  beta_options.error_po_positions = {golden_beta};
  const RuleMiterResult beta_miter = check_rule_miter(
      golden, trojan, beta_features, beta_model, beta_options);
  expect(beta_miter.proved(),
         "beta predicate is proved using its Golden PO scope");

  RuleMiterOptions wrong_scope = alpha_options;
  wrong_scope.error_po_positions = {trojan_alpha};
  const RuleMiterResult wrong_scope_miter = check_rule_miter(
      golden, trojan, alpha_features, alpha_model, wrong_scope);
  expect(!wrong_scope_miter.proved(),
         "a Trojan PO position cannot be reused as a Golden miter scope");

  circuit patched;
  std::string error;
  const std::vector<MultiHeadPatchHead> aligned_heads{
      MultiHeadPatchHead{trojan_alpha, alpha_features, alpha_model},
      MultiHeadPatchHead{trojan_beta, beta_features, beta_model},
  };
  expect(compose_multi_head_po_patch(trojan, aligned_heads, &patched,
                                     nullptr, &error),
         "name-aligned reversed-order patch composes: " + error);
  expect(name_aligned_equivalent(golden, patched),
         "exhaustive comparison proves the name-aligned patch");

  circuit position_bug_patch;
  error.clear();
  const std::vector<MultiHeadPatchHead> direct_position_heads{
      MultiHeadPatchHead{golden_alpha, alpha_features, alpha_model},
      MultiHeadPatchHead{golden_beta, beta_features, beta_model},
  };
  expect(compose_multi_head_po_patch(trojan, direct_position_heads,
                                     &position_bug_patch, nullptr, &error),
         "the historical direct-position patch remains structurally valid");
  expect(!name_aligned_equivalent(golden, position_bug_patch),
         "exhaustive comparison detects Golden positions applied directly "
         "to reversed Trojan outputs");

  const std::string abc = abc_binary();
  expect(!abc.empty(), "ABC binary is available for PO alignment CEC");
  if (abc.empty()) return;

  // ABC compares outputs positionally.  Canonicalize only the Golden PO
  // vector to the already name-aligned patched interface before invoking CEC.
  circuit canonical_golden = golden;
  for (std::size_t pos = 0; pos < patched.po_count(); ++pos) {
    const std::string& name = patched.node_name(patched.po_indices()[pos]);
    canonical_golden.set_po_index(pos, canonical_golden.node_index(name));
  }

  const std::string prefix =
      "/tmp/test_multi_head_po_alignment_" + std::to_string(getpid());
  const std::string golden_path = prefix + "_golden.bench";
  const std::string patched_path = prefix + "_patched.bench";
  const std::string log_path = prefix + "_cec.log";
  expect(bench_io::write_bench_file(golden_path, canonical_golden, &error),
         "canonical Golden PO-alignment bench is written: " + error);
  error.clear();
  expect(bench_io::write_bench_file(patched_path, patched, &error),
         "reversed-order patched bench is written: " + error);

  const std::string script = "cec " + golden_path + " " + patched_path;
  const std::string command = shell_quote(abc) + " -c " +
                              shell_quote(script) + " > " +
                              shell_quote(log_path) + " 2>&1";
  const int rc = std::system(command.c_str());
  std::ifstream log(log_path);
  const std::string output((std::istreambuf_iterator<char>(log)),
                           std::istreambuf_iterator<char>());
  expect(rc == 0, "PO-alignment ABC CEC exits successfully");
  expect(output.find("Networks are equivalent") != std::string::npos,
         "ABC CEC proves the reordered-PO multi-head patch equivalent");

  (void)std::remove(golden_path.c_str());
  (void)std::remove(patched_path.c_str());
  (void)std::remove(log_path.c_str());
}

void test_scalar_and_abc_cec() {
  const circuit base = make_base();
  circuit patched;
  std::string error;
  expect(compose_multi_head_po_patch(base, all_heads(base), &patched, nullptr,
                                     &error),
         "three-head exact patch composes for equivalence test: " + error);
  const circuit golden = make_golden();
  expect(scalar_equivalent(golden, patched),
         "exhaustive scalar comparison proves the multi-head patch");

  const std::string abc = abc_binary();
  expect(!abc.empty(), "ABC binary is available for exact CEC regression");
  if (abc.empty()) return;

  const std::string prefix =
      "/tmp/test_multi_head_patch_" + std::to_string(getpid());
  const std::string golden_path = prefix + "_golden.bench";
  const std::string patched_path = prefix + "_patched.bench";
  const std::string log_path = prefix + "_cec.log";
  circuit golden_write = golden;
  circuit patched_write = patched;
  expect(bench_io::write_bench_file(golden_path, golden_write, &error),
         "golden CEC bench is written: " + error);
  error.clear();
  expect(bench_io::write_bench_file(patched_path, patched_write, &error),
         "patched CEC bench is written: " + error);

  const std::string script = "cec " + golden_path + " " + patched_path;
  const std::string command = shell_quote(abc) + " -c " +
                              shell_quote(script) + " > " +
                              shell_quote(log_path) + " 2>&1";
  const int rc = std::system(command.c_str());
  std::ifstream log(log_path);
  const std::string output((std::istreambuf_iterator<char>(log)),
                           std::istreambuf_iterator<char>());
  expect(rc == 0, "ABC CEC exits successfully");
  expect(output.find("Networks are equivalent") != std::string::npos,
         "ABC CEC proves the multi-head patch equivalent");

  (void)std::remove(golden_path.c_str());
  (void)std::remove(patched_path.c_str());
  (void)std::remove(log_path.c_str());
}

}  // namespace

int main() {
  test_head_counts_and_truth_table();
  test_invalid_heads_are_transactional();
  test_reordered_po_scope_and_patch_alignment();
  test_scalar_and_abc_cec();
  if (failures != 0) {
    std::cerr << failures << " multi-head patch test(s) failed\n";
    return 1;
  }
  std::cout << "multi_head_patch_tests PASS\n";
  return 0;
}
