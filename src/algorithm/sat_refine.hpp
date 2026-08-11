#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "../core/circuit.hpp"
#include "miner.hpp"

enum class RuleMiterCounterexampleKind {
  false_negative,
  false_positive
};

// `sat` means at least one counterexample of this class exists.  `unsat`
// means the complete (possibly externally blocked, but independently checked)
// search space contains none.  Timeout and unknown are never proofs.
enum class RuleMiterQueryStatus {
  not_checked,
  sat,
  unsat,
  timeout,
  unknown
};

enum class RuleMiterStatus {
  proved,
  counterexamples,
  timeout,
  unknown,
  invalid
};

struct RuleMiterCounterexample {
  // Values are always returned in golden.pi_indices() order.
  std::vector<int> pi_values;
  RuleMiterCounterexampleKind kind =
      RuleMiterCounterexampleKind::false_negative;
};

struct RuleMiterOptions {
  // The implementation hard-caps this at five so callers cannot
  // accidentally turn a refinement check into unbounded enumeration.
  std::size_t max_counterexamples = 5;
  // One shared *soft* wall-clock budget covers encoding, both directional
  // queries, model extraction, and scalar defense-in-depth validation.  This
  // is an in-process deadline, not a process-level hard kill; a single
  // allocation or library call can return slightly after the requested time.
  std::uint64_t timeout_ms = 10000;
};

struct RuleMiterSideResult {
  RuleMiterQueryStatus status = RuleMiterQueryStatus::not_checked;
  std::size_t models_found = 0;
  std::size_t counterexamples_returned = 0;
  std::size_t blocked_violations = 0;
  bool exhausted = false;
  std::string reason;
};

struct RuleMiterResult {
  RuleMiterStatus status = RuleMiterStatus::invalid;
  RuleMiterSideResult false_negative;
  RuleMiterSideResult false_positive;
  std::vector<RuleMiterCounterexample> counterexamples;
  std::size_t solver_checks = 0;
  std::size_t requested_counterexample_limit = 0;
  std::size_t effective_counterexample_limit = 0;
  double encode_ms = 0.0;
  double solver_ms = 0.0;
  double validation_ms = 0.0;
  double total_ms = 0.0;
  std::string reason;

  bool proved() const { return status == RuleMiterStatus::proved; }
};

// Pure state helpers used by the checker and by deterministic regression
// tests.  Once current.models_found is non-zero, a later timeout/unknown event
// cannot erase the established SAT status.  The reason records that the
// remaining search was incomplete.  A proof still requires both sides UNSAT.
RuleMiterSideResult transition_rule_miter_side(
    const RuleMiterSideResult& current,
    RuleMiterQueryStatus observed_status,
    const std::string& reason = std::string{});

RuleMiterStatus aggregate_rule_miter_status(
    const RuleMiterResult& result,
    RuleMiterStatus fallback_status);

// Formally compare the mined DNF R against the circuit-derived error
// predicate E = OR(golden_PO != trojan_PO).  Both E && !R (false negative)
// and !E && R (false positive) are queried, alternating classes while
// collecting at most five total PI patterns.
//
// blocked_pi_bits is optional.  Each key must contain exactly one '0'/'1'
// per golden PI, in golden PI order.  Blocked assignments are independently
// simulated first: assignments that still violate E == R keep the result
// non-proved even though they are not returned again.
RuleMiterResult check_rule_miter(
    const circuit& golden,
    const circuit& trojan,
    const std::vector<int>& feature_nodes,
    const DecisionTreeModel& model,
    const RuleMiterOptions& options = RuleMiterOptions{},
    const std::unordered_set<std::string>* blocked_pi_bits = nullptr);

const char* rule_miter_query_status_name(RuleMiterQueryStatus status);
const char* rule_miter_status_name(RuleMiterStatus status);

bool collect_rule_counterexamples(
    const circuit& golden,
    const circuit& trojan,
    const MiningResult& result,
    std::size_t round_index,
    const std::unordered_set<std::string>& groundtruth_bits,
    std::unordered_set<std::string>* seen_bits,
    std::size_t max_models,
    std::size_t max_counterexamples,
    std::vector<std::vector<int>>* counterexamples,
    std::string* error);
