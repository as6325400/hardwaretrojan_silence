#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "../core/circuit.hpp"
#include "decision_tree.hpp"
#include "rule_optimizer.hpp"
#include "virtual_node.hpp"

enum class MiningRuleOptimizer {
  none,
  z3_pb,
  milp_cover
};

struct MiningOptions {
  std::size_t max_depth = 10;
  std::size_t neg_ratio = 50;
  std::size_t eval_count = 1000000;
  std::size_t mine_rounds = 15;
  std::size_t mine_max = 5000;
  bool include_pi = false;
  bool force_split = false;
  bool strict_retry = true;
  MiningRuleOptimizer rule_optimizer = MiningRuleOptimizer::none;
  RuleOptimizerOptions rule_optimizer_options;
};

struct MiningResult {
  std::vector<int> feature_nodes;
  DecisionTreeModel model;
  std::size_t data_pos = 0;
  std::size_t data_neg = 0;
  std::size_t train_pos = 0;
  std::size_t train_neg = 0;
  std::size_t train_false_pos = 0;
  std::size_t train_false_neg = 0;
  std::size_t eval_checked = 0;
  std::size_t eval_false_pos = 0;
  std::size_t hard_added = 0;
  std::size_t rounds_used = 0;
  // Completed work counters for machine-readable rule-synthesis telemetry.
  std::size_t dt_builds = 0;
  std::size_t strict_dt_builds = 0;
  std::size_t training_data_builds = 0;
  RuleOptimizerStats rule_optimizer_stats;
  std::size_t rule_optimizer_calls = 0;
  std::size_t rule_optimizer_accepted = 0;
  std::size_t rule_optimizer_checks = 0;
  std::size_t rule_optimizer_counterexamples = 0;
  double rule_optimizer_solver_ms = 0.0;
};

struct NegSampleTrace {
  std::uint32_t seed = 1337;
  std::vector<PackedFeatureMatrix::word_t> masks;
  std::vector<std::uint8_t> sizes;
};

// Train decision tree with hard-negative mining.
// virtual_defs: optional virtual node definitions.  When provided, virtual
// features are computed on-the-fly from simulation results (the circuit is
// NOT modified).  Virtual features get feature indices starting at
// len(candidate_gate_indices) + PIs.
bool run_mining(const circuit& golden,
                const circuit& trojan,
                const std::vector<std::vector<int>>& trigger_patterns,
                const std::vector<int>& candidate_gate_indices,
                const MiningOptions& options,
                double target_rate,
                const std::vector<std::vector<int>>* extra_neg_patterns,
                NegSampleTrace* neg_trace,
                MiningResult* result,
                std::string* error,
                const std::vector<VirtualNodeDef>* virtual_defs = nullptr);
