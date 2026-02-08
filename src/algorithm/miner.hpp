#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "../core/circuit.hpp"
#include "decision_tree.hpp"

struct MiningOptions {
  std::size_t max_depth = 10;
  std::size_t neg_ratio = 50;
  std::size_t eval_count = 1000000;
  std::size_t mine_rounds = 15;
  std::size_t mine_max = 5000;
  bool include_pi = false;
  bool force_split = false;
  bool strict_retry = true;
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
};

struct NegSampleTrace {
  std::uint32_t seed = 1337;
  std::vector<PackedFeatureMatrix::word_t> masks;
  std::vector<std::uint8_t> sizes;
};

bool run_mining(const circuit& golden,
                const circuit& trojan,
                const std::vector<std::vector<int>>& trigger_patterns,
                const std::vector<int>& candidate_gate_indices,
                const MiningOptions& options,
                double target_rate,
                const std::vector<std::vector<int>>* extra_neg_patterns,
                NegSampleTrace* neg_trace,
                MiningResult* result,
                std::string* error); // Train decision tree with hard-negative mining.
