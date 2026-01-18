#pragma once

#include <cstddef>
#include <string>
#include <unordered_set>
#include <vector>

#include "../core/circuit.hpp"
#include "miner.hpp"

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
