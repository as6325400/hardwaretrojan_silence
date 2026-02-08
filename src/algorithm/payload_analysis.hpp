#pragma once

#include <vector>

#include "../core/circuit.hpp"
#include "miner.hpp"
#include "pattern_sampler.hpp"

void analyze_payload_nodes(const circuit& golden,
                           const circuit& trojan,
                           const PatternStats& stats,
                           const MiningResult& result,
                           int rule_match_node_idx,
                           std::vector<int>* fix_nodes_out);
