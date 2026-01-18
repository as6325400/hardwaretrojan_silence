#pragma once

#include <vector>

#include "../core/circuit.hpp"
#include "miner.hpp"
#include "pattern_sampler.hpp"

void analyze_payload_nodes(const circuit& golden,
                           const circuit& trojan,
                           const PatternStats& stats,
                           const MiningResult& result,
                           std::vector<int>* fix_nodes_out);
