#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "../core/circuit.hpp"

struct PatternStats {
  std::vector<std::vector<int>> trigger_patterns;
  std::vector<int> gate_indices;
  std::vector<std::uint64_t> ones_total;
  std::vector<std::uint64_t> ones_trigger;
  std::vector<std::uint64_t> ones_notrigger;
  std::uint64_t total_patterns = 0;
  std::uint64_t trigger_patterns_total = 0;
  std::uint64_t notrigger_patterns_total = 0;
  std::size_t mismatch_patterns = 0;
};

PatternStats sample_patterns(const circuit& golden,
                             const circuit& trojan,
                             std::size_t pattern_count); // Simulate random patterns and collect gate statistics.
double compute_trojan_rate(const PatternStats& stats); // Compute trigger rate from collected stats.
