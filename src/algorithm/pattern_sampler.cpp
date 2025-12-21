#include "pattern_sampler.hpp"

#include <iostream>
#include <random>

#include <omp.h>

PatternStats sample_patterns(const circuit& golden,
                             const circuit& trojan,
                             std::size_t pattern_count,
                             std::uint32_t base_seed) {
  PatternStats stats;

  stats.gate_indices.reserve(trojan.node_count());
  for (std::size_t i = 0; i < trojan.node_count(); ++i) {
    const auto& c = trojan.get_cell(static_cast<int>(i));
    if (c.ctype == CType::GATE) {
      stats.gate_indices.push_back(static_cast<int>(i));
    }
  }

  std::vector<std::vector<int>> trigger_patterns;

  const int thread_count = omp_get_max_threads();
  std::vector<std::vector<std::uint64_t>> ones_total_thread(
      thread_count, std::vector<std::uint64_t>(stats.gate_indices.size(), 0));
  std::vector<std::vector<std::uint64_t>> ones_trigger_thread(
      thread_count, std::vector<std::uint64_t>(stats.gate_indices.size(), 0));
  std::vector<std::vector<std::uint64_t>> ones_notrigger_thread(
      thread_count, std::vector<std::uint64_t>(stats.gate_indices.size(), 0));
  std::vector<std::uint64_t> total_count_thread(thread_count, 0);
  std::vector<std::uint64_t> trigger_count_thread(thread_count, 0);
  std::vector<std::uint64_t> notrigger_count_thread(thread_count, 0);

  std::size_t mismatch_patterns = 0;

#pragma omp parallel reduction(+:mismatch_patterns)
{
  const int tid = omp_get_thread_num();
  std::mt19937 rng(base_seed + static_cast<std::uint32_t>(tid));
  std::uniform_int_distribution<int> dist(0, 1);
  circuit golden_local = golden;
  circuit trojan_local = trojan;

  #pragma omp for schedule(static)
  for (std::size_t p = 0; p < pattern_count; ++p) {
    std::vector<int> pi_values;
    pi_values.reserve(golden_local.pi_count());
    for (std::size_t i = 0; i < golden_local.pi_count(); ++i) {
      pi_values.push_back(dist(rng));
    }

    std::vector<int> golden_outputs;
    std::vector<int> trojan_outputs;
    try {
      golden_outputs = golden_local.simulate(pi_values);
      trojan_outputs = trojan_local.simulate(pi_values);
    } catch (const std::exception& e) {
      #pragma omp critical
      {
        std::cerr << "Simulation error: " << e.what() << "\n";
      }
      continue;
    }

    std::size_t diff = 0;
    for (std::size_t i = 0; i < golden_outputs.size(); ++i) {
      if (golden_outputs[i] != trojan_outputs[i]) {
        ++diff;
      }
    }

    const bool triggered = diff > 0;
    total_count_thread[tid]++;
    if (triggered) {
      trigger_count_thread[tid]++;
    } else {
      notrigger_count_thread[tid]++;
    }

    for (std::size_t g = 0; g < stats.gate_indices.size(); ++g) {
      const int idx = stats.gate_indices[g];
      const int val = trojan_local.get_cell(idx).val;
      const std::uint64_t one = (val == 1) ? 1 : 0;
      ones_total_thread[tid][g] += one;
      if (triggered) {
        ones_trigger_thread[tid][g] += one;
      } else {
        ones_notrigger_thread[tid][g] += one;
      }
    }

    if (triggered) {
      #pragma omp critical
      {
        trigger_patterns.push_back(pi_values);
      }
      ++mismatch_patterns;
    }
  }
}

  stats.ones_total.assign(stats.gate_indices.size(), 0);
  stats.ones_trigger.assign(stats.gate_indices.size(), 0);
  stats.ones_notrigger.assign(stats.gate_indices.size(), 0);

  for (int t = 0; t < thread_count; ++t) {
    stats.total_patterns += total_count_thread[t];
    stats.trigger_patterns_total += trigger_count_thread[t];
    stats.notrigger_patterns_total += notrigger_count_thread[t];
    for (std::size_t g = 0; g < stats.gate_indices.size(); ++g) {
      stats.ones_total[g] += ones_total_thread[t][g];
      stats.ones_trigger[g] += ones_trigger_thread[t][g];
      stats.ones_notrigger[g] += ones_notrigger_thread[t][g];
    }
  }

  stats.trigger_patterns = std::move(trigger_patterns);
  stats.mismatch_patterns = mismatch_patterns;

  return stats;
}

double compute_trojan_rate(const PatternStats& stats) {
  if (stats.total_patterns == 0) {
    return 0.0;
  }
  return static_cast<double>(stats.trigger_patterns_total) /
         static_cast<double>(stats.total_patterns);
}
