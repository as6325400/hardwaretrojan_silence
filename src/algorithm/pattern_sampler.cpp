#include "pattern_sampler.hpp"

#include <algorithm>
#include <iostream>
#include <random>

#include <omp.h>

#include "../core/packed_circuit.hpp"

namespace {

std::uint64_t popcount_ull(packed_circuit::word_t value) {
  return static_cast<std::uint64_t>(__builtin_popcountll(value));
}

}  // namespace

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

  const std::size_t block_count =
      (pattern_count + packed_circuit::kWordBits - 1) /
      packed_circuit::kWordBits;

#pragma omp parallel reduction(+:mismatch_patterns)
{
  const int tid = omp_get_thread_num();
  std::mt19937 rng(base_seed + static_cast<std::uint32_t>(tid));
  std::uniform_int_distribution<int> dist(0, 1);
  circuit golden_local = golden;
  circuit trojan_local = trojan;
  packed_circuit golden_packed(golden_local);
  packed_circuit trojan_packed(trojan_local);

  #pragma omp for schedule(static)
  for (std::size_t block = 0; block < block_count; ++block) {
    const std::size_t start = block * packed_circuit::kWordBits;
    const std::size_t remaining =
        (pattern_count > start) ? (pattern_count - start) : 0;
    const std::size_t block_size =
        std::min(remaining, packed_circuit::kWordBits);
    if (block_size == 0) {
      continue;
    }

    std::vector<std::vector<int>> patterns;
    patterns.reserve(block_size);
    for (std::size_t p = 0; p < block_size; ++p) {
      std::vector<int> pi_values;
      pi_values.reserve(golden_local.pi_count());
      for (std::size_t i = 0; i < golden_local.pi_count(); ++i) {
        pi_values.push_back(dist(rng));
      }
      patterns.push_back(std::move(pi_values));
    }

    try {
      golden_packed.simulate(patterns);
      trojan_packed.simulate(patterns);
    } catch (const std::exception& e) {
      #pragma omp critical
      {
        std::cerr << "Simulation error: " << e.what() << "\n";
      }
      continue;
    }

    const packed_circuit::word_t pattern_mask =
        packed_circuit::mask_for_count(block_size);
    packed_circuit::word_t diff_mask = 0;
    for (std::size_t i = 0; i < trojan_local.po_count(); ++i) {
      diff_mask |= (golden_packed.po_bits(i) ^ trojan_packed.po_bits(i));
    }
    diff_mask &= pattern_mask;

    const std::uint64_t triggered_count = popcount_ull(diff_mask);
    mismatch_patterns += triggered_count;
    total_count_thread[tid] += static_cast<std::uint64_t>(block_size);
    trigger_count_thread[tid] += triggered_count;
    notrigger_count_thread[tid] +=
        static_cast<std::uint64_t>(block_size) - triggered_count;

    const packed_circuit::word_t notrigger_mask =
        pattern_mask & ~diff_mask;

    for (std::size_t g = 0; g < stats.gate_indices.size(); ++g) {
      const int idx = stats.gate_indices[g];
      const packed_circuit::word_t bits =
          trojan_packed.node_bits(idx) & pattern_mask;
      ones_total_thread[tid][g] += popcount_ull(bits);
      ones_trigger_thread[tid][g] += popcount_ull(bits & diff_mask);
      ones_notrigger_thread[tid][g] += popcount_ull(bits & notrigger_mask);
    }

    if (diff_mask != 0) {
      std::vector<std::vector<int>> local_triggered;
      local_triggered.reserve(triggered_count);
      for (std::size_t bit = 0; bit < block_size; ++bit) {
        if (diff_mask & (packed_circuit::word_t(1) << bit)) {
          local_triggered.push_back(patterns[bit]);
        }
      }
      #pragma omp critical
      {
        trigger_patterns.insert(trigger_patterns.end(),
                                local_triggered.begin(),
                                local_triggered.end());
      }
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
