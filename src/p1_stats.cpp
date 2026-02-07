#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "algorithm/pattern_sampler.hpp"
#include "core/circuit_compare.hpp"
#include "core/packed_circuit.hpp"
#include "io/bench_parser.hpp"
#include "io/parallel_collect_log.hpp"

namespace {

std::uint64_t popcount_ull(packed_circuit::word_t value) {
  return static_cast<std::uint64_t>(__builtin_popcountll(value));
}

packed_circuit::word_t take_first_bits(packed_circuit::word_t mask,
                                       std::size_t count) {
  packed_circuit::word_t out = 0;
  while (mask && count > 0) {
    const packed_circuit::word_t lsb = mask & (~mask + 1ULL);
    out |= lsb;
    mask &= (mask - 1);
    count -= 1;
  }
  return out;
}

bool build_stats_from_groundtruth(const circuit& golden,
                                  const circuit& trojan,
                                  const std::string& log_path,
                                  std::size_t neg_ratio,
                                  PatternStats* stats,
                                  std::string* error) {
  if (error) {
    error->clear();
  }
  if (!stats) {
    if (error) {
      *error = "Stats output pointer is null";
    }
    return false;
  }

  *stats = PatternStats{};
  ParallelCollectLog log(log_path);

  const auto& log_pi_order = log.pi_order();
  if (log_pi_order.empty()) {
    if (error) {
      *error = "pi_order not available in groundtruth log";
    }
    return false;
  }

  const auto& pi_indices = trojan.pi_indices();
  std::unordered_map<std::string, std::size_t> pi_name_to_pos;
  pi_name_to_pos.reserve(pi_indices.size());
  for (std::size_t pos = 0; pos < pi_indices.size(); ++pos) {
    pi_name_to_pos[trojan.node_name(pi_indices[pos])] = pos;
  }

  std::vector<std::size_t> log_to_circuit;
  log_to_circuit.reserve(log_pi_order.size());
  std::vector<int> seen_pos(pi_indices.size(), 0);
  for (const auto& name : log_pi_order) {
    auto it = pi_name_to_pos.find(name);
    if (it == pi_name_to_pos.end()) {
      if (error) {
        *error = "pi_order entry not found in circuit: " + name;
      }
      return false;
    }
    log_to_circuit.push_back(it->second);
    if (it->second < seen_pos.size()) {
      seen_pos[it->second] += 1;
    }
  }
  for (std::size_t pos = 0; pos < seen_pos.size(); ++pos) {
    if (seen_pos[pos] == 0) {
      if (error) {
        *error = "circuit PI missing from groundtruth pi_order: " +
                 trojan.node_name(pi_indices[pos]);
      }
      return false;
    }
  }

  std::unordered_set<std::string> unique_bits;
  std::vector<std::string> ordered_bits;
  unique_bits.reserve(log.size());
  ordered_bits.reserve(log.size());
  for (std::size_t i = 0; i < log.size(); ++i) {
    auto bits = log.get_pattern_bits(static_cast<int>(i));
    if (!bits) {
      continue;
    }
    if (unique_bits.insert(*bits).second) {
      ordered_bits.push_back(*bits);
    }
  }

  if (ordered_bits.empty()) {
    if (error) {
      *error = "No pattern_bits found in groundtruth log";
    }
    return false;
  }

  stats->trigger_patterns.reserve(ordered_bits.size());
  for (const auto& bits : ordered_bits) {
    if (bits.size() != log_to_circuit.size()) {
      if (error) {
        *error = "pattern_bits length does not match pi_order";
      }
      return false;
    }
    std::vector<int> pi_values(pi_indices.size(), 0);
    for (std::size_t i = 0; i < log_to_circuit.size(); ++i) {
      char bit = bits[i];
      if (bit != '0' && bit != '1') {
        if (error) {
          *error = "pattern_bits contains invalid character";
        }
        return false;
      }
      pi_values[log_to_circuit[i]] = (bit == '1') ? 1 : 0;
    }
    stats->trigger_patterns.push_back(std::move(pi_values));
  }

  stats->trigger_patterns_total = stats->trigger_patterns.size();
  stats->mismatch_patterns = stats->trigger_patterns_total;

  stats->gate_indices.reserve(trojan.node_count());
  for (std::size_t i = 0; i < trojan.node_count(); ++i) {
    const auto& c = trojan.get_cell(static_cast<int>(i));
    if (c.ctype == CType::GATE) {
      stats->gate_indices.push_back(static_cast<int>(i));
    }
  }

  stats->ones_total.assign(stats->gate_indices.size(), 0);
  stats->ones_trigger.assign(stats->gate_indices.size(), 0);
  stats->ones_notrigger.assign(stats->gate_indices.size(), 0);

  circuit trojan_trigger = trojan;
  packed_circuit trojan_packed(trojan_trigger);
  std::size_t trigger_offset = 0;
  while (trigger_offset < stats->trigger_patterns.size()) {
    const std::size_t remaining =
        stats->trigger_patterns.size() - trigger_offset;
    const std::size_t block_size =
        std::min(packed_circuit::kWordBits, remaining);
    std::vector<std::vector<int>> patterns;
    patterns.reserve(block_size);
    for (std::size_t p = 0; p < block_size; ++p) {
      patterns.push_back(stats->trigger_patterns[trigger_offset + p]);
    }

    try {
      trojan_packed.simulate(patterns);
    } catch (const std::exception& e) {
      if (error) {
        *error = std::string("Trigger simulation error: ") + e.what();
      }
      return false;
    }

    #pragma omp parallel for schedule(static)
    for (std::size_t g = 0; g < stats->gate_indices.size(); ++g) {
      const int idx = stats->gate_indices[g];
      const std::uint64_t ones = popcount_ull(trojan_packed.node_bits(idx));
      stats->ones_trigger[g] += ones;
      stats->ones_total[g] += ones;
    }

    trigger_offset += block_size;
  }

  const std::size_t target_notrigger =
      stats->trigger_patterns_total * std::max<std::size_t>(1, neg_ratio);
  stats->notrigger_patterns_total = 0;
  stats->total_patterns = stats->trigger_patterns_total;

  if (target_notrigger == 0) {
    if (error) {
      *error = "No trigger patterns available";
    }
    return false;
  }

  circuit golden_eval = golden;
  circuit trojan_eval = trojan;
  packed_circuit golden_packed(golden_eval);
  packed_circuit trojan_eval_packed(trojan_eval);
  std::mt19937 rng(1337);
  std::uniform_int_distribution<int> dist(0, 1);
  std::size_t attempts = 0;
  const std::size_t max_attempts = target_notrigger * 50 + 1000;
  const std::size_t block_bits = packed_circuit::kWordBits;

  while (stats->notrigger_patterns_total < target_notrigger &&
         attempts < max_attempts) {
    const std::size_t remaining_attempts = max_attempts - attempts;
    const std::size_t block_size = std::min(block_bits, remaining_attempts);
    if (block_size == 0) {
      break;
    }

    std::vector<std::vector<int>> patterns;
    patterns.reserve(block_size);
    for (std::size_t p = 0; p < block_size; ++p) {
      std::vector<int> pi_values;
      pi_values.reserve(golden_eval.pi_count());
      for (std::size_t i = 0; i < golden_eval.pi_count(); ++i) {
        pi_values.push_back(dist(rng));
      }
      patterns.push_back(std::move(pi_values));
    }

    try {
      golden_packed.simulate(patterns);
      trojan_eval_packed.simulate(patterns);
    } catch (const std::exception&) {
      attempts += block_size;
      continue;
    }

    const packed_circuit::word_t mask =
        packed_circuit::mask_for_count(block_size);
    packed_circuit::word_t diff_mask = 0;
    for (std::size_t o = 0; o < trojan_eval.po_count(); ++o) {
      diff_mask |= (golden_packed.po_bits(o) ^ trojan_eval_packed.po_bits(o));
    }
    diff_mask &= mask;
    packed_circuit::word_t notrigger_mask = mask & ~diff_mask;

    const std::size_t remaining_needed =
        target_notrigger - stats->notrigger_patterns_total;
    const std::size_t available = popcount_ull(notrigger_mask);
    const std::size_t take = std::min(remaining_needed, available);
    packed_circuit::word_t accept_mask =
        (take == available) ? notrigger_mask
                            : take_first_bits(notrigger_mask, take);

    if (take > 0) {
      stats->notrigger_patterns_total += take;
      stats->total_patterns += take;
      #pragma omp parallel for schedule(static)
      for (std::size_t g = 0; g < stats->gate_indices.size(); ++g) {
        const int idx = stats->gate_indices[g];
        const packed_circuit::word_t bits =
            trojan_eval_packed.node_bits(idx) & accept_mask;
        const std::uint64_t ones = popcount_ull(bits);
        stats->ones_notrigger[g] += ones;
        stats->ones_total[g] += ones;
      }
    }

    attempts += block_size;
  }

  if (stats->notrigger_patterns_total < target_notrigger) {
    if (error) {
      *error = "Not enough non-trigger patterns collected: " +
               std::to_string(stats->notrigger_patterns_total) + "/" +
               std::to_string(target_notrigger);
    }
    return false;
  }

  return true;
}

struct GateScore {
  int gate_idx = 0;
  double p1_trigger = 0.0;
  double p1_notrigger = 0.0;
};

bool parse_size_arg(const std::string& text, std::size_t* out) {
  if (text.empty()) {
    return false;
  }
  char* end = nullptr;
  unsigned long long value = std::strtoull(text.c_str(), &end, 10);
  if (!end || *end != '\0') {
    return false;
  }
  *out = static_cast<std::size_t>(value);
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 4) {
    std::cerr << "Usage: " << (argc > 0 ? argv[0] : "p1_stats")
              << " <golden_bench> <trojan_bench> <groundtruth_log>"
                 " [--top N] [--neg-ratio N]\n";
    return 1;
  }

  std::size_t top_n = 10;
  std::size_t neg_ratio = 1;
  for (int i = 4; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--top") {
      if (i + 1 >= argc || !parse_size_arg(argv[++i], &top_n)) {
        std::cerr << "Invalid value for --top\n";
        return 1;
      }
      continue;
    }
    const std::string prefix = "--top=";
    if (arg.rfind(prefix, 0) == 0) {
      if (!parse_size_arg(arg.substr(prefix.size()), &top_n)) {
        std::cerr << "Invalid value for --top\n";
        return 1;
      }
      continue;
    }
    if (arg == "--neg-ratio") {
      if (i + 1 >= argc || !parse_size_arg(argv[++i], &neg_ratio)) {
        std::cerr << "Invalid value for --neg-ratio\n";
        return 1;
      }
      continue;
    }
    const std::string neg_prefix = "--neg-ratio=";
    if (arg.rfind(neg_prefix, 0) == 0) {
      if (!parse_size_arg(arg.substr(neg_prefix.size()), &neg_ratio)) {
        std::cerr << "Invalid value for --neg-ratio\n";
        return 1;
      }
      continue;
    }
  }

  const std::string golden_path = argv[1];
  const std::string trojan_path = argv[2];
  const std::string groundtruth_path = argv[3];

  std::string error;
  circuit golden;
  circuit trojan;
  if (!bench_io::parse_bench_file(golden_path, golden, &error)) {
    std::cerr << "Golden parse error: " << error << "\n";
    return 1;
  }
  if (!bench_io::parse_bench_file(trojan_path, trojan, &error)) {
    std::cerr << "Trojan parse error: " << error << "\n";
    return 1;
  }
  if (!align_circuits(golden, trojan, &error)) {
    std::cerr << "Circuit alignment error: " << error << "\n";
    return 1;
  }

  PatternStats stats;
  if (!build_stats_from_groundtruth(golden,
                                    trojan,
                                    groundtruth_path,
                                    neg_ratio,
                                    &stats,
                                    &error)) {
    std::cerr << "Groundtruth error: " << error << "\n";
    return 1;
  }

  const double trigger_total = static_cast<double>(stats.trigger_patterns_total);
  const double notrigger_total = static_cast<double>(stats.notrigger_patterns_total);

  std::vector<GateScore> scores;
  scores.reserve(stats.gate_indices.size());
  for (std::size_t g = 0; g < stats.gate_indices.size(); ++g) {
    const double p1_trigger = (trigger_total > 0.0)
        ? static_cast<double>(stats.ones_trigger[g]) / trigger_total
        : 0.0;
    const double p1_notrigger = (notrigger_total > 0.0)
        ? static_cast<double>(stats.ones_notrigger[g]) / notrigger_total
        : 0.0;
    scores.push_back(GateScore{stats.gate_indices[g], p1_trigger, p1_notrigger});
  }

  std::size_t perfect_count = 0;
  for (std::size_t g = 0; g < stats.gate_indices.size(); ++g) {
    if (stats.ones_trigger[g] == stats.trigger_patterns_total &&
        stats.ones_notrigger[g] == 0) {
      perfect_count += 1;
    }
  }

  const double p1_trigger_threshold = 0.8;
  const double p1_notrigger_threshold = 0.2;
  std::size_t candidate_count = 0;
  for (const auto& score : scores) {
    if (score.p1_trigger >= p1_trigger_threshold &&
        score.p1_notrigger <= p1_notrigger_threshold) {
      candidate_count += 1;
    }
  }

  std::sort(scores.begin(), scores.end(),
            [](const GateScore& a, const GateScore& b) {
              if (a.p1_trigger != b.p1_trigger) {
                return a.p1_trigger > b.p1_trigger;
              }
              if (a.p1_notrigger != b.p1_notrigger) {
                return a.p1_notrigger < b.p1_notrigger;
              }
              return a.gate_idx < b.gate_idx;
            });

  std::cout << "trigger_patterns_total " << stats.trigger_patterns_total << "\n";
  std::cout << "notrigger_patterns_total " << stats.notrigger_patterns_total << "\n";
  std::cout << "gate_count " << stats.gate_indices.size() << "\n";
  std::cout << "perfect_gate_count " << perfect_count << "\n";
  std::cout << "candidate_gate_count(p1_trigger>=0.8 & p1_notrigger<=0.2) "
            << candidate_count << "\n";

  std::cout << "top_gates_by_p1_trigger " << top_n << "\n";
  std::cout << std::fixed << std::setprecision(6);
  const std::size_t show_n = std::min(top_n, scores.size());
  for (std::size_t i = 0; i < show_n; ++i) {
    const auto& s = scores[i];
    std::cout << "  " << (i + 1) << ". "
              << trojan.node_name(s.gate_idx)
              << " p1_trigger=" << s.p1_trigger
              << " p1_notrigger=" << s.p1_notrigger
              << " idx=" << s.gate_idx << "\n";
  }

  return 0;
}
