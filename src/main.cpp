#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "algorithm/candidate_selector.hpp"
#include "algorithm/miner.hpp"
#include "algorithm/pattern_sampler.hpp"
#include "algorithm/payload_analysis.hpp"
#include "algorithm/rule_patch.hpp"
#include "algorithm/sat_refine.hpp"
#include "algorithm/trigger_fixer.hpp"
#include "core/circuit_compare.hpp"
#include "core/packed_circuit.hpp"
#include "io/bench_parser.hpp"
#include "io/bench_writer.hpp"
#include "io/cli_options.hpp"
#include "io/parallel_collect_log.hpp"

using namespace std;

namespace {

std::uint64_t popcount_ull(packed_circuit::word_t value) {
  return static_cast<std::uint64_t>(__builtin_popcountll(value));
}

packed_circuit::word_t take_first_bits(packed_circuit::word_t mask,
                                       size_t count) {
  packed_circuit::word_t out = 0;
  while (mask && count > 0) {
    const packed_circuit::word_t lsb = mask & (~mask + 1ULL);
    out |= lsb;
    mask &= (mask - 1);
    count -= 1;
  }
  return out;
}

bool compute_pattern_stats(const circuit& golden,
                           const circuit& trojan,
                           PatternStats* stats,
                           string* error) {
  stats->trigger_patterns_total = stats->trigger_patterns.size();
  stats->mismatch_patterns = stats->trigger_patterns_total;

  stats->gate_indices.clear();
  stats->gate_indices.reserve(trojan.node_count());
  for (size_t i = 0; i < trojan.node_count(); ++i) {
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
        *error = string("Trigger simulation error: ") + e.what();
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

  const size_t target_notrigger = stats->trigger_patterns_total;
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
  mt19937 rng(1337);
  uniform_int_distribution<int> dist(0, 1);
  size_t attempts = 0;
  const size_t max_attempts = target_notrigger * 50 + 1000;
  const size_t block_bits = packed_circuit::kWordBits;

  while (stats->notrigger_patterns_total < target_notrigger &&
         attempts < max_attempts) {
    const size_t remaining_attempts = max_attempts - attempts;
    const size_t block_size = min(block_bits, remaining_attempts);
    if (block_size == 0) {
      break;
    }

    vector<vector<int>> patterns;
    patterns.reserve(block_size);
    for (size_t p = 0; p < block_size; ++p) {
      vector<int> pi_values;
      pi_values.reserve(golden_eval.pi_count());
      for (size_t i = 0; i < golden_eval.pi_count(); ++i) {
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
    for (size_t o = 0; o < trojan_eval.po_count(); ++o) {
      diff_mask |= (golden_packed.po_bits(o) ^ trojan_eval_packed.po_bits(o));
    }
    diff_mask &= mask;
    packed_circuit::word_t notrigger_mask = mask & ~diff_mask;

    const size_t remaining_needed =
        target_notrigger - stats->notrigger_patterns_total;
    const size_t available = popcount_ull(notrigger_mask);
    const size_t take = min(remaining_needed, available);
    packed_circuit::word_t accept_mask =
        (take == available) ? notrigger_mask
                            : take_first_bits(notrigger_mask, take);

    if (take > 0) {
      stats->notrigger_patterns_total += take;
      stats->total_patterns += take;
      #pragma omp parallel for schedule(static)
      for (size_t g = 0; g < stats->gate_indices.size(); ++g) {
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
               to_string(stats->notrigger_patterns_total) + "/" +
               to_string(target_notrigger);
    }
    return false;
  }

  return true;
}

bool build_stats_from_groundtruth(const circuit& golden,
                                  const circuit& trojan,
                                  const string& log_path,
                                  PatternStats* stats,
                                  string* error) {
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
  unordered_map<string, size_t> pi_name_to_pos;
  pi_name_to_pos.reserve(pi_indices.size());
  for (size_t pos = 0; pos < pi_indices.size(); ++pos) {
    pi_name_to_pos[trojan.node_name(pi_indices[pos])] = pos;
  }

  vector<size_t> log_to_circuit;
  log_to_circuit.reserve(log_pi_order.size());
  vector<int> seen_pos(pi_indices.size(), 0);
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
  for (size_t pos = 0; pos < seen_pos.size(); ++pos) {
    if (seen_pos[pos] == 0) {
      if (error) {
        *error = "circuit PI missing from groundtruth pi_order: " +
                 trojan.node_name(pi_indices[pos]);
      }
      return false;
    }
  }

  unordered_set<string> unique_bits;
  vector<string> ordered_bits;
  unique_bits.reserve(log.size());
  ordered_bits.reserve(log.size());
  for (size_t i = 0; i < log.size(); ++i) {
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
    vector<int> pi_values(pi_indices.size(), 0);
    for (size_t i = 0; i < log_to_circuit.size(); ++i) {
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

  return compute_pattern_stats(golden, trojan, stats, error);
}

bool run_abc_cec(const string& golden_path, const string& patched_path,
                 string* detail) {
  string cmd = "abc -q \"read_bench " + golden_path +
               "; cec " + patched_path + "\" 2>&1";
  FILE* pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    if (detail) *detail = "popen failed";
    return false;
  }

  string output;
  char buffer[512];
  while (fgets(buffer, sizeof(buffer), pipe)) {
    output += buffer;
  }
  pclose(pipe);

  if (detail) *detail = output;

  if (output.find("NOT EQUIVALENT") != string::npos ||
      output.find("not equivalent") != string::npos) {
    return false;
  }
  if (output.find("equivalent") != string::npos ||
      output.find("Equivalent") != string::npos ||
      output.find("EQUIVALENT") != string::npos) {
    return true;
  }
  return false;
}

bool parse_abc_counterexample(const string& abc_output,
                              const circuit& circ,
                              vector<int>* out_pattern) {
  // ABC CEC output format:
  //   INPUT: name = 1'h0, name = 1'h1, ...  OUTPUT: ...
  // The "Input pattern:" line at the end is often empty, so parse INPUT: instead.
  auto inp_pos = abc_output.find("INPUT:");
  if (inp_pos == string::npos) return false;

  inp_pos += 6; // skip "INPUT:"
  // Extract up to "OUTPUT:" or end of line
  auto out_pos = abc_output.find("OUTPUT:", inp_pos);
  auto nl_pos = abc_output.find('\n', inp_pos);
  size_t end_pos;
  if (out_pos != string::npos && (nl_pos == string::npos || out_pos < nl_pos)) {
    end_pos = out_pos;
  } else if (nl_pos != string::npos) {
    end_pos = nl_pos;
  } else {
    end_pos = abc_output.size();
  }
  string segment = abc_output.substr(inp_pos, end_pos - inp_pos);

  const auto& pi_indices = circ.pi_indices();
  unordered_map<string, size_t> pi_name_to_pos;
  pi_name_to_pos.reserve(pi_indices.size());
  for (size_t i = 0; i < pi_indices.size(); ++i) {
    pi_name_to_pos[circ.node_name(pi_indices[i])] = i;
  }

  out_pattern->assign(pi_indices.size(), 0);
  size_t matched = 0;

  // Parse comma-separated "name = value" pairs
  size_t i = 0;
  while (i < segment.size()) {
    // skip whitespace and commas
    while (i < segment.size() &&
           (segment[i] == ' ' || segment[i] == '\t' || segment[i] == ','))
      ++i;
    if (i >= segment.size()) break;

    size_t eq = segment.find('=', i);
    if (eq == string::npos) break;

    // name is everything from i to eq, trimmed
    size_t name_end = eq;
    while (name_end > i && segment[name_end - 1] == ' ') --name_end;
    string name = segment.substr(i, name_end - i);

    // value starts after '='
    i = eq + 1;
    while (i < segment.size() && segment[i] == ' ') ++i;
    size_t val_end = i;
    while (val_end < segment.size() &&
           segment[val_end] != ',' && segment[val_end] != ' ' &&
           segment[val_end] != '\t')
      ++val_end;
    string val_str = segment.substr(i, val_end - i);
    i = val_end;

    // Strip trailing period (ABC ends the INPUT section with '.')
    if (!val_str.empty() && val_str.back() == '.') {
      val_str.pop_back();
    }

    int val = 0;
    if (val_str == "1" || val_str == "1'h1") val = 1;
    else if (val_str == "0" || val_str == "1'h0") val = 0;
    else continue;

    auto it = pi_name_to_pos.find(name);
    if (it != pi_name_to_pos.end()) {
      (*out_pattern)[it->second] = val;
      ++matched;
    }
  }
  return matched > 0;
}

std::vector<std::vector<int>> find_cec_counterexamples(
    const circuit& golden,
    const circuit& target,
    std::size_t max_attempts,
    std::size_t max_found,
    unsigned seed) {
  std::vector<std::vector<int>> counterexamples;

  circuit golden_eval = golden;
  circuit target_eval = target;
  packed_circuit golden_packed(golden_eval);
  packed_circuit target_packed(target_eval);

  std::mt19937 rng(seed);
  std::uniform_int_distribution<int> dist(0, 1);
  const std::size_t block_bits = packed_circuit::kWordBits;
  std::size_t total_checked = 0;

  std::unordered_set<std::string> seen;

  while (total_checked < max_attempts &&
         counterexamples.size() < max_found) {
    const std::size_t remaining = max_attempts - total_checked;
    const std::size_t block_size = std::min(block_bits, remaining);
    if (block_size == 0) break;

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
      target_packed.simulate(patterns);
    } catch (const std::exception&) {
      total_checked += block_size;
      continue;
    }

    const auto mask = packed_circuit::mask_for_count(block_size);
    packed_circuit::word_t diff_mask = 0;
    for (std::size_t o = 0; o < golden_eval.po_count(); ++o) {
      diff_mask |= (golden_packed.po_bits(o) ^ target_packed.po_bits(o));
    }
    diff_mask &= mask;

    packed_circuit::word_t tmp = diff_mask;
    while (tmp && counterexamples.size() < max_found) {
      const int bit = __builtin_ctzll(tmp);
      std::string key = pi_values_to_bits(patterns[bit]);
      if (seen.insert(key).second) {
        counterexamples.push_back(patterns[bit]);
      }
      tmp &= (tmp - 1);
    }

    total_checked += block_size;
  }

  return counterexamples;
}

}  // namespace

int main(int argc, char** argv) {
  AppOptions options;
  string error;
  const ParseStatus status = parse_cli_options(argc, argv, &options, &error);
  if (status == ParseStatus::help) {
    print_usage(argv[0]);
    return 0;
  }
  if (status == ParseStatus::error) {
    if (!error.empty()) {
      cerr << error << "\n";
    }
    print_usage(argv[0]);
    return 1;
  }

  circuit golden;
  circuit trojan;
  if (!bench_io::parse_bench_file(options.golden_path, golden, &error)) {
    cerr << "Golden parse error: " << error << "\n";
    return 1;
  }
  if (!bench_io::parse_bench_file(options.trojan_path, trojan, &error)) {
    cerr << "Trojan parse error: " << error << "\n";
    return 1;
  }

  if (!align_circuits(golden, trojan, &error)) {
    cerr << "Circuit alignment error: " << error << "\n";
    return 1;
  }

  const string& groundtruth_path = options.groundtruth_path;
  cout << "groundtruth " << groundtruth_path << "\n";

  cout << "patterns " << options.pattern_count
       << " depth " << options.max_depth
       << " eval " << options.eval_count
       << " neg_ratio " << options.neg_ratio
       << " mine_rounds " << options.mine_rounds
       << " mine_max " << options.mine_max << "\n";
  cout << "p1_trigger " << options.p1_trigger_threshold
       << " p1_notrigger " << options.p1_notrigger_threshold
       << " include_pi " << (options.include_pi ? 1 : 0)
       << " no_filter " << (options.no_filter ? 1 : 0)
       << " force_split " << (options.force_split ? 1 : 0)
       << " strict_retry " << (options.strict_retry ? 1 : 0)
       << " cec_rounds " << options.cec_rounds << "\n";

  vector<vector<int>> cec_extra_patterns;
  vector<vector<int>> cec_extra_neg_patterns;
  vector<vector<int>> original_trigger_patterns;

  for (size_t cec_iter = 0; ; ++cec_iter) {
    if (cec_iter > 0) {
      cout << "\n--- cec_retry_round " << (cec_iter + 1)
           << " extra_pos " << cec_extra_patterns.size()
           << " extra_neg " << cec_extra_neg_patterns.size() << " ---\n";
    }

    circuit working_trojan = trojan;
    PatternStats stats;
    MiningResult result;
    NegSampleTrace neg_trace;
    bool did_rule_merge = false;
    int merged_match_idx = -1;
    bool patch_written = false;
    string actual_patched_path;
    circuit final_patched;

    while (true) {
      try {
        if (cec_extra_patterns.empty()) {
          if (!build_stats_from_groundtruth(golden, working_trojan, groundtruth_path, &stats, &error)) {
            cerr << "Groundtruth error: " << error << "\n";
            return 1;
          }
          if (original_trigger_patterns.empty()) {
            original_trigger_patterns = stats.trigger_patterns;
          }
        } else {
          stats = PatternStats{};
          stats.trigger_patterns = original_trigger_patterns;
          for (const auto& p : cec_extra_patterns) {
            stats.trigger_patterns.push_back(p);
          }
          if (!compute_pattern_stats(golden, working_trojan, &stats, &error)) {
            cerr << "Pattern stats error: " << error << "\n";
            return 1;
          }
        }
      } catch (const std::exception& e) {
        cerr << "Groundtruth parse error: " << e.what() << "\n";
        return 1;
      }

      cout << "pattern_total " << stats.total_patterns << "\n";
      cout << "trigger_patterns " << stats.trigger_patterns_total << "\n";
      cout << "notrigger_patterns " << stats.notrigger_patterns_total << "\n";
      const double trojan_rate = compute_trojan_rate(stats);
      cout << "trojan_rates " << trojan_rate << '\n';
      cout << fixed << setprecision(4);

      vector<CandidateInfo> candidates;
      if (!build_candidates(stats,
                            options.p1_trigger_threshold,
                            options.p1_notrigger_threshold,
                            options.no_filter,
                            &candidates,
                            &error)) {
        cerr << error << "\n";
        return 1;
      }

      vector<int> candidate_indices = candidate_gate_indices(candidates);

      bool filter_rule_opt = did_rule_merge;
      if (!filter_rule_opt) {
        bool has_rule_opt = false;
        bool has_rule_match = false;
        for (std::size_t i = 0; i < working_trojan.node_count(); ++i) {
          const std::string& name = working_trojan.node_name(static_cast<int>(i));
          if (!has_rule_opt && name.rfind("rule_opt_gate_", 0) == 0) {
            has_rule_opt = true;
          }
          if (!has_rule_match && name.rfind("rule_match_", 0) == 0) {
            has_rule_match = true;
          }
          if (has_rule_opt && has_rule_match) {
            break;
          }
        }
        filter_rule_opt = has_rule_opt && has_rule_match;
      }

      if (filter_rule_opt) {
        std::vector<int> filtered;
        filtered.reserve(candidate_indices.size());
        for (int idx : candidate_indices) {
          const std::string& name = working_trojan.node_name(idx);
          if (name.rfind("rule_opt_gate_", 0) == 0) {
            continue;
          }
          filtered.push_back(idx);
        }
        candidate_indices.swap(filtered);
      }

      if (merged_match_idx >= 0 &&
          std::find(candidate_indices.begin(),
                    candidate_indices.end(),
                    merged_match_idx) == candidate_indices.end()) {
        candidate_indices.push_back(merged_match_idx);
      }

      unordered_set<string> groundtruth_bits;
      groundtruth_bits.reserve(stats.trigger_patterns.size() * 2);
      for (const auto& pattern : stats.trigger_patterns) {
        groundtruth_bits.insert(pi_values_to_bits(pattern));
      }

      vector<vector<int>> sat_neg_patterns(cec_extra_neg_patterns);
      unordered_set<string> sat_seen_bits;
      for (const auto& p : cec_extra_neg_patterns) {
        sat_seen_bits.insert(pi_values_to_bits(p));
      }
      size_t sat_rounds = options.mine_rounds;
      if (sat_rounds == 0) {
        sat_rounds = 1;
      }
      const size_t sat_max_new = options.mine_max;
      const size_t sat_max_models =
          (options.eval_count > 0) ? options.eval_count
                                   : (sat_max_new * 20 + 1000);

      for (size_t round = 0; round < sat_rounds; ++round) {
        MiningOptions mining_options;
        mining_options.max_depth = options.max_depth;
        mining_options.neg_ratio = options.neg_ratio;
        mining_options.eval_count = 0;
        mining_options.mine_rounds = 1;
        mining_options.mine_max = 0;
        mining_options.include_pi = options.include_pi;
        mining_options.force_split = options.force_split;
        mining_options.strict_retry = options.strict_retry;

      if (!run_mining(golden,
                      working_trojan,
                      stats.trigger_patterns,
                      candidate_indices,
                      mining_options,
                      trojan_rate,
                      &sat_neg_patterns,
                      &neg_trace,
                      &result,
                      &error)) {
          if (!error.empty()) {
            cerr << error << "\n";
          }
          return 1;
        }

        const size_t rules_before = result.model.rules.size();
        simplify_rules(&result.model.rules);
        if (result.model.rules.size() != rules_before) {
          result.model.leaf_count = result.model.rules.size();
          cout << "rule_simplify " << rules_before
               << " -> " << result.model.rules.size() << "\n";
        }

        if (sat_max_new == 0 || sat_max_models == 0) {
          cout << "sat_refine_skipped 1\n";
          break;
        }

        cout << "sat_refine_round_start " << (round + 1)
             << " max_models " << sat_max_models
             << " max_new " << sat_max_new << "\n";

        vector<vector<int>> new_negatives;
        if (!collect_rule_counterexamples(golden,
                                          working_trojan,
                                          result,
                                          round + 1,
                                          groundtruth_bits,
                                          &sat_seen_bits,
                                          sat_max_models,
                                          sat_max_new,
                                          &new_negatives,
                                          &error)) {
          if (!error.empty()) {
            cerr << "SAT rule check error: " << error << "\n";
          }
          return 1;
        }

        if (new_negatives.empty()) {
          cout << "sat_refine_round " << (round + 1)
               << " sat_new_neg 0\n";
          break;
        }

        for (auto& pattern : new_negatives) {
          sat_neg_patterns.push_back(std::move(pattern));
        }
        cout << "sat_refine_round " << (round + 1)
             << " sat_new_neg " << new_negatives.size()
             << " sat_total_neg " << sat_neg_patterns.size() << "\n";
      }

      cout << "training_set pos=" << result.data_pos
           << " neg=" << result.data_neg << '\n';
      cout << "hard_mined " << result.hard_added
           << " rounds " << result.rounds_used << '\n';

      cout << "mis match " << stats.mismatch_patterns << '\n';

      if (!did_rule_merge && result.model.rules.size() > 1U) {
        circuit merged = working_trojan;
        std::string merge_error;
        int match_idx = -1;
        std::string match_name;
        if (append_rule_match_node(merged,
                                   result.feature_nodes,
                                   result.model,
                                   &match_idx,
                                   &match_name,
                                   &merge_error)) {
          const std::string merge_path = derive_rule_merged_path(options.trojan_path);
          if (!bench_io::write_bench_file(merge_path, merged, &merge_error)) {
            cerr << "rule_merge_write_error: " << merge_error << "\n";
          } else {
            cout << "rule_merge_bench " << merge_path << "\n";
          }
          cout << "rule_merge_node " << match_name << "\n";
          working_trojan = std::move(merged);
          merged_match_idx = match_idx;
          did_rule_merge = true;
          break;
        }
        if (!merge_error.empty()) {
          cerr << "rule_merge_error: " << merge_error << "\n";
        }
      }
      break;
    }

    bool trigger_killed = false;
    int kill_trigger_idx = -1;
    int kill_value = 0;
    std::string kill_error;
    circuit killed = working_trojan;
    if (try_kill_simple_trigger(killed,
                                result.feature_nodes,
                                result.model,
                                &kill_trigger_idx,
                                &kill_value,
                                &kill_error)) {
      std::size_t base_area = 0;
      std::size_t base_level = 0;
      std::size_t killed_area = 0;
      std::size_t killed_level = 0;
      try {
        circuit base_eval = working_trojan;
        base_eval.ensure_eval_order();
        base_area = base_eval.area();
        base_level = base_eval.level();
        killed.ensure_eval_order();
        killed_area = killed.area();
        killed_level = killed.level();
      } catch (const std::exception& e) {
        cerr << "Payload kill area/level error: " << e.what() << "\n";
        return 1;
      }

      cout << "payload_kill_trigger " << working_trojan.node_name(kill_trigger_idx)
           << " forced " << kill_value << "\n";
      cout << "payload_kill_area " << base_area << " -> " << killed_area
           << " level " << base_level << " -> " << killed_level << "\n";

      std::size_t mismatch_index = 0;
      if (!verify_patch_groundtruth(golden,
                                    killed,
                                    stats.trigger_patterns,
                                    &mismatch_index,
                                    &error)) {
        cerr << "Payload kill verification failed: " << error;
        if (!stats.trigger_patterns.empty()) {
          cerr << " pattern " << mismatch_index;
        }
        cerr << "\n";
        cout << "payload_fix_apply skipped: groundtruth_verify_failed\n";
      } else {
        const long long delta_area =
            static_cast<long long>(killed_area) -
            static_cast<long long>(base_area);
        const long long delta_level =
            static_cast<long long>(killed_level) -
            static_cast<long long>(base_level);

        const string output_path = options.output_path.empty()
                                       ? derive_patched_path(options.trojan_path)
                                       : options.output_path;
        if (!bench_io::write_bench_file(output_path, killed, &error)) {
          cerr << "Write error: " << error << "\n";
          return 1;
        }
        cout << "payload_fix_selected 1 area_delta " << delta_area
             << " level_delta " << delta_level << "\n";
        cout << "payload_fix_bench " << output_path << "\n";
        patch_written = true;
        actual_patched_path = output_path;
        final_patched = killed;
        trigger_killed = true;
      }
    } else if (!kill_error.empty()) {
      cerr << "payload_kill_trigger skipped: " << kill_error << "\n";
    }

    if (!trigger_killed) {
      std::vector<int> payload_fix_nodes;
      analyze_payload_nodes(golden,
                            working_trojan,
                            stats,
                            result,
                            merged_match_idx,
                            &payload_fix_nodes);

      if (!payload_fix_nodes.empty()) {
        circuit base_eval = working_trojan;
        std::size_t base_area = 0;
        std::size_t base_level = 0;
        try {
          base_eval.ensure_eval_order();
          base_area = base_eval.area();
          base_level = base_eval.level();
        } catch (const std::exception& e) {
          cerr << "Payload fix baseline error: " << e.what() << "\n";
          return 1;
        }

        circuit patched = working_trojan;
        for (int fix_idx : payload_fix_nodes) {
          std::size_t step_area_before = 0;
          std::size_t step_level_before = 0;
          try {
            patched.ensure_eval_order();
            step_area_before = patched.area();
            step_level_before = patched.level();
          } catch (const std::exception& e) {
            cerr << "Payload fix step baseline error: " << e.what() << "\n";
            return 1;
          }

          const auto start = std::chrono::steady_clock::now();
          const std::size_t base_nodes = patched.node_count();
          bool used_bypass = false;
          if (!apply_rule_patch(patched,
                                result.feature_nodes,
                                result.model,
                                fix_idx,
                                base_nodes,
                                &used_bypass,
                                &error)) {
            cerr << "Payload fix apply error: " << error << "\n";
            return 1;
          }
          const auto end = std::chrono::steady_clock::now();
          const auto elapsed_ms =
              std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

          std::size_t step_area_after = 0;
          std::size_t step_level_after = 0;
          try {
            patched.ensure_eval_order();
            step_area_after = patched.area();
            step_level_after = patched.level();
          } catch (const std::exception& e) {
            cerr << "Payload fix step area/level error: " << e.what() << "\n";
            return 1;
          }

          cout << "payload_fix_step " << working_trojan.node_name(fix_idx)
               << " time_ms " << elapsed_ms
               << " area " << step_area_before << " -> " << step_area_after
               << " level " << step_level_before << " -> " << step_level_after
               << " bypass " << (used_bypass ? 1 : 0) << "\n";
        }

        std::size_t mismatch_index = 0;
        if (!verify_patch_groundtruth(golden,
                                      patched,
                                      stats.trigger_patterns,
                                      &mismatch_index,
                                      &error)) {
          cerr << "Payload fix verification failed: " << error;
          if (!stats.trigger_patterns.empty()) {
            cerr << " pattern " << mismatch_index;
          }
          cerr << "\n";
          cout << "payload_fix_apply skipped: groundtruth_verify_failed\n";
        } else {
          std::size_t patched_area = 0;
          std::size_t patched_level = 0;
          try {
            patched.ensure_eval_order();
            patched_area = patched.area();
            patched_level = patched.level();
          } catch (const std::exception& e) {
            cerr << "Payload fix area/level error: " << e.what() << "\n";
            return 1;
          }

          const long long delta_area =
              static_cast<long long>(patched_area) -
              static_cast<long long>(base_area);
          const long long delta_level =
              static_cast<long long>(patched_level) -
              static_cast<long long>(base_level);

          const string output_path = options.output_path.empty()
                                         ? derive_patched_path(options.trojan_path)
                                         : options.output_path;
          if (!bench_io::write_bench_file(output_path, patched, &error)) {
            cerr << "Write error: " << error << "\n";
            return 1;
          }
          cout << "payload_fix_selected " << payload_fix_nodes.size()
               << " area_delta " << delta_area
               << " level_delta " << delta_level << "\n";
          cout << "payload_fix_bench " << output_path << "\n";
          patch_written = true;
          actual_patched_path = output_path;
          final_patched = patched;
        }
      } else {
        cout << "payload_fix_apply skipped: no fix nodes\n";
      }
    }

    if (options.cec_rounds == 0 || !patch_written) {
      break;
    }
    if (cec_iter >= options.cec_rounds - 1) {
      cout << "cec_max_rounds " << options.cec_rounds << "\n";
      break;
    }

    string cec_detail;
    cout << "cec_check round " << (cec_iter + 1) << " ... ";
    cout.flush();
    bool equivalent = run_abc_cec(options.golden_path, actual_patched_path,
                                  &cec_detail);
    cout << (equivalent ? "equivalent" : "not_equivalent") << "\n";

    if (equivalent) {
      cout << "cec_pass 1\n";
      break;
    }

    unordered_set<string> existing_bits;
    for (const auto& p : original_trigger_patterns) {
      existing_bits.insert(pi_values_to_bits(p));
    }
    for (const auto& p : cec_extra_patterns) {
      existing_bits.insert(pi_values_to_bits(p));
    }

    // Collect raw counterexamples (golden != patched)
    vector<vector<int>> raw_cex;

    // Try parsing the ABC counterexample directly
    vector<int> abc_cex;
    if (parse_abc_counterexample(cec_detail, golden, &abc_cex)) {
      string key = pi_values_to_bits(abc_cex);
      if (existing_bits.insert(key).second) {
        raw_cex.push_back(std::move(abc_cex));
        cout << "cec_abc_counterexample 1\n";
      }
    }

    // Also search by simulation for more counterexamples
    auto new_cex = find_cec_counterexamples(
        golden, final_patched, 1000000, 64,
        static_cast<unsigned>(42 + cec_iter));

    for (auto& p : new_cex) {
      string key = pi_values_to_bits(p);
      if (existing_bits.insert(key).second) {
        raw_cex.push_back(std::move(p));
      }
    }

    // Classify: simulate on golden vs trojan to separate
    //   golden != trojan  -> real trigger (positive)
    //   golden == trojan  -> patch collateral damage (negative)
    size_t added_pos = 0;
    size_t added_neg = 0;
    if (!raw_cex.empty()) {
      circuit golden_cls = golden;
      circuit trojan_cls = trojan;
      packed_circuit golden_pk(golden_cls);
      packed_circuit trojan_pk(trojan_cls);

      for (auto& pat : raw_cex) {
        vector<vector<int>> batch = { pat };
        golden_pk.simulate(batch);
        trojan_pk.simulate(batch);

        bool differs = false;
        for (size_t o = 0; o < golden_cls.po_count(); ++o) {
          if ((golden_pk.po_bits(o) ^ trojan_pk.po_bits(o)) & 1ULL) {
            differs = true;
            break;
          }
        }

        if (differs) {
          cec_extra_patterns.push_back(std::move(pat));
          ++added_pos;
        } else {
          cec_extra_neg_patterns.push_back(std::move(pat));
          ++added_neg;
        }
      }
    }

    cout << "cec_new_counterexamples " << (added_pos + added_neg)
         << " cec_pos " << added_pos
         << " cec_neg " << added_neg
         << " cec_total_extra_pos " << cec_extra_patterns.size()
         << " cec_total_extra_neg " << cec_extra_neg_patterns.size() << "\n";

    if (added_pos + added_neg == 0) {
      cout << "cec_no_new_counterexamples\n";
      break;
    }
  }

  return 0;
}
