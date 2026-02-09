#include <algorithm>
#include <cstdint>
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
#include "algorithm/virtual_node.hpp"
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

  stats->trigger_patterns_total = stats->trigger_patterns.size();
  stats->mismatch_patterns = stats->trigger_patterns_total;

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
       << " strict_retry " << (options.strict_retry ? 1 : 0) << "\n";

  circuit working_trojan = trojan;
  PatternStats stats;
  MiningResult result;
  NegSampleTrace neg_trace;
  bool did_rule_merge = false;
  int merged_match_idx = -1;

  while (true) {
    try {
      if (!build_stats_from_groundtruth(golden, working_trojan, groundtruth_path, &stats, &error)) {
        cerr << "Groundtruth error: " << error << "\n";
        return 1;
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

    // --- Virtual node feature preprocessing (iterative multi-pass) ---
    // Virtual features are computed on-the-fly from simulation results.
    // The circuit is NOT modified during the VN iteration phase.
    // After iterations, only used VNs are inserted into the circuit.
    std::vector<VirtualNodeDef> final_vn_defs;  // VN defs for the SAT loop.
    if (!options.no_virtual) {
      // Collect base candidates (exclude any previously added virtual nodes).
      std::vector<int> base_for_vn;
      base_for_vn.reserve(candidate_indices.size());
      for (int idx : candidate_indices) {
        const std::string& nm = working_trojan.node_name(idx);
        if (nm.rfind("vn_", 0) != 0) {
          base_for_vn.push_back(idx);
        }
      }

      if (base_for_vn.size() >= 2) {
        // Phase 1: Quick tree training to identify important features.
        MiningOptions phase1_opts;
        phase1_opts.max_depth = options.max_depth;
        phase1_opts.neg_ratio = options.neg_ratio;
        phase1_opts.eval_count = 0;
        phase1_opts.mine_rounds = 1;
        phase1_opts.mine_max = 0;
        phase1_opts.include_pi = options.include_pi;
        phase1_opts.force_split = options.force_split;
        phase1_opts.strict_retry = false;

        MiningResult phase1_result;
        string phase1_error;
        bool phase1_ok = run_mining(golden, working_trojan,
                                     stats.trigger_patterns,
                                     base_for_vn, phase1_opts,
                                     trojan_rate, nullptr, nullptr,
                                     &phase1_result, &phase1_error);
        if (phase1_ok && !phase1_result.model.rules.empty()) {
          // Extract circuit node indices actually used by the tree.
          unordered_set<int> used_set;
          for (const auto& rule : phase1_result.model.rules) {
            for (const auto& term : rule.terms) {
              if (term.first < phase1_result.feature_nodes.size()) {
                used_set.insert(
                    phase1_result.feature_nodes[term.first]);
              }
            }
          }
          vector<int> important_signals(used_set.begin(), used_set.end());
          sort(important_signals.begin(), important_signals.end());

          cout << "vn_phase1_rules " << phase1_result.model.rules.size()
               << " important_signals " << important_signals.size()
               << " from_candidates " << base_for_vn.size() << "\n";

          // Phase 2: Generate pairwise+triple virtual nodes from important
          // signals.
          std::vector<VirtualNodeDef> all_vn_defs;
          if (important_signals.size() >= 2) {
            const std::size_t max_arity =
                (important_signals.size() <= 12) ? 3 : 2;
            generate_virtual_candidates(important_signals, max_arity,
                                        &all_vn_defs);
            cout << "vn_phase2_combo " << all_vn_defs.size()
                 << " max_arity " << max_arity << "\n";
          }

          // Phase 2b: Mine frequent subclauses (length 3-4) from phase1 rules
          // to create targeted higher-arity virtual nodes.
          // first_virtual_idx=0 means no virtual features exist yet.
          {
            std::vector<VirtualNodeDef> subclause_defs;
            mine_subclauses_from_rules(
                phase1_result.feature_nodes,
                phase1_result.model,
                3, 4,    // min_len=3, max_len=4 (reduced from 5)
                500,     // max_candidates (conservative)
                all_vn_defs,  // existing VN for dedup
                &subclause_defs,
                0);      // no virtual features in phase1
            if (!subclause_defs.empty()) {
              cout << "vn_phase2_subclauses " << subclause_defs.size() << "\n";
              for (auto& sd : subclause_defs) {
                all_vn_defs.push_back(std::move(sd));
              }
            }
          }

          // Phase 3: Iterative refinement - train with virtual features
          // (computed on-the-fly, NO circuit modification), then mine
          // subclauses from that result.
          if (!all_vn_defs.empty()) {
            cout << "vn_phase2_total " << all_vn_defs.size()
                 << " (virtual, circuit unchanged)\n";

            // best_vn_defs tracks the VN set that produced the fewest rules.
            std::vector<VirtualNodeDef> best_vn_defs = all_vn_defs;
            std::size_t best_rules = 0;

            const int max_vn_iters = 3;
            std::size_t prev_iter_rules = 0;
            for (int vn_iter = 0; vn_iter < max_vn_iters; ++vn_iter) {
              // Snapshot VN defs so we can revert on regression.
              const std::size_t vn_snapshot = all_vn_defs.size();

              MiningOptions iter_opts;
              iter_opts.max_depth = options.max_depth;
              iter_opts.neg_ratio = options.neg_ratio;
              iter_opts.eval_count = 0;
              iter_opts.mine_rounds = 1;
              iter_opts.mine_max = 0;
              iter_opts.include_pi = options.include_pi;
              iter_opts.force_split = options.force_split;
              iter_opts.strict_retry = false;

              // Train with base candidates + virtual features (on-the-fly).
              MiningResult iter_result;
              string iter_error;
              bool iter_ok = run_mining(golden, working_trojan,
                                         stats.trigger_patterns,
                                         base_for_vn, iter_opts,
                                         trojan_rate, nullptr, nullptr,
                                         &iter_result, &iter_error,
                                         &all_vn_defs);
              if (!iter_ok || iter_result.model.rules.empty()) {
                if (!iter_error.empty()) {
                  cerr << "vn_iter" << (vn_iter + 1)
                       << " error: " << iter_error << "\n";
                }
                break;
              }

              const std::size_t iter_rules = iter_result.model.rules.size();
              cout << "vn_iter" << (vn_iter + 1)
                   << "_rules " << iter_rules
                   << " vn_count " << all_vn_defs.size() << "\n";

              // Stop if rule count increased (regression from feature noise).
              // Revert VN defs to before this iteration's additions.
              if (prev_iter_rules > 0 && iter_rules >= prev_iter_rules) {
                all_vn_defs.resize(vn_snapshot);
                cout << "vn_iter" << (vn_iter + 1)
                     << " stopped+reverted: rules did not decrease ("
                     << prev_iter_rules << " -> " << iter_rules << ")\n";
                break;
              }
              prev_iter_rules = iter_rules;
              best_vn_defs = all_vn_defs;
              best_rules = iter_rules;

              // Mine subclauses of length 2-4 from this iteration's rules.
              // Skip virtual feature terms to prevent VN-on-VN composition.
              const std::size_t first_vn_feat = iter_result.feature_nodes.size();
              const std::size_t sc_max =
                  (vn_iter == 0) ? 500 : 200;
              std::vector<VirtualNodeDef> iter_subclauses;
              mine_subclauses_from_rules(
                  iter_result.feature_nodes,
                  iter_result.model,
                  2, 4,    // min_len=2, max_len=4 (reduced from 5)
                  sc_max,  // max_candidates (decreasing)
                  all_vn_defs,  // dedup against all existing
                  &iter_subclauses,
                  first_vn_feat);  // skip virtual features

              if (iter_subclauses.empty()) {
                cout << "vn_iter" << (vn_iter + 1)
                     << "_new_subclauses 0 (converged)\n";
                break;
              }

              // Add new subclauses to VN defs (no circuit modification).
              for (auto& sd : iter_subclauses) {
                all_vn_defs.push_back(std::move(sd));
              }
              cout << "vn_iter" << (vn_iter + 1)
                   << "_new_subclauses " << iter_subclauses.size()
                   << " total_vn " << all_vn_defs.size() << "\n";
            }

            // Use the best VN set found during iterations.
            final_vn_defs = std::move(best_vn_defs);
            cout << "vn_best_rules " << best_rules
                 << " vn_count " << final_vn_defs.size() << "\n";
          }
        } else {
          if (!phase1_error.empty()) {
            cerr << "virtual_node phase1 error: " << phase1_error << "\n";
          }
        }
      }
    }

    // --- Insert only used virtual nodes into the circuit ---
    // This happens BEFORE the SAT refinement loop, so the circuit
    // has only the VNs that actually appear in the best tree rules.
    // A final training pass determines which VNs are used.
    if (!final_vn_defs.empty()) {
      // Do one final training pass with the best VN set to identify
      // which VNs are actually referenced in the rules.
      MiningOptions final_vn_opts;
      final_vn_opts.max_depth = options.max_depth;
      final_vn_opts.neg_ratio = options.neg_ratio;
      final_vn_opts.eval_count = 0;
      final_vn_opts.mine_rounds = 1;
      final_vn_opts.mine_max = 0;
      final_vn_opts.include_pi = options.include_pi;
      final_vn_opts.force_split = options.force_split;
      final_vn_opts.strict_retry = false;

      // Collect base candidates again.
      std::vector<int> base_for_insert;
      for (int idx : candidate_indices) {
        const std::string& nm = working_trojan.node_name(idx);
        if (nm.rfind("vn_", 0) != 0) {
          base_for_insert.push_back(idx);
        }
      }

      MiningResult final_vn_result;
      string final_vn_error;
      bool final_vn_ok = run_mining(golden, working_trojan,
                                     stats.trigger_patterns,
                                     base_for_insert, final_vn_opts,
                                     trojan_rate, nullptr, nullptr,
                                     &final_vn_result, &final_vn_error,
                                     &final_vn_defs);

      if (final_vn_ok && !final_vn_result.model.rules.empty()) {
        // Find which VN indices are used in the rules.
        const std::size_t first_vn_feat = final_vn_result.feature_nodes.size();
        std::unordered_set<std::size_t> used_vn_set;
        for (const auto& rule : final_vn_result.model.rules) {
          for (const auto& term : rule.terms) {
            if (term.first >= first_vn_feat) {
              used_vn_set.insert(term.first - first_vn_feat);
            }
          }
        }

        // Collect only the used VN definitions.
        std::vector<VirtualNodeDef> used_defs;
        std::vector<std::size_t> used_vn_indices;
        for (std::size_t i = 0; i < final_vn_defs.size(); ++i) {
          if (used_vn_set.count(i)) {
            used_vn_indices.push_back(i);
            used_defs.push_back(final_vn_defs[i]);
          }
        }

        if (!used_defs.empty()) {
          // Add only used VNs to the circuit.
          std::vector<int> vn_circuit_indices =
              add_virtual_gates_to_circuit(working_trojan, used_defs);
          for (int vi : vn_circuit_indices) {
            candidate_indices.push_back(vi);
          }
          cout << "vn_insert_used " << used_defs.size()
               << " from " << final_vn_defs.size()
               << " circuit_nodes " << working_trojan.node_count() << "\n";
        }
        // Clear final_vn_defs since the used VNs are now in the circuit.
        final_vn_defs.clear();
      }
    }

    unordered_set<string> groundtruth_bits;
    groundtruth_bits.reserve(stats.trigger_patterns.size() * 2);
    for (const auto& pattern : stats.trigger_patterns) {
      groundtruth_bits.insert(pi_values_to_bits(pattern));
    }

    vector<vector<int>> sat_neg_patterns;
    unordered_set<string> sat_seen_bits;
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
      return 0;
    }

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
    return 0;
  } else if (!kill_error.empty()) {
    cerr << "payload_kill_trigger skipped: " << kill_error << "\n";
  }

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
    }
  } else {
    cout << "payload_fix_apply skipped: no fix nodes\n";
  }

  // FixResult fix_result;
  // if (!apply_rule_fix(golden,
  //                     trojan,
  //                     stats.trigger_patterns,
  //                     result.feature_nodes,
  //                     result.model,
  //                     &fix_result,
  //                     &error)) {
  //   if (!error.empty()) {
  //     cerr << "Trigger fix error: " << error << "\n";
  //   }
  //   return 1;
  // }

  // cout << "trigger_fix rules_total " << fix_result.rules_total
  //      << " rules_applied " << fix_result.rules_applied
  //      << " rules_skipped " << fix_result.rules_skipped
  //      << " po_candidates " << fix_result.po_candidates
  //      << " po_fixed " << fix_result.po_fixed
  //      << " po_xor " << fix_result.po_fixed_xor
  //      << " po_mux " << fix_result.po_fixed_mux << '\n';

  // PatternStats stats_after = sample_patterns(golden, trojan, options.pattern_count, 1337);
  // const double trojan_rate_after = compute_trojan_rate(stats_after);
  // cout << "trigger_patterns_after " << stats_after.trigger_patterns_total << '\n';
  // const ios_base::fmtflags prev_flags = cout.flags();
  // const streamsize prev_precision = cout.precision();
  // cout << defaultfloat << setprecision(6);
  // cout << "trojan_rates_after " << trojan_rate_after << '\n';
  // cout.flags(prev_flags);
  // cout.precision(prev_precision);

  // if (!options.output_path.empty()) {
  //   error.clear();
  //   if (!bench_io::write_bench_file(options.output_path, trojan, &error)) {
  //     cerr << "Write error: " << error << "\n";
  //     return 1;
  //   }
  // }

  return 0;
}
