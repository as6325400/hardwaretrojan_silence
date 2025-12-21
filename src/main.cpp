#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "algorithm/candidate_selector.hpp"
#include "algorithm/miner.hpp"
#include "algorithm/pattern_sampler.hpp"
#include "algorithm/trigger_fixer.hpp"
#include "core/circuit_compare.hpp"
#include "io/bench_parser.hpp"
#include "io/bench_writer.hpp"
#include "io/cli_options.hpp"

using namespace std;

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

  PatternStats stats = sample_patterns(golden, trojan, options.pattern_count);

  cout << "pattern_total " << stats.total_patterns << "\n";
  cout << "trigger_patterns " << stats.trigger_patterns_total << "\n";
  cout << "notrigger_patterns " << stats.notrigger_patterns_total << "\n";
  const double trojan_rate = compute_trojan_rate(stats);
  cout << "trojan_rates " << trojan_rate << '\n';

  cout << "gate_zero_ratio\n";
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

  cout << "trigger_candidates\n";
  for (const auto& cand : candidates) {
    cout << trojan.node_name(cand.gate_idx)
         << " p1_trigger=" << cand.p1_trigger
         << " p1_notrigger=" << cand.p1_notrigger << '\n';
  }

  vector<int> candidate_indices = candidate_gate_indices(candidates);

  MiningOptions mining_options;
  mining_options.max_depth = options.max_depth;
  mining_options.neg_ratio = options.neg_ratio;
  mining_options.eval_count = options.eval_count;
  mining_options.mine_rounds = options.mine_rounds;
  mining_options.mine_max = options.mine_max;
  mining_options.include_pi = options.include_pi;
  mining_options.force_split = options.force_split;
  mining_options.strict_retry = options.strict_retry;

  MiningResult result;
  if (!run_mining(golden,
                  trojan,
                  stats.trigger_patterns,
                  candidate_indices,
                  mining_options,
                  trojan_rate,
                  &result,
                  &error)) {
    if (!error.empty()) {
      cerr << error << "\n";
    }
    return 1;
  }

  cout << "training_set pos=" << result.data_pos
       << " neg=" << result.data_neg << '\n';
  cout << "hard_mined " << result.hard_added
       << " rounds " << result.rounds_used << '\n';

  cout << "decision_tree_rules " << result.model.rules.size()
       << " depth_used " << result.model.max_depth_used
       << " leaf_count " << result.model.leaf_count << '\n';

  for (size_t i = 0; i < result.model.rules.size(); ++i) {
    const auto& rule = result.model.rules[i];
    cout << "rule " << (i + 1) << ": ";
    if (rule.terms.empty()) {
      cout << "TRUE\n";
      continue;
    }
    for (size_t t = 0; t < rule.terms.size(); ++t) {
      if (t > 0) {
        cout << " & ";
      }
      const size_t feature_idx = rule.terms[t].first;
      const int value = rule.terms[t].second;
      if (feature_idx < result.feature_nodes.size()) {
        cout << trojan.node_name(result.feature_nodes[feature_idx]) << '=' << value;
      } else {
        cout << "f" << feature_idx << '=' << value;
      }
    }
    cout << '\n';
  }

  cout << "train_pos " << result.train_pos << " train_neg " << result.train_neg << '\n';
  cout << "train_false_neg " << result.train_false_neg
       << " train_false_pos " << result.train_false_pos << '\n';

  cout << "eval_normal " << result.eval_checked
       << " eval_false_pos " << result.eval_false_pos;
  if (result.eval_checked > 0) {
    const double rate =
        static_cast<double>(result.eval_false_pos) /
        static_cast<double>(result.eval_checked);
    cout << " rate " << rate;
  }
  cout << '\n';

  cout << "mis match " << stats.mismatch_patterns << '\n';

  FixResult fix_result;
  if (!apply_rule_fix(golden,
                      trojan,
                      stats.trigger_patterns,
                      result.feature_nodes,
                      result.model,
                      &fix_result,
                      &error)) {
    if (!error.empty()) {
      cerr << "Trigger fix error: " << error << "\n";
    }
    return 1;
  }

  cout << "trigger_fix rules_total " << fix_result.rules_total
       << " rules_applied " << fix_result.rules_applied
       << " rules_skipped " << fix_result.rules_skipped
       << " po_candidates " << fix_result.po_candidates
       << " po_fixed " << fix_result.po_fixed << '\n';

  PatternStats stats_after = sample_patterns(golden, trojan, options.pattern_count);
  const double trojan_rate_after = compute_trojan_rate(stats_after);
  cout << "trigger_patterns_after " << stats_after.trigger_patterns_total << '\n';
  const ios_base::fmtflags prev_flags = cout.flags();
  const streamsize prev_precision = cout.precision();
  cout << defaultfloat << setprecision(6);
  cout << "trojan_rates_after " << trojan_rate_after << '\n';
  cout.flags(prev_flags);
  cout.precision(prev_precision);

  if (!options.output_path.empty()) {
    error.clear();
    if (!bench_io::write_bench_file(options.output_path, trojan, &error)) {
      cerr << "Write error: " << error << "\n";
      return 1;
    }
  }

  return 0;
}
