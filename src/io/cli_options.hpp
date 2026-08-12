#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

enum class ParseStatus {
  ok,
  help,
  error
};

enum class RuleMethod {
  vn_retrain,
  dt,
  z3_pb
};

const char* rule_method_name(RuleMethod method);

enum class RepairMethod {
  legacy,
  dac25_inspired
};

const char* repair_method_name(RepairMethod method);

struct AppOptions {
  std::string golden_path;
  std::string trojan_path;
  std::string groundtruth_path;
  std::string output_path;
  std::size_t max_depth = 10;
  std::size_t neg_ratio = 50;
  std::size_t mine_rounds = 15;
  std::size_t mine_max = 5000;
  bool include_pi = true;
  bool no_filter = true;
  bool force_split = false;
  bool strict_retry = true;
  bool no_virtual = false;
  RuleMethod rule_method = RuleMethod::vn_retrain;
  RepairMethod repair_method = RepairMethod::legacy;
  unsigned rule_opt_timeout_ms = 10000;
  std::size_t rule_opt_max_rounds = 100;
  std::size_t rule_opt_cex_batch = 5;
  // Zero derives the cap from the current DT baseline.  An explicit nonzero
  // value is honored even when it is larger than the baseline rule count.
  std::size_t rule_opt_max_clauses = 0;
  std::size_t rule_opt_max_literals = 10;
  bool rule_formal_refine = false;
  std::uint64_t rule_formal_timeout_ms = 10000;
  std::size_t rule_formal_max_rounds = 5;
  std::size_t rule_formal_cex_batch = 5;
  std::uint64_t dac25_selector_timeout_ms = 30000;
  std::size_t dac25_candidate_limit = 32;
  std::size_t dac25_max_targets = 2;
  std::size_t dac25_max_sets = 4;
  std::uint64_t dac25_runeco_timeout_s = 60;
  std::string dac25_abc_bin = "abc";
};

ParseStatus parse_cli_options(int argc, char** argv, AppOptions* out, std::string* error); // Parse CLI args into AppOptions.
void print_usage(const char* prog); // Print CLI usage to stdout.
