#pragma once

#include <cstddef>
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
  unsigned rule_opt_timeout_ms = 10000;
  std::size_t rule_opt_max_rounds = 100;
  std::size_t rule_opt_cex_batch = 5;
  std::size_t rule_opt_max_clauses = 8;
  std::size_t rule_opt_max_literals = 10;
};

ParseStatus parse_cli_options(int argc, char** argv, AppOptions* out, std::string* error); // Parse CLI args into AppOptions.
void print_usage(const char* prog); // Print CLI usage to stdout.
