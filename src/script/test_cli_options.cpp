#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "../io/cli_options.hpp"

namespace {

ParseStatus parse(std::vector<std::string> args,
                  AppOptions* options,
                  std::string* error) {
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (std::string& arg : args) {
    argv.push_back(arg.data());
  }
  return parse_cli_options(static_cast<int>(argv.size()), argv.data(),
                           options, error);
}

bool expect_method(std::vector<std::string> args,
                   RuleMethod expected,
                   const char* label) {
  AppOptions options;
  std::string error;
  const ParseStatus status = parse(std::move(args), &options, &error);
  if (status != ParseStatus::ok || options.rule_method != expected) {
    std::cerr << label << " failed: status=" << static_cast<int>(status)
              << " method=" << rule_method_name(options.rule_method)
              << " error=" << error << "\n";
    return false;
  }
  return true;
}

bool expect_error(std::vector<std::string> args,
                  const std::string& expected_text,
                  const char* label) {
  AppOptions options;
  std::string error;
  const ParseStatus status = parse(std::move(args), &options, &error);
  if (status != ParseStatus::error ||
      error.find(expected_text) == std::string::npos) {
    std::cerr << label << " failed: status=" << static_cast<int>(status)
              << " error=" << error << "\n";
    return false;
  }
  return true;
}

bool expect_z3_options(std::vector<std::string> args) {
  AppOptions options;
  std::string error;
  const ParseStatus status = parse(std::move(args), &options, &error);
  if (status != ParseStatus::ok ||
      options.rule_method != RuleMethod::z3_pb ||
      options.rule_opt_timeout_ms != 0 ||
      options.rule_opt_max_rounds != 7 ||
      options.rule_opt_cex_batch != 3 ||
      options.rule_opt_max_clauses != 0 ||
      options.rule_opt_max_literals != 4) {
    std::cerr << "z3 option parse failed: status="
              << static_cast<int>(status) << " error=" << error << "\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  const std::vector<std::string> positional = {"test_cli", "g", "t", "gt"};
  bool ok = true;
  ok &= expect_method(positional, RuleMethod::vn_retrain, "default");

  auto explicit_vn = positional;
  explicit_vn.insert(explicit_vn.end(), {"--rule-method", "vn-retrain"});
  ok &= expect_method(explicit_vn, RuleMethod::vn_retrain, "explicit vn");

  auto explicit_dt = positional;
  explicit_dt.insert(explicit_dt.end(), {"--rule-method", "dt"});
  ok &= expect_method(explicit_dt, RuleMethod::dt, "explicit dt");

  auto legacy_dt = positional;
  legacy_dt.push_back("--no-virtual");
  ok &= expect_method(legacy_dt, RuleMethod::dt, "legacy dt alias");

  auto compatible_alias = positional;
  compatible_alias.insert(compatible_alias.end(),
                          {"--rule-method", "dt", "--no-virtual"});
  ok &= expect_method(compatible_alias, RuleMethod::dt,
                      "compatible dt alias");

  auto conflicting_alias = positional;
  conflicting_alias.insert(conflicting_alias.end(),
                           {"--rule-method", "vn-retrain", "--no-virtual"});
  ok &= expect_error(conflicting_alias, "conflicts", "conflicting alias");

  auto explicit_z3 = positional;
  explicit_z3.insert(explicit_z3.end(), {"--rule-method", "z3-pb"});
  ok &= expect_method(explicit_z3, RuleMethod::z3_pb, "explicit z3-pb");

  auto configured_z3 = positional;
  configured_z3.insert(configured_z3.end(),
                       {"--rule-method", "z3-pb",
                        "--rule-opt-timeout-ms", "0",
                        "--rule-opt-max-rounds", "7",
                        "--rule-opt-cex-batch", "3",
                        "--rule-opt-max-clauses", "0",
                        "--rule-opt-max-literals", "4"});
  ok &= expect_z3_options(configured_z3);

  auto conflicting_z3_alias = positional;
  conflicting_z3_alias.insert(conflicting_z3_alias.end(),
                              {"--rule-method", "z3-pb", "--no-virtual"});
  ok &= expect_error(conflicting_z3_alias, "conflicts",
                     "z3-pb conflicts with no-virtual");

  auto zero_rounds = positional;
  zero_rounds.insert(zero_rounds.end(),
                     {"--rule-opt-max-rounds", "0"});
  ok &= expect_error(zero_rounds, "must be positive", "zero rounds");

  if (!ok) {
    return EXIT_FAILURE;
  }
  std::cout << "rule_method_cli_tests PASS\n";
  return EXIT_SUCCESS;
}
