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

bool expect_milp_options(std::vector<std::string> args) {
  AppOptions options;
  std::string error;
  const ParseStatus status = parse(std::move(args), &options, &error);
  if (status != ParseStatus::ok ||
      options.rule_method != RuleMethod::milp_cover ||
      options.rule_opt_timeout_ms != 0 ||
      options.rule_opt_max_clauses != 3 ||
      options.rule_opt_max_literals != 4 ||
      options.rule_cover_max_terms != 123 ||
      options.rule_cover_minimize_inverters ||
      options.rule_cover_phase3_timeout_ms != 0) {
    std::cerr << "milp option parse failed: status="
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

  auto explicit_milp = positional;
  explicit_milp.insert(explicit_milp.end(),
                       {"--rule-method", "milp-cover"});
  ok &= expect_method(explicit_milp, RuleMethod::milp_cover,
                      "explicit milp-cover");

  auto configured_z3 = positional;
  configured_z3.insert(configured_z3.end(),
                       {"--rule-method", "z3-pb",
                        "--rule-opt-timeout-ms", "0",
                        "--rule-opt-max-rounds", "7",
                        "--rule-opt-cex-batch", "3",
                        "--rule-opt-max-clauses", "0",
                        "--rule-opt-max-literals", "4"});
  ok &= expect_z3_options(configured_z3);

  auto configured_milp = positional;
  configured_milp.insert(configured_milp.end(),
                         {"--rule-method", "milp-cover",
                          "--rule-opt-timeout-ms", "0",
                          "--rule-opt-max-clauses", "3",
                          "--rule-opt-max-literals", "4",
                          "--rule-cover-max-terms", "123",
                          "--rule-cover-third-objective", "none",
                          "--rule-cover-phase3-timeout-ms", "0"});
  ok &= expect_milp_options(configured_milp);

  auto conflicting_z3_alias = positional;
  conflicting_z3_alias.insert(conflicting_z3_alias.end(),
                              {"--rule-method", "z3-pb", "--no-virtual"});
  ok &= expect_error(conflicting_z3_alias, "conflicts",
                     "z3-pb conflicts with no-virtual");

  auto conflicting_milp_alias = positional;
  conflicting_milp_alias.insert(
      conflicting_milp_alias.end(),
      {"--rule-method", "milp-cover", "--no-virtual"});
  ok &= expect_error(conflicting_milp_alias, "conflicts",
                     "milp-cover conflicts with no-virtual");

  auto zero_rounds = positional;
  zero_rounds.insert(zero_rounds.end(),
                     {"--rule-opt-max-rounds", "0"});
  ok &= expect_error(zero_rounds, "must be positive", "zero rounds");

  auto ignored_optimizer_option = positional;
  ignored_optimizer_option.insert(ignored_optimizer_option.end(),
                                  {"--rule-opt-max-clauses", "2"});
  ok &= expect_error(ignored_optimizer_option,
                     "require --rule-method z3-pb or milp-cover",
                     "optimizer option with VN strategy");

  auto cover_option_with_z3 = positional;
  cover_option_with_z3.insert(
      cover_option_with_z3.end(),
      {"--rule-method", "z3-pb", "--rule-cover-max-terms", "10"});
  ok &= expect_error(cover_option_with_z3, "requires --rule-method milp-cover",
                     "cover option with z3-pb");

  auto cover_cost_with_z3 = positional;
  cover_cost_with_z3.insert(
      cover_cost_with_z3.end(),
      {"--rule-method", "z3-pb", "--rule-cover-third-objective", "none"});
  ok &= expect_error(cover_cost_with_z3,
                     "requires --rule-method milp-cover",
                     "cover cost with z3-pb");

  auto cover_phase3_with_z3 = positional;
  cover_phase3_with_z3.insert(
      cover_phase3_with_z3.end(),
      {"--rule-method", "z3-pb", "--rule-cover-phase3-timeout-ms", "1"});
  ok &= expect_error(cover_phase3_with_z3,
                     "requires --rule-method milp-cover",
                     "cover phase3 timeout with z3-pb");

  auto invalid_cover_cost = positional;
  invalid_cover_cost.insert(
      invalid_cover_cost.end(),
      {"--rule-method", "milp-cover", "--rule-cover-third-objective",
       "area-magic"});
  ok &= expect_error(invalid_cover_cost,
                     "expected none or unique-inverters",
                     "invalid cover cost");

  auto z3_option_with_milp = positional;
  z3_option_with_milp.insert(
      z3_option_with_milp.end(),
      {"--rule-method", "milp-cover", "--rule-opt-max-rounds", "7"});
  ok &= expect_error(z3_option_with_milp, "apply only to z3-pb",
                     "z3-only option with milp-cover");

  auto z3_cex_option_with_milp = positional;
  z3_cex_option_with_milp.insert(
      z3_cex_option_with_milp.end(),
      {"--rule-method", "milp-cover", "--rule-opt-cex-batch", "7"});
  ok &= expect_error(z3_cex_option_with_milp, "apply only to z3-pb",
                     "z3 cex option with milp-cover");

  auto zero_cover_terms = positional;
  zero_cover_terms.insert(
      zero_cover_terms.end(),
      {"--rule-method", "milp-cover", "--rule-cover-max-terms", "0"});
  ok &= expect_error(zero_cover_terms, "must be positive",
                     "zero cover term cap");

  if (!ok) {
    return EXIT_FAILURE;
  }
  std::cout << "rule_method_cli_tests PASS\n";
  return EXIT_SUCCESS;
}
