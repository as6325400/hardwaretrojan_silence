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

bool expect_formal_options(std::vector<std::string> args) {
  AppOptions options;
  std::string error;
  const ParseStatus status = parse(std::move(args), &options, &error);
  if (status != ParseStatus::ok ||
      options.rule_method != RuleMethod::z3_pb ||
      !options.rule_formal_refine ||
      options.rule_formal_timeout_ms != 0 ||
      options.rule_formal_max_rounds != 3 ||
      options.rule_formal_cex_batch != 4) {
    std::cerr << "formal option parse failed: status="
              << static_cast<int>(status) << " error=" << error << "\n";
    return false;
  }
  return true;
}

bool expect_default_repair_options(std::vector<std::string> args,
                                   const std::string& expected_abc_bin) {
  AppOptions options;
  std::string error;
  const ParseStatus status = parse(std::move(args), &options, &error);
  if (status != ParseStatus::ok ||
      options.repair_method != RepairMethod::legacy ||
      options.dac25_selector_timeout_ms != 30000 ||
      options.dac25_candidate_limit != 64 ||
      options.dac25_max_targets != 3 ||
      options.dac25_max_sets != 16 ||
      options.dac25_runeco_timeout_s != 60 ||
      options.dac25_abc_bin != expected_abc_bin) {
    std::cerr << "default repair option parse failed: status="
              << static_cast<int>(status)
              << " method=" << repair_method_name(options.repair_method)
              << " abc=" << options.dac25_abc_bin
              << " error=" << error << "\n";
    return false;
  }
  return true;
}

bool expect_dac25_options(std::vector<std::string> args) {
  AppOptions options;
  std::string error;
  const ParseStatus status = parse(std::move(args), &options, &error);
  if (status != ParseStatus::ok ||
      options.repair_method != RepairMethod::dac25_inspired ||
      options.dac25_selector_timeout_ms != 45000 ||
      options.dac25_candidate_limit != 80 ||
      options.dac25_max_targets != 4 ||
      options.dac25_max_sets != 20 ||
      options.dac25_runeco_timeout_s != 90 ||
      options.dac25_abc_bin != "/tmp/custom-abc") {
    std::cerr << "DAC25 option parse failed: status="
              << static_cast<int>(status)
              << " method=" << repair_method_name(options.repair_method)
              << " error=" << error << "\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  const std::vector<std::string> positional = {"test_cli", "g", "t", "gt"};
  const char* original_abc_bin_value = std::getenv("ABC_BIN");
  const bool had_original_abc_bin = original_abc_bin_value != nullptr;
  const std::string original_abc_bin =
      original_abc_bin_value ? original_abc_bin_value : "";
  unsetenv("ABC_BIN");

  bool ok = true;
  ok &= expect_method(positional, RuleMethod::vn_retrain, "default");
  ok &= expect_default_repair_options(positional, "abc");

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

  auto formal_z3 = positional;
  formal_z3.insert(formal_z3.end(),
                   {"--rule-method", "z3-pb",
                    "--rule-formal-refine",
                    "--rule-formal-timeout-ms", "0",
                    "--rule-formal-max-rounds", "3",
                    "--rule-formal-cex-batch", "4"});
  ok &= expect_formal_options(formal_z3);

  auto explicit_dac25 = positional;
  explicit_dac25.insert(explicit_dac25.end(),
                        {"--repair-method", "dac25-inspired"});
  {
    AppOptions options;
    std::string error;
    const ParseStatus status = parse(explicit_dac25, &options, &error);
    if (status != ParseStatus::ok ||
        options.repair_method != RepairMethod::dac25_inspired ||
        std::string(repair_method_name(options.repair_method)) !=
            "dac25-inspired") {
      std::cerr << "explicit DAC25 repair method failed: status="
                << static_cast<int>(status) << " error=" << error << "\n";
      ok = false;
    }
  }

  auto configured_dac25 = positional;
  configured_dac25.insert(
      configured_dac25.end(),
      {"--repair-method", "dac25-inspired",
       "--dac25-selector-timeout-ms", "45000",
       "--dac25-candidate-limit", "80",
       "--dac25-max-targets", "4",
       "--dac25-max-sets", "20",
       "--dac25-runeco-timeout-s", "90",
       "--dac25-abc-bin", "/tmp/custom-abc"});
  ok &= expect_dac25_options(configured_dac25);

  setenv("ABC_BIN", "/tmp/env-abc", 1);
  ok &= expect_default_repair_options(positional, "/tmp/env-abc");
  ok &= expect_dac25_options(configured_dac25);
  unsetenv("ABC_BIN");

  auto invalid_repair = positional;
  invalid_repair.insert(invalid_repair.end(),
                        {"--repair-method", "dac25"});
  ok &= expect_error(invalid_repair, "Invalid --repair-method",
                     "invalid repair method");

  const std::vector<std::vector<std::string>> dac25_only_options = {
      {"--dac25-selector-timeout-ms", "1"},
      {"--dac25-candidate-limit", "8"},
      {"--dac25-max-targets", "2"},
      {"--dac25-max-sets", "4"},
      {"--dac25-runeco-timeout-s", "1"},
      {"--dac25-abc-bin", "/tmp/abc"},
  };
  for (const auto& dac25_option : dac25_only_options) {
    auto dac25_knob_with_legacy = positional;
    dac25_knob_with_legacy.insert(dac25_knob_with_legacy.end(),
                                  dac25_option.begin(), dac25_option.end());
    ok &= expect_error(dac25_knob_with_legacy,
                       "require --repair-method dac25-inspired",
                       dac25_option.front().c_str());
  }

  auto zero_selector_timeout = explicit_dac25;
  zero_selector_timeout.insert(zero_selector_timeout.end(),
                               {"--dac25-selector-timeout-ms", "0"});
  ok &= expect_error(zero_selector_timeout, "must be positive",
                     "zero DAC25 selector timeout");

  auto zero_candidate_limit = explicit_dac25;
  zero_candidate_limit.insert(zero_candidate_limit.end(),
                              {"--dac25-candidate-limit", "0"});
  ok &= expect_error(zero_candidate_limit, "must be positive",
                     "zero DAC25 candidate limit");

  auto zero_max_targets = explicit_dac25;
  zero_max_targets.insert(zero_max_targets.end(),
                          {"--dac25-max-targets", "0"});
  ok &= expect_error(zero_max_targets, "must be positive",
                     "zero DAC25 max targets");

  auto too_many_targets = explicit_dac25;
  too_many_targets.insert(too_many_targets.end(),
                          {"--dac25-candidate-limit", "2",
                           "--dac25-max-targets", "3"});
  ok &= expect_error(too_many_targets, "cannot exceed",
                     "DAC25 max targets above candidate limit");

  auto zero_max_sets = explicit_dac25;
  zero_max_sets.insert(zero_max_sets.end(), {"--dac25-max-sets", "0"});
  ok &= expect_error(zero_max_sets, "must be positive",
                     "zero DAC25 max sets");

  auto zero_runeco_timeout = explicit_dac25;
  zero_runeco_timeout.insert(zero_runeco_timeout.end(),
                             {"--dac25-runeco-timeout-s", "0"});
  ok &= expect_error(zero_runeco_timeout, "must be positive",
                     "zero DAC25 runeco timeout");

  auto empty_dac25_abc = explicit_dac25;
  empty_dac25_abc.insert(empty_dac25_abc.end(),
                         {"--dac25-abc-bin", ""});
  ok &= expect_error(empty_dac25_abc, "must not be empty",
                     "empty DAC25 ABC path");

  auto conflicting_z3_alias = positional;
  conflicting_z3_alias.insert(conflicting_z3_alias.end(),
                              {"--rule-method", "z3-pb", "--no-virtual"});
  ok &= expect_error(conflicting_z3_alias, "conflicts",
                     "z3-pb conflicts with no-virtual");

  auto zero_rounds = positional;
  zero_rounds.insert(zero_rounds.end(),
                     {"--rule-opt-max-rounds", "0"});
  ok &= expect_error(zero_rounds, "must be positive", "zero rounds");

  auto ignored_optimizer_option = positional;
  ignored_optimizer_option.insert(ignored_optimizer_option.end(),
                                  {"--rule-opt-max-clauses", "2"});
  ok &= expect_error(ignored_optimizer_option,
                     "require --rule-method z3-pb",
                     "optimizer option with VN strategy");

  auto formal_with_vn = positional;
  formal_with_vn.push_back("--rule-formal-refine");
  ok &= expect_error(formal_with_vn,
                     "requires --rule-method z3-pb",
                     "formal refinement with VN");

  auto formal_knob_without_flag = positional;
  formal_knob_without_flag.insert(
      formal_knob_without_flag.end(),
      {"--rule-method", "z3-pb", "--rule-formal-max-rounds", "2"});
  ok &= expect_error(formal_knob_without_flag,
                     "require --rule-formal-refine",
                     "formal knob without flag");

  auto zero_formal_rounds = positional;
  zero_formal_rounds.insert(
      zero_formal_rounds.end(),
      {"--rule-method", "z3-pb", "--rule-formal-refine",
       "--rule-formal-max-rounds", "0"});
  ok &= expect_error(zero_formal_rounds, "must be positive",
                     "zero formal rounds");

  auto oversized_formal_batch = positional;
  oversized_formal_batch.insert(
      oversized_formal_batch.end(),
      {"--rule-method", "z3-pb", "--rule-formal-refine",
       "--rule-formal-cex-batch", "6"});
  ok &= expect_error(oversized_formal_batch, "between 1 and 5",
                     "oversized formal batch");

  if (had_original_abc_bin) {
    setenv("ABC_BIN", original_abc_bin.c_str(), 1);
  } else {
    unsetenv("ABC_BIN");
  }

  if (!ok) {
    return EXIT_FAILURE;
  }
  std::cout << "rule_method_cli_tests PASS\n";
  return EXIT_SUCCESS;
}
