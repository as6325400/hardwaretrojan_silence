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

  auto future_method = positional;
  future_method.insert(future_method.end(), {"--rule-method", "z3-pb"});
  ok &= expect_error(future_method, "Invalid --rule-method",
                     "future method rejected");

  if (!ok) {
    return EXIT_FAILURE;
  }
  std::cout << "rule_method_cli_tests PASS\n";
  return EXIT_SUCCESS;
}
