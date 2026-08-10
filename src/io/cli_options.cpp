#include "cli_options.hpp"

#include <iostream>

#include "../../extern/CLI11/CLI11.hpp"

const char* rule_method_name(RuleMethod method) {
  switch (method) {
    case RuleMethod::vn_retrain:
      return "vn-retrain";
    case RuleMethod::dt:
      return "dt";
  }
  return "unknown";
}

void print_usage(const char* prog) {
  const char* name = prog ? prog : "main";
  std::cout << "Usage: " << name
            << " <golden_bench> <trojan_bench> <groundtruth_log> [output_bench]"
               " [--depth N] [--neg-ratio N]"
               " [--mine-rounds N] [--mine-max N]"
               " [--rule-method vn-retrain|dt]"
               " [--force-split] [--no-strict] [--no-virtual]\n";
}

ParseStatus parse_cli_options(int argc, char** argv, AppOptions* out, std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out) {
    if (error) {
      *error = "Output options pointer is null";
    }
    return ParseStatus::error;
  }
  *out = AppOptions{};

  CLI::App app{"Hardware trojan silence tool"};
  app.allow_extras(false);

  app.add_option("golden_bench", out->golden_path, "Golden benchmark")
      ->required();
  app.add_option("trojan_bench", out->trojan_path, "Trojan benchmark")
      ->required();
  app.add_option("groundtruth_log", out->groundtruth_path, "Groundtruth log")
      ->required();
  app.add_option("output_bench", out->output_path, "Output benchmark");

  app.add_option("--depth", out->max_depth, "Max tree depth");
  app.add_option("--neg-ratio", out->neg_ratio, "Negative sampling ratio");
  app.add_option("--mine-rounds", out->mine_rounds, "Mining rounds");
  app.add_option("--mine-max", out->mine_max, "Max mining iterations");
  app.add_flag("--include-pi", out->include_pi, "Include primary inputs");
  app.add_flag("--no-filter,--all-gates", out->no_filter, "No gate filtering");
  app.add_flag("--force-split", out->force_split, "Force split in tree");
  CLI::Option* no_virtual_option =
      app.add_flag("--no-virtual", out->no_virtual,
                   "Disable virtual nodes (legacy alias for --rule-method dt)");
  std::string rule_method = "vn-retrain";
  CLI::Option* rule_method_option =
      app.add_option("--rule-method", rule_method,
                     "Rule synthesis method: vn-retrain or dt");
  app.add_option("--output", out->output_path, "Output path (alternative)");

  // --no-strict disables strict_retry (inverted flag)
  bool no_strict = false;
  app.add_flag("--no-strict", no_strict, "Disable strict retry");

  try {
    app.parse(argc, argv);
  } catch (const CLI::CallForHelp&) {
    return ParseStatus::help;
  } catch (const CLI::ParseError& e) {
    if (error) {
      *error = e.what();
    }
    return ParseStatus::error;
  }

  if (no_strict) {
    out->strict_retry = false;
  }

  const bool rule_method_explicit = rule_method_option->count() > 0;
  const bool no_virtual_explicit = no_virtual_option->count() > 0;
  if (rule_method != "vn-retrain" && rule_method != "dt") {
    if (error) {
      *error = "Invalid --rule-method '" + rule_method +
               "' (expected vn-retrain or dt)";
    }
    return ParseStatus::error;
  }
  if (no_virtual_explicit && rule_method_explicit &&
      rule_method != "dt") {
    if (error) {
      *error = "--no-virtual conflicts with --rule-method " + rule_method;
    }
    return ParseStatus::error;
  }
  if (no_virtual_explicit) {
    rule_method = "dt";
  }
  out->rule_method = rule_method == "dt" ? RuleMethod::dt
                                          : RuleMethod::vn_retrain;
  out->no_virtual = out->rule_method == RuleMethod::dt;

  return ParseStatus::ok;
}
