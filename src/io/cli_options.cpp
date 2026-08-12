#include "cli_options.hpp"

#include <cstdlib>
#include <iostream>

#include "../../extern/CLI11/CLI11.hpp"

const char* rule_method_name(RuleMethod method) {
  switch (method) {
    case RuleMethod::vn_retrain:
      return "vn-retrain";
    case RuleMethod::dt:
      return "dt";
    case RuleMethod::z3_pb:
      return "z3-pb";
  }
  return "unknown";
}

const char* repair_method_name(RepairMethod method) {
  switch (method) {
    case RepairMethod::legacy:
      return "legacy";
    case RepairMethod::dac25_inspired:
      return "dac25-inspired";
  }
  return "unknown";
}

void print_usage(const char* prog) {
  const char* name = prog ? prog : "main";
  std::cout << "Usage: " << name
            << " <golden_bench> <trojan_bench> <groundtruth_log> [output_bench]"
               " [--depth N] [--neg-ratio N]"
               " [--mine-rounds N] [--mine-max N]"
               " [--rule-method vn-retrain|dt|z3-pb]"
               " [--rule-opt-timeout-ms N] [--rule-opt-max-rounds N]"
               " [--rule-opt-cex-batch N] [--rule-opt-max-clauses N]"
               " [--rule-opt-max-literals N]"
               " [--rule-formal-refine] [--rule-formal-timeout-ms N]"
               " [--rule-formal-max-rounds N] [--rule-formal-cex-batch N]"
               " [--repair-method legacy|dac25-inspired]"
               " [--dac25-selector-timeout-ms N]"
               " [--dac25-candidate-limit N] [--dac25-max-targets N]"
               " [--dac25-max-sets N] [--dac25-runeco-timeout-s N]"
               " [--dac25-abc-bin PATH]"
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
  if (const char* abc_bin = std::getenv("ABC_BIN");
      abc_bin != nullptr && abc_bin[0] != '\0') {
    out->dac25_abc_bin = abc_bin;
  }

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
                     "Rule synthesis method: vn-retrain, dt, or z3-pb");
  CLI::Option* opt_timeout =
      app.add_option("--rule-opt-timeout-ms", out->rule_opt_timeout_ms,
                     "Shared Z3-PB wall-clock budget in milliseconds");
  CLI::Option* opt_rounds =
      app.add_option("--rule-opt-max-rounds", out->rule_opt_max_rounds,
                     "Maximum Z3-PB CEGIS checks");
  CLI::Option* opt_cex =
      app.add_option("--rule-opt-cex-batch", out->rule_opt_cex_batch,
                     "Counterexample signatures added per Z3-PB round");
  CLI::Option* opt_clauses =
      app.add_option("--rule-opt-max-clauses", out->rule_opt_max_clauses,
                     "Z3-PB DNF clause cap (0 uses baseline rule count)");
  CLI::Option* opt_literals =
      app.add_option("--rule-opt-max-literals", out->rule_opt_max_literals,
                     "Z3-PB literals per clause cap (0 uses baseline maximum)");
  CLI::Option* formal_refine =
      app.add_flag("--rule-formal-refine", out->rule_formal_refine,
                   "Refine learned rules with SAT FN/FP counterexamples");
  CLI::Option* formal_timeout =
      app.add_option("--rule-formal-timeout-ms",
                     out->rule_formal_timeout_ms,
                     "SAT rule-miter soft wall-clock budget");
  CLI::Option* formal_rounds =
      app.add_option("--rule-formal-max-rounds",
                     out->rule_formal_max_rounds,
                     "Maximum SAT rule-refinement rebuilds");
  CLI::Option* formal_batch =
      app.add_option("--rule-formal-cex-batch",
                     out->rule_formal_cex_batch,
                     "SAT rule counterexamples returned per check (1-5)");
  std::string repair_method = "legacy";
  app.add_option("--repair-method", repair_method,
                 "Repair method: legacy or dac25-inspired");
  CLI::Option* dac25_selector_timeout =
      app.add_option("--dac25-selector-timeout-ms",
                     out->dac25_selector_timeout_ms,
                     "DAC25-inspired selector timeout in milliseconds");
  CLI::Option* dac25_candidate_limit =
      app.add_option("--dac25-candidate-limit",
                     out->dac25_candidate_limit,
                     "Maximum DAC25-inspired rectification candidates");
  CLI::Option* dac25_max_targets =
      app.add_option("--dac25-max-targets",
                     out->dac25_max_targets,
                     "Maximum targets in a DAC25-inspired candidate set");
  CLI::Option* dac25_max_sets =
      app.add_option("--dac25-max-sets",
                     out->dac25_max_sets,
                     "Maximum feasible DAC25-inspired sets to retain");
  CLI::Option* dac25_runeco_timeout =
      app.add_option("--dac25-runeco-timeout-s",
                     out->dac25_runeco_timeout_s,
                     "DAC25-inspired runeco timeout in seconds");
  CLI::Option* dac25_abc_bin =
      app.add_option("--dac25-abc-bin", out->dac25_abc_bin,
                     "ABC executable used by DAC25-inspired runeco");
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
  if (rule_method != "vn-retrain" && rule_method != "dt" &&
      rule_method != "z3-pb") {
    if (error) {
      *error = "Invalid --rule-method '" + rule_method +
               "' (expected vn-retrain, dt, or z3-pb)";
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
  if (rule_method == "dt") {
    out->rule_method = RuleMethod::dt;
  } else if (rule_method == "z3-pb") {
    out->rule_method = RuleMethod::z3_pb;
  } else {
    out->rule_method = RuleMethod::vn_retrain;
  }
  out->no_virtual = out->rule_method == RuleMethod::dt;

  if (repair_method != "legacy" && repair_method != "dac25-inspired") {
    if (error) {
      *error = "Invalid --repair-method '" + repair_method +
               "' (expected legacy or dac25-inspired)";
    }
    return ParseStatus::error;
  }
  out->repair_method = repair_method == "dac25-inspired"
                           ? RepairMethod::dac25_inspired
                           : RepairMethod::legacy;

  const bool dac25_option_used =
      dac25_selector_timeout->count() || dac25_candidate_limit->count() ||
      dac25_max_targets->count() || dac25_max_sets->count() ||
      dac25_runeco_timeout->count() || dac25_abc_bin->count();
  if (out->repair_method != RepairMethod::dac25_inspired &&
      dac25_option_used) {
    if (error) {
      *error = "--dac25-* options require --repair-method dac25-inspired";
    }
    return ParseStatus::error;
  }
  if (out->dac25_selector_timeout_ms == 0) {
    if (error) *error = "--dac25-selector-timeout-ms must be positive";
    return ParseStatus::error;
  }
  if (out->dac25_candidate_limit == 0) {
    if (error) *error = "--dac25-candidate-limit must be positive";
    return ParseStatus::error;
  }
  if (out->dac25_max_targets == 0) {
    if (error) *error = "--dac25-max-targets must be positive";
    return ParseStatus::error;
  }
  if (out->dac25_max_targets > out->dac25_candidate_limit) {
    if (error) {
      *error = "--dac25-max-targets cannot exceed --dac25-candidate-limit";
    }
    return ParseStatus::error;
  }
  if (out->dac25_max_sets == 0) {
    if (error) *error = "--dac25-max-sets must be positive";
    return ParseStatus::error;
  }
  if (out->dac25_runeco_timeout_s == 0) {
    if (error) *error = "--dac25-runeco-timeout-s must be positive";
    return ParseStatus::error;
  }
  if (out->dac25_abc_bin.empty()) {
    if (error) *error = "--dac25-abc-bin must not be empty";
    return ParseStatus::error;
  }

  if (out->rule_opt_max_rounds == 0) {
    if (error) *error = "--rule-opt-max-rounds must be positive";
    return ParseStatus::error;
  }
  if (out->rule_opt_cex_batch == 0) {
    if (error) *error = "--rule-opt-cex-batch must be positive";
    return ParseStatus::error;
  }
  if (out->rule_method != RuleMethod::z3_pb &&
      (opt_timeout->count() || opt_rounds->count() || opt_cex->count() ||
       opt_clauses->count() || opt_literals->count())) {
    if (error) {
      *error = "--rule-opt-* options require --rule-method z3-pb";
    }
    return ParseStatus::error;
  }

  const bool formal_option_used =
      formal_refine->count() || formal_timeout->count() ||
      formal_rounds->count() || formal_batch->count();
  if (formal_option_used && out->rule_method != RuleMethod::z3_pb) {
    if (error) {
      *error = "rule formal refinement requires --rule-method z3-pb";
    }
    return ParseStatus::error;
  }
  if (!out->rule_formal_refine &&
      (formal_timeout->count() || formal_rounds->count() ||
       formal_batch->count())) {
    if (error) {
      *error =
          "rule formal refinement options require --rule-formal-refine";
    }
    return ParseStatus::error;
  }
  if (out->rule_formal_max_rounds == 0) {
    if (error) *error = "--rule-formal-max-rounds must be positive";
    return ParseStatus::error;
  }
  if (out->rule_formal_cex_batch == 0 ||
      out->rule_formal_cex_batch > 5) {
    if (error) *error = "--rule-formal-cex-batch must be between 1 and 5";
    return ParseStatus::error;
  }

  return ParseStatus::ok;
}
