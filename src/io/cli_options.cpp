#include "cli_options.hpp"

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
    case RuleMethod::milp_cover:
      return "milp-cover";
  }
  return "unknown";
}

void print_usage(const char* prog) {
  const char* name = prog ? prog : "main";
  std::cout << "Usage: " << name
            << " <golden_bench> <trojan_bench> <groundtruth_log> [output_bench]"
               " [--depth N] [--neg-ratio N]"
               " [--mine-rounds N] [--mine-max N]"
               " [--rule-method vn-retrain|dt|z3-pb|milp-cover]"
               " [--rule-opt-timeout-ms N] [--rule-opt-max-rounds N]"
               " [--rule-opt-cex-batch N] [--rule-opt-max-clauses N]"
               " [--rule-opt-max-literals N] [--rule-cover-max-terms N]"
               " [--rule-cover-third-objective none|unique-inverters]"
               " [--rule-cover-phase3-timeout-ms N]"
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
                     "Rule synthesis method: vn-retrain, dt, z3-pb, or "
                     "milp-cover");
  CLI::Option* opt_timeout =
      app.add_option("--rule-opt-timeout-ms", out->rule_opt_timeout_ms,
                     "Shared optimizer wall-clock budget in milliseconds");
  CLI::Option* opt_rounds =
      app.add_option("--rule-opt-max-rounds", out->rule_opt_max_rounds,
                     "Maximum Z3-PB CEGIS checks");
  CLI::Option* opt_cex =
      app.add_option("--rule-opt-cex-batch", out->rule_opt_cex_batch,
                     "Counterexample signatures added per Z3-PB round");
  CLI::Option* opt_clauses =
      app.add_option("--rule-opt-max-clauses", out->rule_opt_max_clauses,
                     "Optimizer DNF clause cap (0 uses baseline rule count)");
  CLI::Option* opt_literals =
      app.add_option("--rule-opt-max-literals", out->rule_opt_max_literals,
                     "Optimizer literals per clause cap (0 uses baseline "
                     "maximum)");
  CLI::Option* cover_terms =
      app.add_option("--rule-cover-max-terms", out->rule_cover_max_terms,
                     "MILP cover term-pool cap");
  std::string cover_third_objective = "unique-inverters";
  CLI::Option* cover_third =
      app.add_option("--rule-cover-third-objective", cover_third_objective,
                     "MILP tie-break objective: none or unique-inverters");
  CLI::Option* cover_phase3_timeout =
      app.add_option("--rule-cover-phase3-timeout-ms",
                     out->rule_cover_phase3_timeout_ms,
                     "MILP phase-3 wall-clock sub-budget in milliseconds");
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
      rule_method != "z3-pb" && rule_method != "milp-cover") {
    if (error) {
      *error = "Invalid --rule-method '" + rule_method +
               "' (expected vn-retrain, dt, z3-pb, or milp-cover)";
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
  } else if (rule_method == "milp-cover") {
    out->rule_method = RuleMethod::milp_cover;
  } else {
    out->rule_method = RuleMethod::vn_retrain;
  }
  out->no_virtual = out->rule_method == RuleMethod::dt;

  if (out->rule_opt_max_rounds == 0) {
    if (error) *error = "--rule-opt-max-rounds must be positive";
    return ParseStatus::error;
  }
  if (out->rule_opt_cex_batch == 0) {
    if (error) *error = "--rule-opt-cex-batch must be positive";
    return ParseStatus::error;
  }
  const bool optimizer_method =
      out->rule_method == RuleMethod::z3_pb ||
      out->rule_method == RuleMethod::milp_cover;
  if (!optimizer_method &&
      (opt_timeout->count() || opt_rounds->count() || opt_cex->count() ||
       opt_clauses->count() || opt_literals->count() || cover_terms->count())) {
    if (error) {
      *error =
          "rule optimizer options require --rule-method z3-pb or milp-cover";
    }
    return ParseStatus::error;
  }
  if (out->rule_method == RuleMethod::z3_pb && cover_terms->count()) {
    if (error) {
      *error = "--rule-cover-max-terms requires --rule-method milp-cover";
    }
    return ParseStatus::error;
  }
  if (cover_third_objective != "none" &&
      cover_third_objective != "unique-inverters") {
    if (error) {
      *error = "Invalid --rule-cover-third-objective '" +
               cover_third_objective +
               "' (expected none or unique-inverters)";
    }
    return ParseStatus::error;
  }
  if (out->rule_method != RuleMethod::milp_cover && cover_third->count()) {
    if (error) {
      *error =
          "--rule-cover-third-objective requires --rule-method milp-cover";
    }
    return ParseStatus::error;
  }
  if (out->rule_method != RuleMethod::milp_cover &&
      cover_phase3_timeout->count()) {
    if (error) {
      *error =
          "--rule-cover-phase3-timeout-ms requires --rule-method milp-cover";
    }
    return ParseStatus::error;
  }
  out->rule_cover_minimize_inverters =
      cover_third_objective == "unique-inverters";
  if (out->rule_method == RuleMethod::milp_cover &&
      (opt_rounds->count() || opt_cex->count())) {
    if (error) {
      *error = "--rule-opt-max-rounds and --rule-opt-cex-batch apply only to z3-pb";
    }
    return ParseStatus::error;
  }
  if (out->rule_cover_max_terms == 0) {
    if (error) *error = "--rule-cover-max-terms must be positive";
    return ParseStatus::error;
  }

  return ParseStatus::ok;
}
