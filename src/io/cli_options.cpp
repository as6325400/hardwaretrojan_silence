#include "cli_options.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

bool parse_size_arg(const std::string& text, std::size_t* out) {
  if (text.empty()) {
    return false;
  }
  char* end = nullptr;
  unsigned long long value = std::strtoull(text.c_str(), &end, 10);
  if (!end || *end != '\0') {
    return false;
  }
  *out = static_cast<std::size_t>(value);
  return true;
}

bool parse_double_arg(const std::string& text, double* out) {
  if (text.empty()) {
    return false;
  }
  char* end = nullptr;
  double value = std::strtod(text.c_str(), &end);
  if (!end || *end != '\0') {
    return false;
  }
  *out = value;
  return true;
}

bool is_help_arg(const char* arg) {
  return arg && std::string(arg) == "--help";
}

}  // namespace

void print_usage(const char* prog) {
  const char* name = prog ? prog : "main";
  std::cout << "Usage: " << name
            << " <golden_bench> <trojan_bench> [output_bench]"
               " [--patterns N] [--depth N] [--eval N] [--neg-ratio N]"
               " [--mine-rounds N] [--mine-max N]"
               " [--p1-trigger X] [--p1-notrigger Y] [--include-pi] [--no-filter]"
               " [--force-split] [--no-strict]\n";
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

  for (int i = 1; i < argc; ++i) {
    if (is_help_arg(argv[i])) {
      return ParseStatus::help;
    }
  }

  if (argc < 3) {
    if (error) {
      *error = "Missing required bench paths";
    }
    return ParseStatus::error;
  }

  out->golden_path = argv[1];
  out->trojan_path = argv[2];

  std::string arg_error;

  for (int i = 3; i < argc; ++i) {
    std::string arg = argv[i];

    auto parse_option = [&](const std::string& name, std::size_t* target) -> bool {
      if (arg == name) {
        if (i + 1 >= argc) {
          arg_error = "Missing value for " + name;
          return true;
        }
        if (!parse_size_arg(argv[++i], target)) {
          arg_error = "Invalid value for " + name;
          return true;
        }
        return true;
      }
      const std::string prefix = name + "=";
      if (arg.rfind(prefix, 0) == 0) {
        if (!parse_size_arg(arg.substr(prefix.size()), target)) {
          arg_error = "Invalid value for " + name;
        }
        return true;
      }
      return false;
    };

    auto parse_double_option = [&](const std::string& name, double* target) -> bool {
      if (arg == name) {
        if (i + 1 >= argc) {
          arg_error = "Missing value for " + name;
          return true;
        }
        if (!parse_double_arg(argv[++i], target)) {
          arg_error = "Invalid value for " + name;
          return true;
        }
        return true;
      }
      const std::string prefix = name + "=";
      if (arg.rfind(prefix, 0) == 0) {
        if (!parse_double_arg(arg.substr(prefix.size()), target)) {
          arg_error = "Invalid value for " + name;
        }
        return true;
      }
      return false;
    };

    if (parse_option("--patterns", &out->pattern_count)) {
      if (!arg_error.empty()) {
        break;
      }
      continue;
    }
    if (parse_option("--depth", &out->max_depth)) {
      if (!arg_error.empty()) {
        break;
      }
      continue;
    }
    if (parse_option("--eval", &out->eval_count)) {
      if (!arg_error.empty()) {
        break;
      }
      continue;
    }
    if (parse_option("--neg-ratio", &out->neg_ratio)) {
      if (!arg_error.empty()) {
        break;
      }
      continue;
    }
    if (parse_option("--mine-rounds", &out->mine_rounds)) {
      if (!arg_error.empty()) {
        break;
      }
      continue;
    }
    if (parse_option("--mine-max", &out->mine_max)) {
      if (!arg_error.empty()) {
        break;
      }
      continue;
    }
    if (parse_double_option("--p1-trigger", &out->p1_trigger_threshold)) {
      if (!arg_error.empty()) {
        break;
      }
      continue;
    }
    if (parse_double_option("--p1-notrigger", &out->p1_notrigger_threshold)) {
      if (!arg_error.empty()) {
        break;
      }
      continue;
    }
    if (arg == "--include-pi") {
      out->include_pi = true;
      continue;
    }
    if (arg == "--no-filter" || arg == "--all-gates") {
      out->no_filter = true;
      continue;
    }
    if (arg == "--force-split") {
      out->force_split = true;
      continue;
    }
    if (arg == "--no-strict") {
      out->strict_retry = false;
      continue;
    }
    if (arg == "--output") {
      if (i + 1 >= argc) {
        arg_error = "Missing value for --output";
        break;
      }
      out->output_path = argv[++i];
      continue;
    }
    if (!arg.empty() && arg[0] != '-' && out->output_path.empty()) {
      out->output_path = arg;
      continue;
    }

    arg_error = "Unknown argument: " + arg;
    break;
  }

  if (!arg_error.empty()) {
    if (error) {
      *error = arg_error;
    }
    return ParseStatus::error;
  }

  if (out->p1_trigger_threshold < 0.0 || out->p1_trigger_threshold > 1.0 ||
      out->p1_notrigger_threshold < 0.0 || out->p1_notrigger_threshold > 1.0) {
    if (error) {
      *error = "p1 thresholds must be within [0, 1]";
    }
    return ParseStatus::error;
  }

  return ParseStatus::ok;
}
