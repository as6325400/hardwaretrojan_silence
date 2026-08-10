#include <z3++.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../extern/nlohmann/json.hpp"
#include "../core/batch_simulator.hpp"
#include "../core/circuit.hpp"
#include "../io/bench_parser.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

constexpr const char* kCaseSchema = "v4-multi-independent-trojan/1";
constexpr const char* kGroundTruthSchema = "v4-groundtruth-1";
constexpr const char* kStableSeedAlgorithm =
    "fnv1a64-case-id-hash-combine-manifest-seed-v1";
constexpr std::size_t kMaxAbcSeedAttemptsPerMask = 8;

std::uint64_t Fnv1a64(const std::string& text) {
  std::uint64_t hash = 14695981039346656037ULL;
  for (unsigned char byte : text) {
    hash ^= static_cast<std::uint64_t>(byte);
    hash *= 1099511628211ULL;
  }
  return hash;
}

struct Options {
  fs::path manifest_path;
  fs::path output_path;
  fs::path negative_output_path;
  std::size_t witnesses_per_mask = 1;
  std::optional<std::size_t> witnesses_per_singleton;
  std::optional<std::size_t> witnesses_per_pair;
  std::optional<std::size_t> witnesses_per_all;
  std::size_t hard_negative_count = 0;
  std::size_t outputs_per_instance = 1;
  std::size_t z3_node_threshold = 20000;
  std::size_t max_random_attempts = 8192;
  std::size_t wall_clock_ms = 10000;
  std::string solver_mode = "auto";
  fs::path abc_bin = "./abc";
  unsigned abc_timeout_ms = 5000;
  unsigned timeout_ms = 30000;
  std::size_t max_encoded_nodes = 1000000;
  std::string mask_set = "auto";
  std::vector<std::string> explicit_masks;
  bool force = false;
  bool plan_only = false;
  bool show_help = false;
};

struct LiteralSpec {
  std::string net;
  bool required_value = false;
};

struct InstanceSpec {
  std::string id;
  std::string individual_path;
  std::string trigger_net;
  std::vector<LiteralSpec> literals;
  std::string victim_net;
  std::string payload_result_net;
  std::vector<std::string> rewritten_fanouts;
};

enum class CircuitSide { kGolden, kCombined };

struct ResolvedLiteral {
  CircuitSide side = CircuitSide::kCombined;
  int node_idx = -1;
  bool required_value = false;
  std::string net;
};

struct ResolvedInstance {
  InstanceSpec spec;
  std::vector<ResolvedLiteral> literals;
  std::optional<int> combined_trigger_idx;
};

struct MaskEnumerationResult {
  std::string status = "unknown";
  std::string activation_status = "unknown";
  std::string observable_status = "unknown";
  std::string reason;
  std::size_t witness_count = 0;
  bool exhausted = false;
};

class ScopedTempDirectory {
 public:
  explicit ScopedTempDirectory(const std::string& prefix) {
    const fs::path base = fs::temp_directory_path();
    const auto stamp = static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    for (std::uint64_t attempt = 0; attempt < 1024; ++attempt) {
      const fs::path candidate =
          base / (prefix + std::to_string(stamp + attempt));
      std::error_code ec;
      if (fs::create_directory(candidate, ec)) {
        path_ = candidate;
        return;
      }
      if (ec && ec != std::errc::file_exists) {
        throw std::runtime_error("failed to create temporary directory: " +
                                 ec.message());
      }
    }
    throw std::runtime_error("failed to allocate a unique temporary directory");
  }

  ScopedTempDirectory(const ScopedTempDirectory&) = delete;
  ScopedTempDirectory& operator=(const ScopedTempDirectory&) = delete;

  ~ScopedTempDirectory() {
    if (!path_.empty()) {
      std::error_code ec;
      fs::remove_all(path_, ec);
    }
  }

  const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

std::string ReadTextFile(const fs::path& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to open text file: " + path.string());
  }
  std::ostringstream contents;
  contents << input.rdbuf();
  if (!input.eof() && input.fail()) {
    throw std::runtime_error("failed while reading text file: " + path.string());
  }
  return contents.str();
}

std::string ShellQuote(const std::string& value) {
  std::string quoted = "'";
  for (char c : value) {
    if (c == '\'') {
      quoted += "'\\''";
    } else {
      quoted.push_back(c);
    }
  }
  quoted.push_back('\'');
  return quoted;
}

std::string AbcQuotePath(const fs::path& path) {
  const std::string value = path.string();
  if (value.find_first_of("\"\r\n") != std::string::npos) {
    throw std::runtime_error("ABC path contains unsupported quoting characters");
  }
  return "\"" + value + "\"";
}

struct AbcCommandResult {
  int exit_code = -1;
  bool timed_out = false;
  std::string output;
  double elapsed_seconds = 0.0;
};

AbcCommandResult RunAbcCommand(const fs::path& abc_bin,
                               const std::string& script,
                               const fs::path& log_path,
                               std::size_t timeout_ms) {
  const auto start = std::chrono::steady_clock::now();
  const std::size_t bounded_timeout = std::max<std::size_t>(1, timeout_ms);
  std::ostringstream duration;
  duration << std::fixed << std::setprecision(3)
           << (static_cast<double>(bounded_timeout) / 1000.0) << 's';
  const std::string command =
      "/usr/bin/timeout --signal=TERM --kill-after=1s " + duration.str() + " " +
      ShellQuote(abc_bin.string()) + " -c " + ShellQuote(script) + " > " +
      ShellQuote(log_path.string()) + " 2>&1";
  const int raw_status = std::system(command.c_str());

  AbcCommandResult result;
  result.elapsed_seconds = std::chrono::duration<double>(
                                     std::chrono::steady_clock::now() - start)
                                     .count();
  if (raw_status == -1) {
    result.exit_code = -1;
  } else if (WIFEXITED(raw_status)) {
    result.exit_code = WEXITSTATUS(raw_status);
  } else if (WIFSIGNALED(raw_status)) {
    result.exit_code = 128 + WTERMSIG(raw_status);
  }
  result.timed_out = result.exit_code == 124 || result.exit_code == 137;
  std::error_code ec;
  if (fs::exists(log_path, ec)) result.output = ReadTextFile(log_path);
  return result;
}

bool WriteExactMaskBlif(const fs::path& base_blif,
                        const fs::path& output_blif,
                        const std::vector<InstanceSpec>& specs,
                        const std::vector<std::string>& pi_order,
                        const std::string& mask,
                        const std::vector<std::string>& blocked_patterns,
                        std::string* error) {
  if (error) error->clear();
  if (mask.size() != specs.size()) {
    if (error) *error = "exact-mask width does not match instance count";
    return false;
  }
  std::ifstream input(base_blif);
  std::ofstream output(output_blif);
  if (!input || !output) {
    if (error) *error = "cannot open ABC BLIF input/output";
    return false;
  }

  bool replaced_outputs = false;
  bool inserted_goal = false;
  std::string line;
  while (std::getline(input, line)) {
    const std::size_t first = line.find_first_not_of(" \t\r");
    const std::string trimmed =
        first == std::string::npos ? std::string() : line.substr(first);
    if (trimmed.rfind(".outputs", 0) == 0) {
      output << ".outputs __gt_atpg_goal\n";
      replaced_outputs = true;
      continue;
    }
    if (trimmed == ".end") {
      for (std::size_t instance_idx = 0; instance_idx < specs.size();
           ++instance_idx) {
        const auto& instance = specs[instance_idx];
        output << ".names";
        std::string cube;
        for (const auto& literal : instance.literals) {
          output << ' ' << literal.net;
          cube.push_back(literal.required_value ? '1' : '0');
        }
        output << " __gt_atpg_trigger_" << instance_idx << "\n"
               << cube << " 1\n";
      }

      output << ".names";
      for (std::size_t instance_idx = 0; instance_idx < specs.size();
           ++instance_idx) {
        output << " __gt_atpg_trigger_" << instance_idx;
      }
      output << " __gt_atpg_exact\n" << mask << " 1\n";

      for (std::size_t block_idx = 0; block_idx < blocked_patterns.size();
           ++block_idx) {
        const std::string& bits = blocked_patterns[block_idx];
        if (bits.size() != pi_order.size() ||
            std::find_if(bits.begin(), bits.end(), [](char bit) {
              return bit != '0' && bit != '1';
            }) != bits.end()) {
          if (error) *error = "invalid ABC blocked PI pattern";
          return false;
        }
        output << ".names";
        for (const auto& pi : pi_order) output << ' ' << pi;
        output << " __gt_atpg_block_" << block_idx << "\n"
               << bits << " 1\n";
      }

      output << ".names miter __gt_atpg_exact";
      for (std::size_t block_idx = 0; block_idx < blocked_patterns.size();
           ++block_idx) {
        output << " __gt_atpg_block_" << block_idx;
      }
      output << " __gt_atpg_goal\n11"
             << std::string(blocked_patterns.size(), '0') << " 1\n.end\n";
      inserted_goal = true;
      continue;
    }
    output << line << '\n';
  }
  if (!input.eof() || !output) {
    if (error) *error = "failed while rewriting exact-mask BLIF";
    return false;
  }
  if (!replaced_outputs || !inserted_goal) {
    if (error) *error = "base BLIF is missing .outputs or .end";
    return false;
  }
  return true;
}

bool ParseNamedAbcCex(const fs::path& cex_path,
                      const std::vector<std::string>& pi_order,
                      std::vector<int>* values,
                      std::string* error) {
  if (error) error->clear();
  if (!values) {
    if (error) *error = "null ABC CEX output vector";
    return false;
  }
  std::unordered_map<std::string, std::size_t> positions;
  for (std::size_t i = 0; i < pi_order.size(); ++i) positions[pi_order[i]] = i;
  values->assign(pi_order.size(), -1);

  std::ifstream input(cex_path);
  if (!input) {
    if (error) *error = "ABC did not produce a CEX file";
    return false;
  }
  std::string line;
  while (std::getline(input, line)) {
    const std::size_t first = line.find_first_not_of(" \t\r");
    if (first == std::string::npos || line[first] == '#') continue;
    const std::size_t equal = line.find('=', first);
    if (equal == std::string::npos) continue;
    std::string name = line.substr(first, equal - first);
    const std::size_t at = name.rfind('@');
    if (at != std::string::npos) name.resize(at);
    const std::size_t value_pos = line.find_first_not_of(" \t", equal + 1);
    if (value_pos == std::string::npos ||
        (line[value_pos] != '0' && line[value_pos] != '1')) {
      if (error) *error = "ABC CEX contains a non-binary PI assignment";
      return false;
    }
    const auto position = positions.find(name);
    if (position == positions.end()) continue;
    const int bit = line[value_pos] == '1' ? 1 : 0;
    int& stored = (*values)[position->second];
    if (stored != -1 && stored != bit) {
      if (error) *error = "ABC CEX repeats a PI with conflicting values";
      return false;
    }
    stored = bit;
  }
  for (std::size_t i = 0; i < values->size(); ++i) {
    if ((*values)[i] == -1) {
      if (error) *error = "ABC CEX is missing PI " + pi_order[i];
      return false;
    }
  }
  return true;
}

[[maybe_unused]] bool ParseAbcCecInputPattern(const std::string& output,
                             const std::vector<std::string>& pi_order,
                             std::vector<int>* values,
                             std::string* error) {
  if (error) error->clear();
  if (!values) {
    if (error) *error = "null ABC CEC output vector";
    return false;
  }
  const std::size_t marker = output.rfind("Input pattern:");
  if (marker == std::string::npos) {
    if (error) *error = "ABC CEC output has no scalar Input pattern section";
    return false;
  }
  const std::size_t begin = marker + std::string("Input pattern:").size();
  const std::size_t end = output.find('\n', begin);
  const std::string assignments =
      output.substr(begin, end == std::string::npos ? std::string::npos
                                                    : end - begin);
  std::unordered_map<std::string, std::size_t> positions;
  for (std::size_t i = 0; i < pi_order.size(); ++i) positions[pi_order[i]] = i;
  values->assign(pi_order.size(), -1);
  std::istringstream tokens(assignments);
  std::string token;
  while (tokens >> token) {
    const std::size_t equal = token.rfind('=');
    if (equal == std::string::npos || equal + 1 >= token.size()) continue;
    const std::string name = token.substr(0, equal);
    const char raw_value = token[equal + 1];
    if (raw_value != '0' && raw_value != '1') continue;
    const auto position = positions.find(name);
    if (position != positions.end()) {
      (*values)[position->second] = raw_value == '1' ? 1 : 0;
    }
  }
  for (std::size_t i = 0; i < values->size(); ++i) {
    if ((*values)[i] == -1) {
      if (error) *error = "ABC CEC Input pattern is missing PI " + pi_order[i];
      return false;
    }
  }
  return true;
}

[[maybe_unused]] bool ParseAbcCecInputSection(const std::string& output,
                             const std::vector<std::string>& pi_order,
                             std::vector<int>* values,
                             std::string* error) {
  if (error) error->clear();
  if (!values) {
    if (error) *error = "null ABC CEC INPUT output vector";
    return false;
  }
  const std::size_t marker = output.find("INPUT:");
  if (marker == std::string::npos) {
    if (error) *error = "ABC CEC output has no INPUT section";
    return false;
  }
  const std::size_t begin = marker + std::string("INPUT:").size();
  const std::size_t end = output.find(".  OUTPUT:", begin);
  if (end == std::string::npos) {
    if (error) *error = "ABC CEC INPUT section has no OUTPUT delimiter";
    return false;
  }
  std::unordered_map<std::string, std::size_t> positions;
  for (std::size_t i = 0; i < pi_order.size(); ++i) positions[pi_order[i]] = i;
  values->assign(pi_order.size(), -1);
  std::istringstream entries(output.substr(begin, end - begin));
  std::string entry;
  while (std::getline(entries, entry, ',')) {
    const std::size_t equal = entry.find('=');
    if (equal == std::string::npos) continue;
    const std::size_t name_begin = entry.find_first_not_of(" \t\r\n");
    const std::size_t name_end = entry.find_last_not_of(" \t", equal - 1);
    if (name_begin == std::string::npos || name_end == std::string::npos ||
        name_end < name_begin) {
      continue;
    }
    const std::string name = entry.substr(name_begin, name_end - name_begin + 1);
    const auto position = positions.find(name);
    if (position == positions.end()) continue;
    const std::string encoded = entry.substr(equal + 1);
    (*values)[position->second] =
        encoded.find("1'h1") != std::string::npos ? 1 : 0;
  }
  for (std::size_t i = 0; i < values->size(); ++i) {
    if ((*values)[i] == -1) {
      if (error) *error = "ABC CEC INPUT section is missing PI " + pi_order[i];
      return false;
    }
  }
  return true;
}

struct AbcAtpgResult {
  std::string status = "error";
  std::string reason;
  std::vector<int> values;
  int exit_code = -1;
  double elapsed_seconds = 0.0;
};

struct AbcCecResult {
  std::string status = "error";
  std::string reason;
  std::string seed_status = "not_run";
  std::string seed_reason;
  std::vector<int> values;
  int exit_code = -1;
  int seed_exit_code = -1;
  std::size_t invocation_count = 0;
  std::size_t timeout_count = 0;
  double classification_seconds = 0.0;
  double seed_seconds = 0.0;
  double elapsed_seconds = 0.0;
};

AbcCecResult RunAbcIndividualCec(const fs::path& abc_bin,
                                 const fs::path& temp_dir,
                                 const fs::path& golden_path,
                                 const fs::path& individual_path,
                                 const std::vector<std::string>& pi_order,
                                 std::size_t instance_idx,
                                 std::size_t timeout_ms) {
  AbcCecResult result;
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_ms);
  const fs::path cex =
      temp_dir / ("individual_" + std::to_string(instance_idx) + ".cex");
  const fs::path classification_log =
      temp_dir /
      ("individual_" + std::to_string(instance_idx) + "_cec.log");
  const std::string classification_script =
      "cec " + AbcQuotePath(golden_path) + " " +
      AbcQuotePath(individual_path);
  const AbcCommandResult classification = RunAbcCommand(
      abc_bin, classification_script, classification_log, timeout_ms);
  ++result.invocation_count;
  result.exit_code = classification.exit_code;
  result.classification_seconds = classification.elapsed_seconds;
  result.elapsed_seconds = classification.elapsed_seconds;
  if (classification.timed_out) {
    result.status = "timeout";
    result.reason = "ABC individual CEC exceeded its bounded timeout";
    ++result.timeout_count;
    return result;
  }
  if (classification.output.find("Networks are equivalent") !=
      std::string::npos) {
    result.status = "equivalent";
    result.seed_status = "not_applicable";
    return result;
  }
  if (classification.output.find("Networks are NOT EQUIVALENT") ==
      std::string::npos) {
    result.status = "error";
    result.reason = "ABC individual CEC returned no equivalence result (exit " +
                    std::to_string(classification.exit_code) + ")";
    return result;
  }

  // ABC's `cec` reliably classifies the pair, but in some builds it consumes
  // the network before a following `write_cex`.  Rebuild an explicit miter and
  // use `dsat` solely to obtain a complete named PI assignment.
  result.status = "not_equivalent";
  const auto now = std::chrono::steady_clock::now();
  if (now >= deadline) {
    result.seed_status = "timeout";
    result.seed_reason =
        "no per-instance budget remains to extract the individual CEX";
    ++result.timeout_count;
    return result;
  }
  const std::size_t remaining_ms = std::max<std::size_t>(
      1, static_cast<std::size_t>(
             std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                                    now)
                 .count()));
  const fs::path seed_log =
      temp_dir /
      ("individual_" + std::to_string(instance_idx) + "_seed.log");
  const std::string seed_script =
      "miter " + AbcQuotePath(golden_path) + " " +
      AbcQuotePath(individual_path) +
      "; strash; dsat; write_cex -n " + AbcQuotePath(cex);
  const AbcCommandResult seed =
      RunAbcCommand(abc_bin, seed_script, seed_log, remaining_ms);
  ++result.invocation_count;
  result.seed_exit_code = seed.exit_code;
  result.seed_seconds = seed.elapsed_seconds;
  result.elapsed_seconds += seed.elapsed_seconds;
  if (seed.timed_out) {
    result.seed_status = "timeout";
    result.seed_reason =
        "ABC individual-miter dsat exceeded its bounded timeout";
    ++result.timeout_count;
    return result;
  }
  if (seed.output.find("UNSATISFIABLE") != std::string::npos) {
    result.seed_status = "unsat";
    result.seed_reason =
        "ABC individual-miter dsat contradicted the non-equivalent CEC result";
    return result;
  }
  if (seed.output.find("SATISFIABLE") == std::string::npos) {
    result.seed_status = "error";
    result.seed_reason =
        "ABC individual-miter dsat returned no SAT result (exit " +
        std::to_string(seed.exit_code) + ")";
    return result;
  }
  if (!ParseNamedAbcCex(cex, pi_order, &result.values,
                        &result.seed_reason)) {
    result.seed_status = "error";
    return result;
  }
  result.seed_status = "sat";
  return result;
}

AbcAtpgResult SolveAbcExactMask(
    const fs::path& abc_bin,
    const fs::path& temp_dir,
    const fs::path& base_blif,
    const std::vector<InstanceSpec>& specs,
    const std::vector<std::string>& pi_order,
    const std::string& mask,
    const std::vector<std::string>& blocked_patterns,
    std::size_t invocation,
    std::size_t timeout_ms) {
  AbcAtpgResult result;
  const fs::path conditioned =
      temp_dir / ("conditioned_" + mask + "_" +
                  std::to_string(invocation) + ".blif");
  const fs::path cex = temp_dir / ("conditioned_" + mask + "_" +
                                  std::to_string(invocation) + ".cex");
  const fs::path log = temp_dir / ("conditioned_" + mask + "_" +
                                  std::to_string(invocation) + ".log");
  if (!WriteExactMaskBlif(base_blif, conditioned, specs, pi_order, mask,
                          blocked_patterns, &result.reason)) {
    return result;
  }
  const std::string script =
      "read_blif " + AbcQuotePath(conditioned) +
      "; strash; dsat; write_cex -n " + AbcQuotePath(cex);
  const AbcCommandResult command =
      RunAbcCommand(abc_bin, script, log, timeout_ms);
  result.exit_code = command.exit_code;
  result.elapsed_seconds = command.elapsed_seconds;
  if (command.timed_out) {
    result.status = "timeout";
    result.reason = "ABC dsat exceeded its bounded timeout";
    return result;
  }
  if (command.output.find("UNSATISFIABLE") != std::string::npos) {
    result.status = "unsat";
    return result;
  }
  if (command.output.find("SATISFIABLE") == std::string::npos) {
    result.status = "error";
    result.reason = "ABC dsat returned no SAT/UNSAT result (exit " +
                    std::to_string(command.exit_code) + ")";
    return result;
  }
  if (!ParseNamedAbcCex(cex, pi_order, &result.values, &result.reason)) {
    result.status = "error";
    return result;
  }
  result.status = "sat";
  return result;
}

std::string Usage(const char* argv0) {
  std::ostringstream out;
  out << "Usage: " << argv0
      << " <case_manifest.json> [--output groundtruth.json]\n"
         "       [--per-mask N] [--per-singleton N] [--per-pair N] [--per-all N]\n"
         "       [--hard-negatives N]\n"
         "       [--negative-output negative_patterns.json]\n"
         "       [--outputs-per-instance N]\n"
         "       [--solver-mode auto|z3|constructive] [--z3-node-threshold N]\n"
         "       [--abc-bin PATH] [--abc-timeout-ms N]\n"
         "       [--max-random-attempts N] [--wall-clock-ms N]\n"
         "       [--timeout-ms N] [--max-encoded-nodes N]\n"
         "       [--mask-set auto|core|all] [--mask BITS]... [--force] [--plan-only]\n\n"
         "Generates exact-activation-mask, PO-observable witnesses for a V4\n"
         "multi-independent-Trojan case. Mask characters follow instances[]\n"
         "order; for [HT0, HT1], HT0's singleton mask is 10.\n";
  return out.str();
}

std::size_t ParseSize(const std::string& text, const std::string& flag) {
  std::size_t consumed = 0;
  unsigned long long value = 0;
  try {
    value = std::stoull(text, &consumed, 10);
  } catch (const std::exception&) {
    throw std::runtime_error(flag + " expects a non-negative integer");
  }
  if (consumed != text.size()) {
    throw std::runtime_error(flag + " expects a non-negative integer");
  }
  return static_cast<std::size_t>(value);
}

Options ParseArgs(int argc, char** argv) {
  Options opts;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto require_value = [&](const std::string& flag) -> std::string {
      if (i + 1 >= argc) {
        throw std::runtime_error(flag + " requires a value");
      }
      return argv[++i];
    };

    if (arg == "-h" || arg == "--help") {
      opts.show_help = true;
    } else if (arg == "--output" || arg == "-o") {
      opts.output_path = require_value(arg);
    } else if (arg == "--negative-output") {
      opts.negative_output_path = require_value(arg);
    } else if (arg == "--per-mask") {
      opts.witnesses_per_mask = ParseSize(require_value(arg), arg);
      if (opts.witnesses_per_mask == 0) {
        throw std::runtime_error("--per-mask must be greater than zero");
      }
    } else if (arg == "--per-singleton" || arg == "--per-pair" ||
               arg == "--per-all") {
      const std::size_t value = ParseSize(require_value(arg), arg);
      if (value == 0) {
        throw std::runtime_error(arg + " must be greater than zero");
      }
      if (arg == "--per-singleton") opts.witnesses_per_singleton = value;
      if (arg == "--per-pair") opts.witnesses_per_pair = value;
      if (arg == "--per-all") opts.witnesses_per_all = value;
    } else if (arg == "--hard-negatives") {
      opts.hard_negative_count = ParseSize(require_value(arg), arg);
    } else if (arg == "--outputs-per-instance") {
      opts.outputs_per_instance = ParseSize(require_value(arg), arg);
      if (opts.outputs_per_instance == 0) {
        throw std::runtime_error("--outputs-per-instance must be greater than zero");
      }
    } else if (arg == "--solver-mode") {
      opts.solver_mode = require_value(arg);
      if (opts.solver_mode != "auto" && opts.solver_mode != "z3" &&
          opts.solver_mode != "constructive") {
        throw std::runtime_error("--solver-mode must be auto, z3, or constructive");
      }
    } else if (arg == "--abc-bin") {
      opts.abc_bin = require_value(arg);
      if (opts.abc_bin.empty()) {
        throw std::runtime_error("--abc-bin must not be empty");
      }
    } else if (arg == "--abc-timeout-ms") {
      const std::size_t value = ParseSize(require_value(arg), arg);
      if (value == 0 || value > static_cast<std::size_t>(UINT32_MAX)) {
        throw std::runtime_error("--abc-timeout-ms must be in [1, 4294967295]");
      }
      opts.abc_timeout_ms = static_cast<unsigned>(value);
    } else if (arg == "--z3-node-threshold") {
      opts.z3_node_threshold = ParseSize(require_value(arg), arg);
    } else if (arg == "--max-random-attempts") {
      opts.max_random_attempts = ParseSize(require_value(arg), arg);
      if (opts.max_random_attempts == 0) {
        throw std::runtime_error("--max-random-attempts must be greater than zero");
      }
    } else if (arg == "--wall-clock-ms") {
      opts.wall_clock_ms = ParseSize(require_value(arg), arg);
      if (opts.wall_clock_ms == 0) {
        throw std::runtime_error("--wall-clock-ms must be greater than zero");
      }
    } else if (arg == "--timeout-ms") {
      const std::size_t value = ParseSize(require_value(arg), arg);
      if (value == 0 || value > static_cast<std::size_t>(UINT32_MAX)) {
        throw std::runtime_error("--timeout-ms must be in [1, 4294967295]");
      }
      opts.timeout_ms = static_cast<unsigned>(value);
    } else if (arg == "--max-encoded-nodes") {
      opts.max_encoded_nodes = ParseSize(require_value(arg), arg);
      if (opts.max_encoded_nodes == 0) {
        throw std::runtime_error("--max-encoded-nodes must be greater than zero");
      }
    } else if (arg == "--mask-set") {
      opts.mask_set = require_value(arg);
      if (opts.mask_set != "auto" && opts.mask_set != "core" &&
          opts.mask_set != "all") {
        throw std::runtime_error("--mask-set must be auto, core, or all");
      }
    } else if (arg == "--mask") {
      opts.explicit_masks.push_back(require_value(arg));
    } else if (arg == "--force") {
      opts.force = true;
    } else if (arg == "--plan-only") {
      opts.plan_only = true;
    } else if (!arg.empty() && arg[0] == '-') {
      throw std::runtime_error("unknown option: " + arg);
    } else if (opts.manifest_path.empty()) {
      opts.manifest_path = arg;
    } else {
      throw std::runtime_error("unexpected positional argument: " + arg);
    }
  }

  if (!opts.show_help && opts.manifest_path.empty()) {
    throw std::runtime_error("missing case_manifest.json path");
  }
  return opts;
}

json ReadJson(const fs::path& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to open manifest: " + path.string());
  }
  try {
    return json::parse(input);
  } catch (const std::exception& e) {
    throw std::runtime_error("failed to parse manifest " + path.string() +
                             ": " + e.what());
  }
}

std::string RequireString(const json& object,
                          const std::string& key,
                          const std::string& context) {
  const auto it = object.find(key);
  if (it == object.end() || !it->is_string() || it->get<std::string>().empty()) {
    throw std::runtime_error(context + "." + key + " must be a non-empty string");
  }
  return it->get<std::string>();
}

std::optional<std::string> OptionalString(const json& object,
                                          const std::string& key) {
  const auto it = object.find(key);
  if (it == object.end() || !it->is_string() || it->get<std::string>().empty()) {
    return std::nullopt;
  }
  return it->get<std::string>();
}

std::vector<std::string> RequireStringArray(const json& object,
                                            const std::string& key,
                                            const std::string& context) {
  const auto it = object.find(key);
  if (it == object.end() || !it->is_array()) {
    throw std::runtime_error(context + "." + key + " must be an array");
  }
  std::vector<std::string> values;
  values.reserve(it->size());
  for (std::size_t i = 0; i < it->size(); ++i) {
    if (!(*it)[i].is_string() || (*it)[i].get<std::string>().empty()) {
      throw std::runtime_error(context + "." + key + "[" +
                               std::to_string(i) + "] must be a string");
    }
    values.push_back((*it)[i].get<std::string>());
  }
  return values;
}

fs::path ResolveCasePath(const fs::path& manifest_path,
                         const std::string& relative,
                         const std::string& label) {
  const fs::path raw(relative);
  if (raw.is_absolute()) {
    throw std::runtime_error(label + " path must be relative to the manifest: " +
                             relative);
  }
  if (std::find(raw.begin(), raw.end(), fs::path("..")) != raw.end()) {
    throw std::runtime_error(label + " path must not contain '..': " + relative);
  }
  const fs::path resolved = manifest_path.parent_path() / raw;
  std::error_code ec;
  if (!fs::is_regular_file(resolved, ec)) {
    throw std::runtime_error(label + " file not found: " + resolved.string());
  }
  return fs::absolute(resolved).lexically_normal();
}

std::vector<std::string> CircuitPiNames(const circuit& c) {
  std::vector<std::string> names;
  names.reserve(c.pi_count());
  for (int idx : c.pi_indices()) {
    names.push_back(c.node_name(idx));
  }
  return names;
}

std::vector<std::string> CircuitPoNames(const circuit& c) {
  std::vector<std::string> names;
  names.reserve(c.po_count());
  for (int idx : c.po_indices()) {
    names.push_back(c.node_name(idx));
  }
  return names;
}

void RequireUniqueNames(const std::vector<std::string>& names,
                        const std::string& label) {
  std::unordered_set<std::string> seen;
  for (const auto& name : names) {
    if (!seen.insert(name).second) {
      throw std::runtime_error(label + " contains duplicate name: " + name);
    }
  }
}

void RequireSameInterface(const std::vector<std::string>& expected,
                          const std::vector<std::string>& actual,
                          const std::string& label) {
  if (expected == actual) {
    return;
  }
  std::set<std::string> expected_set(expected.begin(), expected.end());
  std::set<std::string> actual_set(actual.begin(), actual.end());
  if (expected_set != actual_set) {
    throw std::runtime_error(label + " name set differs from manifest");
  }
  throw std::runtime_error(label + " order differs from manifest");
}

circuit ParseBench(const fs::path& path, const std::string& label) {
  circuit c;
  std::string error;
  if (!bench_io::parse_bench_file(path.string(), c, &error)) {
    throw std::runtime_error("failed to parse " + label + " bench: " + error);
  }
  return c;
}

std::vector<InstanceSpec> ParseInstances(const json& manifest) {
  const auto instances_it = manifest.find("instances");
  if (instances_it == manifest.end() || !instances_it->is_array() ||
      instances_it->empty()) {
    throw std::runtime_error("manifest.instances must be a non-empty array");
  }
  if (instances_it->size() > 63) {
    throw std::runtime_error("at most 63 Trojan instances are supported");
  }

  std::vector<InstanceSpec> result;
  std::unordered_set<std::string> ids;
  result.reserve(instances_it->size());
  for (std::size_t i = 0; i < instances_it->size(); ++i) {
    const json& entry = (*instances_it)[i];
    if (!entry.is_object()) {
      throw std::runtime_error("instances[" + std::to_string(i) +
                               "] must be an object");
    }
    InstanceSpec instance;
    instance.id = RequireString(entry, "instance_id",
                                "instances[" + std::to_string(i) + "]");
    if (!ids.insert(instance.id).second) {
      throw std::runtime_error("duplicate instance_id: " + instance.id);
    }
    instance.individual_path =
        RequireString(entry, "individual_path",
                      "instances[" + std::to_string(i) + "]");
    instance.victim_net = RequireString(entry, "victim_net",
                                        "instances[" + std::to_string(i) + "]");

    const auto trigger_it = entry.find("trigger");
    if (trigger_it == entry.end() || !trigger_it->is_object()) {
      throw std::runtime_error("instances[" + std::to_string(i) +
                               "].trigger must be an object");
    }
    instance.trigger_net = OptionalString(*trigger_it, "trigger_net").value_or("");
    const auto literals_it = trigger_it->find("literals");
    if (literals_it == trigger_it->end() || !literals_it->is_array() ||
        literals_it->empty()) {
      throw std::runtime_error("instances[" + std::to_string(i) +
                               "].trigger.literals must be a non-empty array");
    }
    std::unordered_set<std::string> literal_nets;
    for (std::size_t j = 0; j < literals_it->size(); ++j) {
      const json& literal = (*literals_it)[j];
      if (!literal.is_object()) {
        throw std::runtime_error("trigger literal must be an object");
      }
      LiteralSpec spec;
      spec.net = RequireString(literal, "net", "trigger literal");
      const auto value_it = literal.find("required_value");
      if (value_it == literal.end() || !value_it->is_number_integer()) {
        throw std::runtime_error("trigger literal required_value must be 0 or 1");
      }
      const int required = value_it->get<int>();
      if (required != 0 && required != 1) {
        throw std::runtime_error("trigger literal required_value must be 0 or 1");
      }
      spec.required_value = required != 0;
      if (!literal_nets.insert(spec.net).second) {
        throw std::runtime_error(instance.id +
                                 " has duplicate trigger literal net: " + spec.net);
      }
      instance.literals.push_back(std::move(spec));
    }

    const auto payload_it = entry.find("payload");
    if (payload_it == entry.end() || !payload_it->is_object()) {
      throw std::runtime_error("instances[" + std::to_string(i) +
                               "].payload must be an object");
    }
    instance.payload_result_net =
        RequireString(*payload_it, "result_net",
                      "instances[" + std::to_string(i) + "].payload");
    const auto fanouts_it = payload_it->find("rewritten_fanouts");
    if (fanouts_it != payload_it->end() && fanouts_it->is_array()) {
      for (const auto& fanout : *fanouts_it) {
        if (!fanout.is_object()) {
          continue;
        }
        const auto output = OptionalString(fanout, "gate_output");
        if (output) {
          instance.rewritten_fanouts.push_back(*output);
        }
      }
    }
    result.push_back(std::move(instance));
  }
  return result;
}

std::vector<ResolvedInstance> ResolveInstances(
    const std::vector<InstanceSpec>& specs,
    const circuit& golden,
    const circuit& combined) {
  std::vector<ResolvedInstance> result;
  result.reserve(specs.size());
  for (const auto& spec : specs) {
    ResolvedInstance resolved;
    resolved.spec = spec;
    if (!spec.trigger_net.empty()) {
      if (!combined.has_node(spec.trigger_net)) {
        throw std::runtime_error(spec.id + " trigger_net not found in combined bench: " +
                                 spec.trigger_net);
      }
      resolved.combined_trigger_idx = combined.node_index(spec.trigger_net);
    }
    for (const auto& literal : spec.literals) {
      ResolvedLiteral item;
      item.net = literal.net;
      item.required_value = literal.required_value;
      if (combined.has_node(literal.net)) {
        item.side = CircuitSide::kCombined;
        item.node_idx = combined.node_index(literal.net);
      } else if (golden.has_node(literal.net)) {
        item.side = CircuitSide::kGolden;
        item.node_idx = golden.node_index(literal.net);
      } else {
        throw std::runtime_error(spec.id + " trigger literal net not found: " +
                                 literal.net);
      }
      resolved.literals.push_back(std::move(item));
    }
    result.push_back(std::move(resolved));
  }
  return result;
}

struct OutputCandidate {
  std::string name;
  int distance = 0;
  std::size_t fanin_nodes = 0;
  std::size_t po_position = 0;
};

std::size_t FaninConeSize(const circuit& c, int endpoint) {
  std::vector<char> required(c.node_count(), 0);
  std::vector<int> stack{endpoint};
  std::size_t count = 0;
  while (!stack.empty()) {
    const int idx = stack.back();
    stack.pop_back();
    if (idx < 0 || static_cast<std::size_t>(idx) >= c.node_count()) {
      throw std::runtime_error("fan-in cone endpoint out of range");
    }
    if (required[static_cast<std::size_t>(idx)]) continue;
    required[static_cast<std::size_t>(idx)] = 1;
    ++count;
    const cell& node = c.get_cell(idx);
    if (node.ctype == CType::GATE) {
      stack.insert(stack.end(), node.inputs.begin(), node.inputs.end());
    }
  }
  return count;
}

std::vector<OutputCandidate> ReachableOutputCandidates(
    const circuit& c,
    const std::vector<std::string>& start_names,
    std::unordered_map<int, std::size_t>* fanin_size_cache) {
  constexpr int kUnreachable = -1;
  std::vector<int> distance(c.node_count(), kUnreachable);
  for (const auto& name : start_names) {
    if (c.has_node(name)) {
      distance[static_cast<std::size_t>(c.node_index(name))] = 0;
    }
  }
  for (int idx : c.eval_order()) {
    const cell& node = c.get_cell(idx);
    int best = distance[static_cast<std::size_t>(idx)];
    for (int input : node.inputs) {
      const int input_distance = distance[static_cast<std::size_t>(input)];
      if (input_distance != kUnreachable &&
          (best == kUnreachable || input_distance + 1 < best)) {
        best = input_distance + 1;
      }
    }
    distance[static_cast<std::size_t>(idx)] = best;
  }

  std::vector<OutputCandidate> candidates;
  for (std::size_t pos = 0; pos < c.po_indices().size(); ++pos) {
    const int po = c.po_indices()[pos];
    const int po_distance = distance[static_cast<std::size_t>(po)];
    if (po_distance == kUnreachable) continue;
    std::size_t fanin_nodes = 0;
    if (fanin_size_cache) {
      const auto cached = fanin_size_cache->find(po);
      if (cached != fanin_size_cache->end()) {
        fanin_nodes = cached->second;
      } else {
        fanin_nodes = FaninConeSize(c, po);
        fanin_size_cache->emplace(po, fanin_nodes);
      }
    } else {
      fanin_nodes = FaninConeSize(c, po);
    }
    candidates.push_back(
        OutputCandidate{c.node_name(po), po_distance, fanin_nodes, pos});
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const OutputCandidate& lhs, const OutputCandidate& rhs) {
              if (lhs.fanin_nodes != rhs.fanin_nodes) {
                return lhs.fanin_nodes < rhs.fanin_nodes;
              }
              if (lhs.distance != rhs.distance) return lhs.distance < rhs.distance;
              return lhs.po_position < rhs.po_position;
            });
  return candidates;
}

void MarkFaninCone(const circuit& c,
                   const std::vector<int>& endpoints,
                   std::vector<char>* required) {
  if (!required || required->size() != c.node_count()) {
    throw std::runtime_error("internal error: invalid fan-in cone bitmap");
  }
  std::vector<int> stack = endpoints;
  while (!stack.empty()) {
    const int idx = stack.back();
    stack.pop_back();
    if (idx < 0 || static_cast<std::size_t>(idx) >= c.node_count()) {
      throw std::runtime_error("fan-in cone endpoint out of range");
    }
    if ((*required)[static_cast<std::size_t>(idx)]) {
      continue;
    }
    (*required)[static_cast<std::size_t>(idx)] = 1;
    const cell& node = c.get_cell(idx);
    if (node.ctype == CType::GATE) {
      for (int input : node.inputs) {
        stack.push_back(input);
      }
    }
  }
}

std::size_t CountMarked(const std::vector<char>& values) {
  return static_cast<std::size_t>(
      std::count(values.begin(), values.end(), static_cast<char>(1)));
}

class SparseEncoding {
 public:
  SparseEncoding(z3::context& ctx,
                 const circuit& c,
                 const std::vector<char>& required,
                 const std::string& prefix)
      : circuit_(c), required_(required), vars_(c.node_count()) {
    if (required.size() != c.node_count()) {
      throw std::runtime_error("internal error: sparse encoding bitmap mismatch");
    }
    for (std::size_t idx = 0; idx < required.size(); ++idx) {
      if (required[idx]) {
        vars_[idx].emplace(
            ctx.bool_const((prefix + std::to_string(idx)).c_str()));
      }
    }
  }

  const z3::expr& At(int idx) const {
    if (idx < 0 || static_cast<std::size_t>(idx) >= vars_.size() ||
        !vars_[static_cast<std::size_t>(idx)]) {
      throw std::runtime_error("internal error: requested unencoded circuit node");
    }
    return *vars_[static_cast<std::size_t>(idx)];
  }

  bool IsRequired(std::size_t idx) const { return required_[idx] != 0; }
  const circuit& GetCircuit() const { return circuit_; }

 private:
  const circuit& circuit_;
  const std::vector<char>& required_;
  std::vector<std::optional<z3::expr>> vars_;
};

z3::expr BuildGateExpr(const cell& gate, const SparseEncoding& encoding) {
  if (gate.inputs.empty()) {
    throw std::runtime_error("gate with no inputs in Z3 encoding");
  }
  auto input = [&](std::size_t pos) -> const z3::expr& {
    return encoding.At(gate.inputs[pos]);
  };
  z3::expr acc = input(0);
  switch (gate.gtype) {
    case GType::AND:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) acc = acc && input(i);
      return acc;
    case GType::OR:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) acc = acc || input(i);
      return acc;
    case GType::NAND:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) acc = acc && input(i);
      return !acc;
    case GType::NOR:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) acc = acc || input(i);
      return !acc;
    case GType::NOT:
      if (gate.inputs.size() != 1) throw std::runtime_error("NOT gate arity is not 1");
      return !input(0);
    case GType::BUFF:
      if (gate.inputs.size() != 1) throw std::runtime_error("BUFF gate arity is not 1");
      return input(0);
    case GType::XOR:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) acc = (acc != input(i));
      return acc;
    case GType::XNOR:
      for (std::size_t i = 1; i < gate.inputs.size(); ++i) acc = (acc != input(i));
      return !acc;
  }
  throw std::runtime_error("unsupported gate type in Z3 encoding");
}

void AddCircuitConstraints(
    z3::context& ctx,
    const SparseEncoding& encoding,
    const std::unordered_map<std::string, std::size_t>& shared_pi_positions,
    const std::vector<z3::expr>& shared_pi_vars,
    z3::solver* solver) {
  if (!solver) {
    throw std::runtime_error("internal error: null Z3 solver");
  }
  const circuit& c = encoding.GetCircuit();
  for (std::size_t idx = 0; idx < c.node_count(); ++idx) {
    if (!encoding.IsRequired(idx)) {
      continue;
    }
    const cell& node = c.get_cell(static_cast<int>(idx));
    switch (node.ctype) {
      case CType::CONST:
        solver->add(encoding.At(static_cast<int>(idx)) ==
                    ctx.bool_val(node.val != 0));
        break;
      case CType::PI: {
        const std::string& name = c.node_name(static_cast<int>(idx));
        const auto it = shared_pi_positions.find(name);
        if (it == shared_pi_positions.end()) {
          throw std::runtime_error("circuit PI not found in shared interface: " + name);
        }
        solver->add(encoding.At(static_cast<int>(idx)) == shared_pi_vars[it->second]);
        break;
      }
      case CType::GATE:
        solver->add(encoding.At(static_cast<int>(idx)) ==
                    BuildGateExpr(node, encoding));
        break;
      case CType::UNDEF:
        throw std::runtime_error("undefined circuit node in Z3 encoding");
    }
  }
}

z3::expr LiteralConjunction(z3::context& ctx,
                            const ResolvedInstance& instance,
                            const SparseEncoding& golden,
                            const SparseEncoding& combined) {
  z3::expr expression = ctx.bool_val(true);
  for (const auto& literal : instance.literals) {
    const z3::expr& var = literal.side == CircuitSide::kCombined
                              ? combined.At(literal.node_idx)
                              : golden.At(literal.node_idx);
    expression = expression && (var == ctx.bool_val(literal.required_value));
  }
  return expression;
}

std::string CheckStatus(const z3::check_result& result,
                        const z3::solver& solver,
                        std::string* reason) {
  if (result == z3::sat) return "sat";
  if (result == z3::unsat) return "unsat";
  const std::string why = solver.reason_unknown();
  if (reason) *reason = why;
  return why.find("timeout") != std::string::npos ? "timeout" : "unknown";
}

std::string MaskString(std::uint64_t value, std::size_t width) {
  std::string bits(width, '0');
  for (std::size_t pos = 0; pos < width; ++pos) {
    const std::size_t shift = width - 1 - pos;
    if ((value & (std::uint64_t{1} << shift)) != 0) bits[pos] = '1';
  }
  return bits;
}

std::uint64_t ParseMask(const std::string& raw, std::size_t width) {
  std::string bits = raw;
  if (bits.size() > 2 && bits[0] == '0' && (bits[1] == 'b' || bits[1] == 'B')) {
    bits = bits.substr(2);
  }
  if (bits.size() != width ||
      std::find_if(bits.begin(), bits.end(), [](char c) { return c != '0' && c != '1'; }) !=
          bits.end()) {
    throw std::runtime_error("mask must be a width-" + std::to_string(width) +
                             " binary string: " + raw);
  }
  std::uint64_t value = 0;
  for (char bit : bits) value = (value << 1) | (bit == '1' ? 1U : 0U);
  return value;
}

std::vector<std::uint64_t> RequestedMasks(const Options& opts,
                                          std::size_t width) {
  std::vector<std::uint64_t> result;
  std::unordered_set<std::uint64_t> seen;
  auto add = [&](std::uint64_t value) {
    if (value != 0 && seen.insert(value).second) result.push_back(value);
  };
  if (!opts.explicit_masks.empty()) {
    for (const auto& mask : opts.explicit_masks) add(ParseMask(mask, width));
    if (result.empty()) throw std::runtime_error("at least one non-zero --mask is required");
    return result;
  }

  const bool enumerate_all = opts.mask_set == "all" ||
                             (opts.mask_set == "auto" && width <= 3);
  if (enumerate_all) {
    if (width > 16) {
      throw std::runtime_error("--mask-set all is limited to 16 instances");
    }
    const std::uint64_t last = (std::uint64_t{1} << width) - 1;
    for (std::uint64_t value = 1; value <= last; ++value) add(value);
    return result;
  }

  for (std::size_t i = 0; i < width; ++i) {
    add(std::uint64_t{1} << (width - 1 - i));
  }
  for (std::size_t i = 0; i < width; ++i) {
    for (std::size_t j = i + 1; j < width; ++j) {
      add((std::uint64_t{1} << (width - 1 - i)) |
          (std::uint64_t{1} << (width - 1 - j)));
    }
  }
  add((std::uint64_t{1} << width) - 1);
  return result;
}

std::string SampleClass(const std::string& mask) {
  const std::size_t active =
      static_cast<std::size_t>(std::count(mask.begin(), mask.end(), '1'));
  if (active == 1) return "singleton";
  if (active == mask.size()) return "all";
  if (active == 2) return "pair";
  return "subset";
}

std::size_t WitnessTarget(const Options& opts, const std::string& mask) {
  const std::size_t active =
      static_cast<std::size_t>(std::count(mask.begin(), mask.end(), '1'));
  if (active == 1 && opts.witnesses_per_singleton) {
    return *opts.witnesses_per_singleton;
  }
  if (active == mask.size() && opts.witnesses_per_all) {
    return *opts.witnesses_per_all;
  }
  if (active == 2 && opts.witnesses_per_pair) {
    return *opts.witnesses_per_pair;
  }
  return opts.witnesses_per_mask;
}

std::vector<int> LocalPiValues(
    const circuit& c,
    const std::unordered_map<std::string, std::size_t>& shared_positions,
    const std::vector<int>& shared_values) {
  std::vector<int> values;
  values.reserve(c.pi_count());
  for (int idx : c.pi_indices()) {
    const auto it = shared_positions.find(c.node_name(idx));
    if (it == shared_positions.end()) {
      throw std::runtime_error("PI mapping disappeared during simulation");
    }
    values.push_back(shared_values[it->second]);
  }
  return values;
}

bool EvaluateResolvedInstance(const ResolvedInstance& instance,
                              const circuit& golden,
                              const circuit& combined) {
  if (instance.combined_trigger_idx) {
    return combined.get_cell(*instance.combined_trigger_idx).val != 0;
  }
  for (const auto& literal : instance.literals) {
    const circuit& source = literal.side == CircuitSide::kCombined ? combined : golden;
    const bool value = source.get_cell(literal.node_idx).val != 0;
    if (value != literal.required_value) return false;
  }
  return true;
}

bool TriggerStructureMatchesManifest(const ResolvedInstance& instance,
                                     const circuit& combined) {
  if (!instance.combined_trigger_idx) return true;
  const cell& trigger = combined.get_cell(*instance.combined_trigger_idx);
  if (trigger.ctype != CType::GATE || trigger.gtype != GType::AND ||
      trigger.inputs.size() != instance.spec.literals.size()) {
    return false;
  }
  std::vector<std::pair<std::string, bool>> actual;
  actual.reserve(trigger.inputs.size());
  for (int input_idx : trigger.inputs) {
    const cell& input_cell = combined.get_cell(input_idx);
    if (input_cell.ctype == CType::GATE && input_cell.gtype == GType::NOT &&
        input_cell.inputs.size() == 1) {
      actual.emplace_back(combined.node_name(input_cell.inputs[0]), false);
    } else {
      actual.emplace_back(combined.node_name(input_idx), true);
    }
  }
  std::vector<std::pair<std::string, bool>> expected;
  expected.reserve(instance.spec.literals.size());
  for (const auto& literal : instance.spec.literals) {
    expected.emplace_back(literal.net, literal.required_value);
  }
  std::sort(actual.begin(), actual.end());
  std::sort(expected.begin(), expected.end());
  return actual == expected;
}

bool ManifestPartialAssignment(
    const json& manifest,
    const std::string& mask,
    const std::unordered_map<std::string, std::size_t>& pi_positions,
    std::vector<std::optional<int>>* assignment,
    std::string* error) {
  if (!assignment) return false;
  assignment->assign(pi_positions.size(), std::nullopt);
  const auto witnesses = manifest.find("trigger_witnesses");
  if (witnesses == manifest.end() || !witnesses->is_object()) {
    if (error) *error = "manifest.trigger_witnesses is missing";
    return false;
  }
  const auto partials = witnesses->find("partial_pi_assignments");
  if (partials == witnesses->end() || !partials->is_object()) {
    if (error) *error = "trigger_witnesses.partial_pi_assignments is missing";
    return false;
  }
  const auto value = partials->find(mask);
  if (value == partials->end() || !value->is_object()) {
    if (error) *error = "no constructive assignment for mask " + mask;
    return false;
  }
  for (auto it = value->begin(); it != value->end(); ++it) {
    const auto position = pi_positions.find(it.key());
    if (position == pi_positions.end() || !it.value().is_number_integer()) {
      if (error) *error = "invalid PI in constructive assignment: " + it.key();
      return false;
    }
    const int bit = it.value().get<int>();
    if (bit != 0 && bit != 1) {
      if (error) *error = "non-binary constructive assignment for " + it.key();
      return false;
    }
    (*assignment)[position->second] = bit;
  }
  return true;
}

std::optional<std::string> FileHash(const json& manifest,
                                    const std::string& relative_path) {
  const auto files_it = manifest.find("files");
  if (files_it == manifest.end() || !files_it->is_object()) return std::nullopt;
  const auto file_it = files_it->find(relative_path);
  if (file_it == files_it->end() || !file_it->is_object()) return std::nullopt;
  return OptionalString(*file_it, "sha256");
}

void WriteJsonAtomically(const fs::path& path, const json& root, bool force) {
  std::error_code ec;
  if (fs::exists(path, ec) && !force) {
    throw std::runtime_error("output already exists (use --force): " + path.string());
  }
  if (!path.parent_path().empty()) {
    fs::create_directories(path.parent_path(), ec);
    if (ec) {
      throw std::runtime_error("failed to create output directory: " +
                               ec.message());
    }
  }

  // Keep the temporary file beside the destination so POSIX rename(2) is an
  // atomic replacement.  The PID/counter suffix also prevents concurrent
  // cases from sharing the old fixed `<output>.tmp` pathname.
  static std::atomic<std::uint64_t> temporary_serial{0};
  fs::path temporary;
  int temporary_fd = -1;
  for (std::size_t attempt = 0; attempt < 1024; ++attempt) {
    temporary = path;
    temporary += ".tmp." + std::to_string(static_cast<long long>(::getpid())) +
                 "." + std::to_string(temporary_serial.fetch_add(1));
    temporary_fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (temporary_fd >= 0) break;
    if (errno != EEXIST) {
      throw std::runtime_error(
          "failed to create unique temporary output: " +
          std::error_code(errno, std::generic_category()).message());
    }
  }
  if (temporary_fd < 0) {
    throw std::runtime_error("failed to allocate a unique temporary output");
  }
  ::close(temporary_fd);

  try {
    std::ofstream output(temporary);
    if (!output) {
      throw std::runtime_error("failed to open output: " + temporary.string());
    }
    output << std::setw(2) << root << '\n';
    if (!output) {
      throw std::runtime_error("failed while writing output: " + temporary.string());
    }
  } catch (...) {
    fs::remove(temporary, ec);
    throw;
  }

  if (!force && fs::exists(path, ec)) {
    fs::remove(temporary, ec);
    throw std::runtime_error("output already exists (use --force): " +
                             path.string());
  }
  // On POSIX, renaming a same-filesystem regular file over an existing regular
  // file replaces it atomically; deliberately do not unlink the old artifact.
  fs::rename(temporary, path, ec);
  if (ec) {
    const std::string message = ec.message();
    fs::remove(temporary, ec);
    throw std::runtime_error("failed to finalize output: " + message);
  }
}

int Run(const Options& opts) {
  const auto start_time = std::chrono::steady_clock::now();
  const auto wall_deadline =
      start_time + std::chrono::milliseconds(opts.wall_clock_ms);
  auto wall_deadline_exceeded = [&]() {
    return std::chrono::steady_clock::now() >= wall_deadline;
  };
  const fs::path manifest_path = fs::absolute(opts.manifest_path).lexically_normal();
  const json manifest = ReadJson(manifest_path);
  if (!manifest.is_object()) {
    throw std::runtime_error("case manifest root must be an object");
  }
  if (RequireString(manifest, "schema_version", "manifest") != kCaseSchema) {
    throw std::runtime_error("unsupported case manifest schema");
  }
  const std::string case_id = RequireString(manifest, "case_id", "manifest");
  const std::string benchmark = OptionalString(manifest, "benchmark").value_or("unknown");
  const std::string golden_relative = RequireString(manifest, "golden_path", "manifest");
  const std::string combined_relative = RequireString(manifest, "combined_path", "manifest");
  const fs::path golden_path =
      ResolveCasePath(manifest_path, golden_relative, "golden");
  const fs::path combined_path =
      ResolveCasePath(manifest_path, combined_relative, "combined");

  fs::path output_path = opts.output_path;
  if (output_path.empty()) output_path = manifest_path.parent_path() / "groundtruth.json";
  if (output_path.is_relative()) output_path = fs::absolute(output_path).lexically_normal();
  fs::path negative_output_path = opts.negative_output_path;
  if (negative_output_path.empty()) {
    negative_output_path = manifest_path.parent_path() / "negative_patterns.json";
  }
  if (negative_output_path.is_relative()) {
    negative_output_path = fs::absolute(negative_output_path).lexically_normal();
  }
  if (opts.hard_negative_count > 0 && negative_output_path == output_path) {
    throw std::runtime_error("--negative-output must differ from --output");
  }
  std::error_code output_ec;
  if (!opts.plan_only && !opts.force && fs::exists(output_path, output_ec)) {
    throw std::runtime_error("output already exists (use --force): " +
                             output_path.string());
  }
  if (!opts.plan_only && !opts.force && opts.hard_negative_count > 0 &&
      fs::exists(negative_output_path, output_ec)) {
    throw std::runtime_error("negative output already exists (use --force): " +
                             negative_output_path.string());
  }

  std::cout << "Loading " << case_id << "\n";
  circuit golden = ParseBench(golden_path, "golden");
  circuit combined = ParseBench(combined_path, "combined");
  const auto specs = ParseInstances(manifest);
  std::vector<fs::path> individual_paths;
  individual_paths.reserve(specs.size());
  for (const auto& spec : specs) {
    individual_paths.push_back(
        ResolveCasePath(manifest_path, spec.individual_path,
                        spec.id + " individual"));
  }
  const auto instances = ResolveInstances(specs, golden, combined);

  const auto interfaces_it = manifest.find("interfaces");
  if (interfaces_it == manifest.end() || !interfaces_it->is_object()) {
    throw std::runtime_error("manifest.interfaces must be an object");
  }
  const auto pi_order = RequireStringArray(*interfaces_it, "primary_inputs", "interfaces");
  const auto po_order = RequireStringArray(*interfaces_it, "primary_outputs", "interfaces");
  RequireUniqueNames(pi_order, "primary_inputs");
  RequireUniqueNames(po_order, "primary_outputs");
  RequireSameInterface(pi_order, CircuitPiNames(golden), "golden PI interface");
  RequireSameInterface(pi_order, CircuitPiNames(combined), "combined PI interface");
  RequireSameInterface(po_order, CircuitPoNames(golden), "golden PO interface");
  RequireSameInterface(po_order, CircuitPoNames(combined), "combined PO interface");

  std::unordered_map<std::string, std::size_t> pi_positions;
  for (std::size_t i = 0; i < pi_order.size(); ++i) pi_positions[pi_order[i]] = i;

  std::unordered_map<int, std::size_t> fanin_size_cache;
  std::vector<std::vector<OutputCandidate>> output_candidates;
  std::vector<std::vector<std::string>> instance_selected_outputs;
  json output_selection = json::array();
  std::unordered_set<std::string> selected_output_set;
  output_candidates.reserve(specs.size());
  instance_selected_outputs.reserve(specs.size());
  for (const auto& instance : specs) {
    std::vector<std::string> starts{instance.payload_result_net};
    starts.insert(starts.end(), instance.rewritten_fanouts.begin(),
                  instance.rewritten_fanouts.end());
    auto candidates =
        ReachableOutputCandidates(combined, starts, &fanin_size_cache);
    if (candidates.empty()) {
      throw std::runtime_error(instance.id +
                               " payload has no structurally reachable PO");
    }
    std::vector<std::string> selected;
    const std::size_t selected_count =
        std::min(opts.outputs_per_instance, candidates.size());
    for (std::size_t rank = 0; rank < selected_count; ++rank) {
      selected.push_back(candidates[rank].name);
      selected_output_set.insert(candidates[rank].name);
    }

    json selection;
    selection["instance_id"] = instance.id;
    selection["reachable_output_count"] = candidates.size();
    selection["selected_outputs"] = selected;
    selection["ranked_candidates"] = json::array();
    const std::size_t recorded_candidates = std::min<std::size_t>(16, candidates.size());
    for (std::size_t rank = 0; rank < recorded_candidates; ++rank) {
      selection["ranked_candidates"].push_back(
          {{"rank", rank},
           {"output", candidates[rank].name},
           {"forward_distance", candidates[rank].distance},
           {"fanin_nodes", candidates[rank].fanin_nodes},
           {"selected", rank < selected_count}});
    }
    output_selection.push_back(std::move(selection));
    instance_selected_outputs.push_back(std::move(selected));
    output_candidates.push_back(std::move(candidates));
  }

  std::vector<std::string> encoded_outputs;
  for (const auto& po : po_order) {
    if (selected_output_set.find(po) != selected_output_set.end()) {
      encoded_outputs.push_back(po);
    }
  }
  const std::string cone_mode = "min_fanin_then_nearest_per_instance";

  std::vector<char> golden_required(golden.node_count(), 0);
  std::vector<char> combined_required(combined.node_count(), 0);
  std::vector<int> golden_endpoints;
  std::vector<int> combined_endpoints;
  for (const auto& output : encoded_outputs) {
    golden_endpoints.push_back(golden.node_index(output));
    combined_endpoints.push_back(combined.node_index(output));
  }
  for (const auto& instance : instances) {
    if (instance.combined_trigger_idx) combined_endpoints.push_back(*instance.combined_trigger_idx);
    for (const auto& literal : instance.literals) {
      (literal.side == CircuitSide::kCombined ? combined_endpoints : golden_endpoints)
          .push_back(literal.node_idx);
    }
  }
  MarkFaninCone(golden, golden_endpoints, &golden_required);
  MarkFaninCone(combined, combined_endpoints, &combined_required);
  const std::size_t golden_encoded_count = CountMarked(golden_required);
  const std::size_t combined_encoded_count = CountMarked(combined_required);
  const std::size_t encoded_count = golden_encoded_count + combined_encoded_count;
  if (encoded_count > opts.max_encoded_nodes) {
    throw std::runtime_error("selected fan-in cones require " +
                             std::to_string(encoded_count) +
                             " nodes, exceeding --max-encoded-nodes=" +
                             std::to_string(opts.max_encoded_nodes));
  }
  std::cout << "Encoding " << encoded_outputs.size() << "/" << po_order.size()
            << " outputs and " << encoded_count << " sparse nodes\n";
  if (opts.plan_only) {
    json plan;
    plan["case_id"] = case_id;
    plan["mode"] = cone_mode;
    plan["outputs_per_instance"] = opts.outputs_per_instance;
    plan["encoded_outputs"] = encoded_outputs;
    plan["golden_encoded_nodes"] = golden_encoded_count;
    plan["combined_encoded_nodes"] = combined_encoded_count;
    plan["output_selection"] = output_selection;
    std::cout << std::setw(2) << plan << '\n';
    return 0;
  }

  const auto requested_masks = RequestedMasks(opts, instances.size());
  bool constructive_supported = true;
  std::string constructive_error;
  for (const auto& instance : instances) {
    if (!TriggerStructureMatchesManifest(instance, combined)) {
      constructive_supported = false;
      constructive_error = instance.spec.id +
                           " trigger structure differs from manifest literals";
      break;
    }
    for (const auto& literal : instance.spec.literals) {
      if (pi_positions.find(literal.net) == pi_positions.end()) {
        constructive_supported = false;
        constructive_error = instance.spec.id + " literal is not a PI: " +
                             literal.net;
        break;
      }
    }
    if (!constructive_supported) break;
  }
  if (constructive_supported) {
    for (std::uint64_t mask_value : requested_masks) {
      std::vector<std::optional<int>> assignment;
      if (!ManifestPartialAssignment(manifest,
                                     MaskString(mask_value, instances.size()),
                                     pi_positions,
                                     &assignment,
                                     &constructive_error)) {
        constructive_supported = false;
        break;
      }
    }
  }
  const std::size_t raw_max_node_count =
      std::max(golden.node_count(), combined.node_count());
  const bool auto_large_sparse = encoded_count > opts.z3_node_threshold;
  const bool auto_large_raw = raw_max_node_count > opts.z3_node_threshold;
  const bool use_constructive =
      opts.solver_mode == "constructive" ||
      (opts.solver_mode == "auto" &&
       (auto_large_sparse || auto_large_raw));
  if (use_constructive && !constructive_supported) {
    throw std::runtime_error("constructive solver unavailable: " +
                             constructive_error);
  }

  if (use_constructive) {
    std::uint64_t random_seed = Fnv1a64(case_id);
    const auto generation_it = manifest.find("generation");
    if (generation_it != manifest.end() && generation_it->is_object()) {
      const auto seed_it = generation_it->find("seed");
      if (seed_it != generation_it->end() && seed_it->is_number_integer()) {
        random_seed ^= seed_it->get<std::uint64_t>() + 0x9e3779b97f4a7c15ULL;
      }
    }
    std::mt19937_64 random(random_seed);
    const std::size_t positive_budget_ms =
        opts.hard_negative_count == 0
            ? opts.wall_clock_ms
            : std::max<std::size_t>(1, (opts.wall_clock_ms * 3) / 4);
    const auto positive_deadline =
        start_time + std::chrono::milliseconds(positive_budget_ms);
    auto deadline_exceeded = [&]() {
      return wall_deadline_exceeded();
    };
    auto positive_deadline_exceeded = [&]() {
      return std::chrono::steady_clock::now() >= positive_deadline;
    };
    auto random_assignment = [&](const std::vector<std::optional<int>>& partial) {
      std::vector<int> values(pi_order.size(), 0);
      for (std::size_t i = 0; i < values.size(); ++i) {
        values[i] = static_cast<int>(random() & 1ULL);
        if (i < partial.size() && partial[i]) values[i] = *partial[i];
      }
      return values;
    };
    auto random_exact_assignment =
        [&](const std::string& requested_mask,
            const std::vector<std::optional<int>>& fallback_partial) {
          std::vector<std::optional<int>> active_forced(pi_order.size(),
                                                        std::nullopt);
          bool active_conflict = false;
          for (std::size_t instance_idx = 0;
               instance_idx < instances.size(); ++instance_idx) {
            if (requested_mask[instance_idx] != '1') continue;
            for (const auto& literal : instances[instance_idx].spec.literals) {
              const std::size_t position = pi_positions.at(literal.net);
              const int required = literal.required_value ? 1 : 0;
              if (active_forced[position] &&
                  *active_forced[position] != required) {
                active_conflict = true;
              }
              active_forced[position] = required;
            }
          }

          // Inactive triggers are disjunctions of failed literals.  Sampling
          // their PI values, rather than fixing the manifest's one canonical
          // partial assignment, avoids accidentally suppressing payload
          // observability while retaining exact-mask semantics.
          if (!active_conflict) {
            for (std::size_t trial = 0; trial < 64; ++trial) {
              std::vector<int> values(pi_order.size(), 0);
              for (std::size_t position = 0; position < values.size();
                   ++position) {
                values[position] = static_cast<int>(random() & 1ULL);
                if (active_forced[position]) {
                  values[position] = *active_forced[position];
                }
              }
              std::string actual(instances.size(), '0');
              for (std::size_t instance_idx = 0;
                   instance_idx < instances.size(); ++instance_idx) {
                bool active = true;
                for (const auto& literal :
                     instances[instance_idx].spec.literals) {
                  if (values[pi_positions.at(literal.net)] !=
                      static_cast<int>(literal.required_value)) {
                    active = false;
                    break;
                  }
                }
                if (active) actual[instance_idx] = '1';
              }
              if (actual == requested_mask) return values;
            }
          }
          return random_assignment(fallback_partial);
        };
    auto pattern_bits_from_values = [](const std::vector<int>& values) {
      std::string bits;
      bits.reserve(values.size());
      for (int value : values) bits.push_back(value ? '1' : '0');
      return bits;
    };
    auto simulate_shared = [&](const std::vector<int>& shared_values,
                               std::vector<std::string>* mismatches,
                               std::string* activation_mask,
                               std::vector<std::string>* active_instances) {
      const auto golden_values = LocalPiValues(golden, pi_positions, shared_values);
      const auto combined_values = LocalPiValues(combined, pi_positions, shared_values);
      const auto golden_outputs = golden.simulate(golden_values);
      const auto combined_outputs = combined.simulate(combined_values);
      mismatches->clear();
      for (std::size_t i = 0; i < po_order.size(); ++i) {
        if (golden_outputs[i] != combined_outputs[i]) mismatches->push_back(po_order[i]);
      }
      activation_mask->assign(instances.size(), '0');
      active_instances->clear();
      for (std::size_t i = 0; i < instances.size(); ++i) {
        if (EvaluateResolvedInstance(instances[i], golden, combined)) {
          (*activation_mask)[i] = '1';
          active_instances->push_back(instances[i].spec.id);
        }
      }
    };

    // Screen random completions in 256-pattern bit-packed batches.  Full scalar
    // simulation is intentionally reserved for accepted samples, where it acts
    // as an independent correctness check of both the PO mismatch and mask.
    constexpr std::size_t kPackedGpuPatternCapacity = 256;
    constexpr std::size_t kGtMaxWordBlocks =
        (kPackedGpuPatternCapacity + batch_simulator::kBits - 1) /
        batch_simulator::kBits;
    batch_simulator golden_batch(golden, combined.node_count(),
                                 kGtMaxWordBlocks);
    batch_simulator combined_batch(combined, golden.node_count(),
                                   kGtMaxWordBlocks);
    const bool packed_uses_gpu =
        golden_batch.is_gpu() && combined_batch.is_gpu();
    const bool packed_mixed_backend =
        golden_batch.is_gpu() != combined_batch.is_gpu();
    const std::size_t requested_packed_capacity =
        packed_uses_gpu ? kPackedGpuPatternCapacity : 16;
    const std::size_t packed_batch_capacity = std::min<std::size_t>(
        requested_packed_capacity,
        std::min(golden_batch.max_wb(), combined_batch.max_wb()) *
            batch_simulator::kBits);
    if (packed_batch_capacity == 0) {
      throw std::runtime_error("packed simulator has zero pattern capacity");
    }

    struct PackedObservation {
      bool output_mismatch = false;
      std::vector<std::string> mismatched_outputs;
      std::string activation_mask;
      std::vector<std::string> active_instances;
    };
    auto screen_batch = [&](const std::vector<std::vector<int>>& batch) {
      std::vector<PackedObservation> observations(batch.size());
      if (batch.empty()) return observations;
      if (batch.size() > packed_batch_capacity) {
        throw std::runtime_error("internal packed batch exceeds simulator capacity");
      }

      const std::size_t word_blocks =
          golden_batch.pack_patterns(batch, 0, batch.size());
      combined_batch.upload_pi(golden_batch.h_pi_data(), word_blocks);
      golden_batch.simulate(word_blocks, batch.size());
      combined_batch.simulate(word_blocks, batch.size());

      std::vector<batch_simulator::word_t> mismatch_words(word_blocks, 0);
      for (std::size_t output = 0; output < po_order.size(); ++output) {
        for (std::size_t wb = 0; wb < word_blocks; ++wb) {
          mismatch_words[wb] |= golden_batch.po_bits(output, wb) ^
                                combined_batch.po_bits(output, wb);
        }
      }
      const std::size_t tail = batch.size() % batch_simulator::kBits;
      mismatch_words.back() &= batch_simulator::pmask_for(
          tail == 0 ? batch_simulator::kBits : tail);

      for (std::size_t pattern = 0; pattern < batch.size(); ++pattern) {
        PackedObservation& observation = observations[pattern];
        const std::size_t wb = pattern / batch_simulator::kBits;
        const std::size_t bit = pattern % batch_simulator::kBits;
        observation.output_mismatch =
            ((mismatch_words[wb] >> bit) & 1ULL) != 0;
        if (observation.output_mismatch) {
          for (std::size_t output = 0; output < po_order.size(); ++output) {
            if (golden_batch.po_value(output, pattern) !=
                combined_batch.po_value(output, pattern)) {
              observation.mismatched_outputs.push_back(po_order[output]);
            }
          }
        }

        observation.activation_mask.assign(instances.size(), '0');
        for (std::size_t instance_idx = 0; instance_idx < instances.size();
             ++instance_idx) {
          const auto& instance = instances[instance_idx];
          bool active = true;
          if (instance.combined_trigger_idx) {
            active = combined_batch.node_value(*instance.combined_trigger_idx,
                                               pattern) != 0;
          } else {
            for (const auto& literal : instance.literals) {
              const int value = literal.side == CircuitSide::kCombined
                                    ? combined_batch.node_value(literal.node_idx,
                                                                pattern)
                                    : golden_batch.node_value(literal.node_idx,
                                                              pattern);
              if ((value != 0) != literal.required_value) {
                active = false;
                break;
              }
            }
          }
          if (active) {
            observation.activation_mask[instance_idx] = '1';
            observation.active_instances.push_back(instance.spec.id);
          }
        }
      }
      return observations;
    };

    auto remaining_positive_ms = [&]() -> std::size_t {
      const auto now = std::chrono::steady_clock::now();
      if (now >= positive_deadline) return 0;
      return static_cast<std::size_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              positive_deadline - now)
              .count());
    };

    fs::path abc_bin = opts.abc_bin;
    if (abc_bin.is_relative()) abc_bin = fs::absolute(abc_bin).lexically_normal();
    std::unique_ptr<ScopedTempDirectory> abc_temp;
    fs::path abc_golden_copy;
    fs::path abc_combined_copy;
    fs::path abc_base_blif;
    bool abc_ready = false;
    std::string abc_setup_status = "unavailable";
    std::string abc_setup_reason;
    double abc_setup_seconds = 0.0;
    int abc_setup_exit_code = -1;
    std::size_t abc_invocations = 0;
    std::size_t abc_timeouts = 0;
    try {
      std::error_code abc_ec;
      if (!fs::exists(abc_bin, abc_ec)) {
        abc_setup_reason = "ABC binary does not exist: " + abc_bin.string();
      } else if (remaining_positive_ms() == 0) {
        abc_setup_status = "timeout";
        abc_setup_reason = "no positive-phase budget remains for ABC setup";
      } else {
        abc_temp = std::make_unique<ScopedTempDirectory>("multi-gt-abc-");
        abc_golden_copy = abc_temp->path() / "golden.bench";
        abc_combined_copy = abc_temp->path() / "combined.bench";
        abc_base_blif = abc_temp->path() / "base_miter.blif";
        fs::copy_file(golden_path, abc_golden_copy,
                      fs::copy_options::overwrite_existing);
        fs::copy_file(combined_path, abc_combined_copy,
                      fs::copy_options::overwrite_existing);
        const fs::path setup_log = abc_temp->path() / "setup.log";
        const std::string setup_script =
            "miter " + AbcQuotePath(abc_golden_copy) + " " +
            AbcQuotePath(abc_combined_copy) +
            "; strash; write_blif " + AbcQuotePath(abc_base_blif);
        const std::size_t setup_timeout =
            std::min<std::size_t>(opts.abc_timeout_ms,
                                  remaining_positive_ms());
        const AbcCommandResult setup =
            RunAbcCommand(abc_bin, setup_script, setup_log, setup_timeout);
        abc_setup_seconds = setup.elapsed_seconds;
        abc_setup_exit_code = setup.exit_code;
        if (setup.timed_out) {
          abc_setup_status = "timeout";
          abc_setup_reason = "ABC miter setup exceeded its bounded timeout";
          ++abc_timeouts;
        } else if (setup.exit_code != 0 ||
                   !fs::exists(abc_base_blif, abc_ec)) {
          abc_setup_status = "error";
          abc_setup_reason = "ABC miter setup failed with exit " +
                             std::to_string(setup.exit_code);
        } else {
          abc_setup_status = "ready";
          abc_ready = true;
        }
      }
    } catch (const std::exception& e) {
      abc_setup_status = "error";
      abc_setup_reason = e.what();
      abc_ready = false;
    }

    std::vector<AbcCecResult> individual_cec(specs.size());
    bool all_individual_not_equivalent = !specs.empty();
    bool any_individual_equivalent = false;
    for (std::size_t instance_idx = 0; instance_idx < specs.size();
         ++instance_idx) {
      AbcCecResult& cec = individual_cec[instance_idx];
      if (!abc_temp || abc_golden_copy.empty()) {
        cec.status = "not_run";
        cec.reason = abc_setup_reason;
        all_individual_not_equivalent = false;
        continue;
      }
      const std::size_t remaining = remaining_positive_ms();
      if (remaining == 0) {
        cec.status = "timeout";
        cec.reason = "no positive-phase budget remains for individual CEC";
        all_individual_not_equivalent = false;
        ++abc_timeouts;
        continue;
      }
      try {
        const fs::path individual_copy =
            abc_temp->path() /
            ("individual_" + std::to_string(instance_idx) + ".bench");
        fs::copy_file(individual_paths[instance_idx], individual_copy,
                      fs::copy_options::overwrite_existing);
        cec = RunAbcIndividualCec(
            abc_bin, abc_temp->path(), abc_golden_copy, individual_copy,
            pi_order, instance_idx,
            std::min<std::size_t>(opts.abc_timeout_ms, remaining));
        abc_invocations += cec.invocation_count;
        abc_timeouts += cec.timeout_count;
      } catch (const std::exception& e) {
        cec.status = "error";
        cec.reason = e.what();
      }
      any_individual_equivalent =
          any_individual_equivalent || cec.status == "equivalent";
      all_individual_not_equivalent =
          all_individual_not_equivalent && cec.status == "not_equivalent";
    }

    std::unordered_set<std::size_t> trigger_position_set;
    for (const auto& instance : specs) {
      for (const auto& literal : instance.literals) {
        trigger_position_set.insert(pi_positions.at(literal.net));
      }
    }
    std::vector<std::size_t> nontrigger_positions;
    for (std::size_t position = 0; position < pi_order.size(); ++position) {
      if (trigger_position_set.find(position) == trigger_position_set.end()) {
        nontrigger_positions.push_back(position);
      }
    }
    auto trigger_mask_from_values = [&](const std::vector<int>& values) {
      std::string mask(instances.size(), '0');
      for (std::size_t instance_idx = 0; instance_idx < specs.size();
           ++instance_idx) {
        bool active = true;
        for (const auto& literal : specs[instance_idx].literals) {
          if (values[pi_positions.at(literal.net)] !=
              static_cast<int>(literal.required_value)) {
            active = false;
            break;
          }
        }
        if (active) mask[instance_idx] = '1';
      }
      return mask;
    };

    json patterns = json::array();
    json mask_results = json::array();
    std::unordered_set<std::string> emitted_bits;
    enum class ScalarAppendStatus {
      kAccepted,
      kDuplicate,
      kWrongActivationMask,
      kNotObservable,
    };
    bool positive_complete = true;
    for (std::uint64_t mask_value : requested_masks) {
      const std::string requested_mask = MaskString(mask_value, instances.size());
      const std::size_t witness_target = WitnessTarget(opts, requested_mask);
      const std::size_t active_count = static_cast<std::size_t>(
          std::count(requested_mask.begin(), requested_mask.end(), '1'));
      const bool singleton = active_count == 1;
      const std::size_t singleton_idx = singleton
                                            ? static_cast<std::size_t>(
                                                  requested_mask.find('1'))
                                            : specs.size();
      std::vector<std::optional<int>> partial;
      std::string partial_error;
      if (!ManifestPartialAssignment(manifest, requested_mask, pi_positions,
                                     &partial, &partial_error)) {
        throw std::runtime_error(partial_error);
      }

      std::size_t attempts = 0;
      std::size_t witnesses = 0;
      std::size_t exact_mask_candidates = 0;
      std::size_t observable_candidates = 0;
      std::size_t abc_seed_count = 0;
      std::size_t abc_seed_attempts = 0;
      std::size_t abc_duplicate_seed_count = 0;
      std::size_t scalar_wrong_mask_count = 0;
      std::size_t scalar_not_observable_count = 0;
      double abc_mask_seconds = 0.0;
      bool globally_unobservable_proven = false;
      bool skip_after_singleton_equivalence = false;
      bool used_individual_cec_seed = false;
      bool used_conditioned_dsat_seed = false;
      std::string unobservable_proof_engine;
      std::string atpg_status = "not_run";
      std::string atpg_reason;
      std::vector<std::string> atpg_seed_blocks;

      auto append_scalar = [&](const std::vector<int>& values,
                               const std::string& source,
                               bool count_candidate) -> ScalarAppendStatus {
        const std::string bits = pattern_bits_from_values(values);
        if (emitted_bits.find(bits) != emitted_bits.end()) {
          return ScalarAppendStatus::kDuplicate;
        }
        std::vector<std::string> scalar_mismatches;
        std::string scalar_mask;
        std::vector<std::string> scalar_active_instances;
        simulate_shared(values, &scalar_mismatches, &scalar_mask,
                        &scalar_active_instances);
        if (count_candidate && scalar_mask == requested_mask) {
          ++exact_mask_candidates;
          if (!scalar_mismatches.empty()) ++observable_candidates;
        }
        if (scalar_mask != requested_mask) {
          return ScalarAppendStatus::kWrongActivationMask;
        }
        if (scalar_mismatches.empty()) {
          return ScalarAppendStatus::kNotObservable;
        }
        emitted_bits.insert(bits);
        json pattern;
        pattern["pattern_bits"] = bits;
        pattern["activation_mask"] = scalar_mask;
        pattern["activation_mask_value"] = mask_value;
        pattern["active_instances"] = scalar_active_instances;
        pattern["mismatched_outputs"] = scalar_mismatches;
        pattern["output"] = scalar_mismatches.front();
        pattern["sample_class"] = SampleClass(scalar_mask);
        pattern["requested_mask"] = requested_mask;
        pattern["witness_index"] = witnesses;
        pattern["source"] = source;
        patterns.push_back(std::move(pattern));
        ++witnesses;
        return ScalarAppendStatus::kAccepted;
      };

      auto record_scalar_rejection = [&](ScalarAppendStatus status,
                                         const std::string& source) {
        if (status == ScalarAppendStatus::kWrongActivationMask) {
          ++scalar_wrong_mask_count;
          if (atpg_reason.empty()) {
            atpg_reason = source +
                          " produced a scalar activation-mask mismatch";
          }
        } else if (status == ScalarAppendStatus::kNotObservable) {
          ++scalar_not_observable_count;
          if (atpg_reason.empty()) {
            atpg_reason = source +
                          " produced no full-PO scalar mismatch";
          }
        }
      };

      auto expand_seed = [&](const std::vector<int>& seed) {
        std::size_t single_flip_cursor = 0;
        std::vector<std::size_t> safe_flip_positions;
        std::unordered_set<std::size_t> safe_flip_position_set;
        std::set<std::pair<std::size_t, std::size_t>> generated_safe_pairs;
        for (std::size_t round = 0;
             round < 8 && witnesses < witness_target &&
             attempts < opts.max_random_attempts &&
             !positive_deadline_exceeded() && !nontrigger_positions.empty();
             ++round) {
          const std::size_t remaining_target = witness_target - witnesses;
          const std::size_t desired_batch =
              std::max<std::size_t>(64, remaining_target * 8);
          const std::size_t batch_count = std::min(
              {packed_batch_capacity, desired_batch,
               opts.max_random_attempts - attempts});
          std::vector<std::vector<int>> batch;
          batch.reserve(batch_count);
          std::vector<std::optional<std::size_t>> single_flip_metadata;
          single_flip_metadata.reserve(batch_count);
          const std::size_t remaining_single_flips =
              nontrigger_positions.size() - single_flip_cursor;
          const std::size_t single_flip_quota = std::min(
              remaining_single_flips,
              safe_flip_positions.empty() ? batch_count : batch_count / 2);
          for (std::size_t pattern_idx = 0; pattern_idx < batch_count;
               ++pattern_idx) {
            std::vector<int> candidate = seed;
            std::optional<std::size_t> single_flip_position;
            if (pattern_idx < single_flip_quota) {
              single_flip_position =
                  nontrigger_positions[single_flip_cursor++];
              candidate[*single_flip_position] ^= 1;
            } else {
              bool generated_pair = false;
              for (std::size_t first = 0;
                   !generated_pair && first < safe_flip_positions.size();
                   ++first) {
                for (std::size_t second = first + 1;
                     second < safe_flip_positions.size(); ++second) {
                  const auto pair = std::minmax(safe_flip_positions[first],
                                                safe_flip_positions[second]);
                  if (!generated_safe_pairs.insert(pair).second) continue;
                  candidate[pair.first] ^= 1;
                  candidate[pair.second] ^= 1;
                  generated_pair = true;
                  break;
                }
              }
              if (!generated_pair) {
                const std::vector<std::size_t>& flip_pool =
                    safe_flip_positions.empty() ? nontrigger_positions
                                                : safe_flip_positions;
                const std::size_t max_flips =
                    std::min<std::size_t>(8, flip_pool.size());
                const std::size_t flip_count =
                    1 + static_cast<std::size_t>(random() % max_flips);
                std::unordered_set<std::size_t> flipped;
                while (flipped.size() < flip_count) {
                  flipped.insert(static_cast<std::size_t>(random() %
                                                          flip_pool.size()));
                }
                for (std::size_t index : flipped) {
                  candidate[flip_pool[index]] ^= 1;
                }
              }
            }
            batch.push_back(std::move(candidate));
            single_flip_metadata.push_back(single_flip_position);
          }
          attempts += batch.size();
          const auto observations = screen_batch(batch);
          for (std::size_t pattern_idx = 0;
               pattern_idx < batch.size() && witnesses < witness_target;
               ++pattern_idx) {
            const auto& observation = observations[pattern_idx];
            if (observation.activation_mask != requested_mask) continue;
            ++exact_mask_candidates;
            if (!observation.output_mismatch) continue;
            ++observable_candidates;
            const std::string bits =
                pattern_bits_from_values(batch[pattern_idx]);
            if (emitted_bits.find(bits) != emitted_bits.end()) {
              if (single_flip_metadata[pattern_idx]) {
                const std::size_t position =
                    *single_flip_metadata[pattern_idx];
                if (safe_flip_position_set.insert(position).second) {
                  safe_flip_positions.push_back(position);
                }
              }
              continue;
            }
            const ScalarAppendStatus append_status = append_scalar(
                batch[pattern_idx],
                "abc_dsat_seed_packed_local_expansion_scalar_verify", false);
            if (append_status == ScalarAppendStatus::kAccepted &&
                single_flip_metadata[pattern_idx]) {
              const std::size_t position = *single_flip_metadata[pattern_idx];
              if (safe_flip_position_set.insert(position).second) {
                safe_flip_positions.push_back(position);
              }
            } else if (append_status != ScalarAppendStatus::kAccepted) {
              record_scalar_rejection(
                  append_status,
                  "packed ATPG local expansion");
            }
          }
        }
      };

      auto try_individual_seed = [&](const std::vector<int>& cec_values) {
        if (cec_values.size() != pi_order.size()) return false;
        if (trigger_mask_from_values(cec_values) == requested_mask) {
          const ScalarAppendStatus append_status = append_scalar(
              cec_values, "abc_individual_cec_exact_mask", true);
          if (append_status == ScalarAppendStatus::kAccepted) {
            ++abc_seed_count;
            used_individual_cec_seed = true;
            atpg_seed_blocks.push_back(pattern_bits_from_values(cec_values));
            expand_seed(cec_values);
            return true;
          }
          record_scalar_rejection(append_status, "individual CEC seed");
        }

        const std::size_t adaptation_count =
            std::min<std::size_t>(64, packed_batch_capacity);
        std::vector<std::vector<int>> adaptations;
        adaptations.reserve(adaptation_count);
        for (std::size_t trial = 0; trial < adaptation_count; ++trial) {
          std::vector<int> candidate = cec_values;
          const std::vector<int> exact =
              random_exact_assignment(requested_mask, partial);
          for (std::size_t position : trigger_position_set) {
            candidate[position] = exact[position];
          }
          adaptations.push_back(std::move(candidate));
        }
        attempts += adaptations.size();
        const auto observations = screen_batch(adaptations);
        for (std::size_t pattern_idx = 0;
             pattern_idx < adaptations.size(); ++pattern_idx) {
          const auto& observation = observations[pattern_idx];
          if (observation.activation_mask != requested_mask) continue;
          ++exact_mask_candidates;
          if (!observation.output_mismatch) continue;
          ++observable_candidates;
          const std::string bits =
              pattern_bits_from_values(adaptations[pattern_idx]);
          if (emitted_bits.find(bits) != emitted_bits.end()) continue;
          const ScalarAppendStatus append_status = append_scalar(
              adaptations[pattern_idx],
              "abc_individual_cec_trigger_adaptation", false);
          if (append_status != ScalarAppendStatus::kAccepted) {
            record_scalar_rejection(append_status,
                                    "packed individual CEC adaptation");
            continue;
          }
          ++abc_seed_count;
          used_individual_cec_seed = true;
          atpg_seed_blocks.push_back(
              pattern_bits_from_values(adaptations[pattern_idx]));
          expand_seed(adaptations[pattern_idx]);
          return true;
        }
        return false;
      };

      if (singleton && individual_cec[singleton_idx].status == "equivalent") {
        atpg_status = "individual_equivalent";
        globally_unobservable_proven = true;
        unobservable_proof_engine = "abc_individual_cec";
      } else if (!singleton && any_individual_equivalent) {
        atpg_status = "skipped_after_singleton_equivalence";
        atpg_reason =
            "case contains at least one globally equivalent individual Trojan";
        skip_after_singleton_equivalence = true;
      } else if (singleton &&
                 individual_cec[singleton_idx].status == "not_equivalent") {
        atpg_status = "individual_cec_seed";
        abc_mask_seconds += individual_cec[singleton_idx].elapsed_seconds;
        if (!try_individual_seed(individual_cec[singleton_idx].values)) {
          if (individual_cec[singleton_idx].values.empty()) {
            atpg_status = "individual_miter_seed_unavailable";
            atpg_reason = individual_cec[singleton_idx].seed_reason;
          } else {
            atpg_status = "individual_cec_seed_not_exact_observable";
            atpg_reason =
                "individual CEC seed could not be adapted to an exact combined mask";
          }
        }
      }

      const bool conditioned_dsat_allowed =
          abc_ready && !globally_unobservable_proven &&
          !skip_after_singleton_equivalence &&
          (all_individual_not_equivalent || singleton);
      for (std::size_t seed_attempt = 0;
           conditioned_dsat_allowed && witnesses < witness_target &&
           seed_attempt < kMaxAbcSeedAttemptsPerMask &&
           !positive_deadline_exceeded();
           ++seed_attempt) {
        const std::size_t remaining = remaining_positive_ms();
        if (remaining == 0) break;
        const AbcAtpgResult atpg = SolveAbcExactMask(
            abc_bin, abc_temp->path(), abc_base_blif, specs, pi_order,
            requested_mask, atpg_seed_blocks, abc_invocations,
            std::min<std::size_t>(opts.abc_timeout_ms, remaining));
        ++abc_invocations;
        ++abc_seed_attempts;
        abc_mask_seconds += atpg.elapsed_seconds;
        atpg_status = atpg.status == "sat" ? "abc_dsat_exact_mask" : atpg.status;
        atpg_reason = atpg.reason;
        if (atpg.status == "timeout") {
          ++abc_timeouts;
          break;
        }
        if (atpg.status == "unsat") {
          if (witnesses == 0 && atpg_seed_blocks.empty()) {
            globally_unobservable_proven = true;
            unobservable_proof_engine = "abc_dsat_exact_mask_unsat";
          }
          break;
        }
        if (atpg.status != "sat") break;

        const std::string atpg_bits =
            pattern_bits_from_values(atpg.values);
        const ScalarAppendStatus append_status =
            append_scalar(atpg.values, "abc_dsat_exact_mask", true);
        if (append_status == ScalarAppendStatus::kDuplicate) {
          ++abc_duplicate_seed_count;
          atpg_status = "abc_dsat_duplicate_witness";
          atpg_reason =
              "ABC dsat seed duplicated a previously accepted witness; "
              "the duplicate was blocked for a bounded retry";
          if (std::find(atpg_seed_blocks.begin(), atpg_seed_blocks.end(),
                        atpg_bits) != atpg_seed_blocks.end()) {
            atpg_status = "abc_dsat_repeated_blocked_witness";
            atpg_reason =
                "ABC dsat repeated a witness that was already explicitly "
                "blocked; bounded ATPG retries stopped";
            break;
          }
          atpg_seed_blocks.push_back(atpg_bits);
          continue;
        }
        if (append_status != ScalarAppendStatus::kAccepted) {
          record_scalar_rejection(append_status, "ABC dsat seed");
          std::vector<std::string> scalar_mismatches;
          std::string scalar_mask;
          std::vector<std::string> scalar_active_instances;
          simulate_shared(atpg.values, &scalar_mismatches, &scalar_mask,
                          &scalar_active_instances);
          atpg_status =
              append_status == ScalarAppendStatus::kWrongActivationMask
                  ? "abc_dsat_scalar_mask_mismatch"
                  : "abc_dsat_scalar_not_observable";
          atpg_reason = "ABC dsat seed failed independent scalar validation "
                        "(requested_mask=" +
                        requested_mask + ", actual_mask=" + scalar_mask +
                        ", mismatched_outputs=" +
                        std::to_string(scalar_mismatches.size()) +
                        "); the seed was blocked for a bounded retry";
          if (std::find(atpg_seed_blocks.begin(), atpg_seed_blocks.end(),
                        atpg_bits) != atpg_seed_blocks.end()) {
            break;
          }
          atpg_seed_blocks.push_back(atpg_bits);
          continue;
        }
        ++abc_seed_count;
        used_conditioned_dsat_seed = true;
        atpg_seed_blocks.push_back(atpg_bits);
        expand_seed(atpg.values);
      }

      const bool allow_random_fallback =
          !globally_unobservable_proven && !skip_after_singleton_equivalence;
      while (allow_random_fallback && witnesses < witness_target &&
             attempts < opts.max_random_attempts &&
             !positive_deadline_exceeded()) {
        const std::size_t batch_count = std::min(
            packed_batch_capacity, opts.max_random_attempts - attempts);
        std::vector<std::vector<int>> batch;
        batch.reserve(batch_count);
        for (std::size_t pattern_idx = 0; pattern_idx < batch_count;
             ++pattern_idx) {
          batch.push_back(random_exact_assignment(requested_mask, partial));
        }
        attempts += batch.size();
        const auto observations = screen_batch(batch);
        for (std::size_t pattern_idx = 0;
             pattern_idx < batch.size() && witnesses < witness_target;
             ++pattern_idx) {
          const auto& observation = observations[pattern_idx];
          if (observation.activation_mask != requested_mask) continue;
          ++exact_mask_candidates;
          if (!observation.output_mismatch) continue;
          ++observable_candidates;
          const std::string bits = pattern_bits_from_values(batch[pattern_idx]);
          if (emitted_bits.find(bits) != emitted_bits.end()) continue;
          const ScalarAppendStatus append_status = append_scalar(
              batch[pattern_idx],
              "constructive_exact_mask_packed_screen_scalar_verify", false);
          if (append_status != ScalarAppendStatus::kAccepted) {
            record_scalar_rejection(append_status,
                                    "packed random candidate");
          }
        }
      }

      const bool mask_complete = witnesses == witness_target;
      positive_complete = positive_complete && mask_complete;
      json result;
      result["mask"] = requested_mask;
      if (witnesses > 0) {
        result["status"] = "sat";
        result["observable_status"] = "sat";
      } else if (globally_unobservable_proven) {
        result["status"] = "unsat";
        result["observable_status"] = "unsat";
      } else if (deadline_exceeded()) {
        result["status"] = "timeout";
        result["observable_status"] = "timeout";
      } else {
        result["status"] = "unknown";
        result["observable_status"] = "unknown";
      }
      result["activation_status"] = "sat";
      result["requested_witnesses"] = witness_target;
      result["witness_count"] = witnesses;
      result["attempts"] = attempts;
      result["exact_mask_candidates"] = exact_mask_candidates;
      result["observable_candidates"] = observable_candidates;
      result["abc_seed_count"] = abc_seed_count;
      result["abc_seed_attempts"] = abc_seed_attempts;
      result["abc_seed_attempt_limit"] = kMaxAbcSeedAttemptsPerMask;
      result["abc_duplicate_seed_count"] = abc_duplicate_seed_count;
      result["scalar_wrong_mask_count"] = scalar_wrong_mask_count;
      result["scalar_not_observable_count"] =
          scalar_not_observable_count;
      result["backend_validation_status"] =
          scalar_wrong_mask_count + scalar_not_observable_count == 0
              ? "verified"
              : "mismatch_observed";
      result["abc_elapsed_seconds"] = abc_mask_seconds;
      result["atpg_status"] = atpg_status;
      if (!atpg_reason.empty()) result["atpg_reason"] = atpg_reason;
      result["exhausted"] = attempts >= opts.max_random_attempts ||
                              globally_unobservable_proven ||
                              (!mask_complete &&
                               abc_seed_attempts >=
                                   kMaxAbcSeedAttemptsPerMask);
      result["complete"] = mask_complete;
      result["engine"] =
          globally_unobservable_proven
              ? unobservable_proof_engine
              : (used_conditioned_dsat_seed
                     ? "abc_dsat_exact_mask"
                     : (used_individual_cec_seed
                            ? "abc_individual_cec"
                            : "constructive_packed_full_po_screen"));
      result["screened_output_scope"] = "all_primary_outputs";
      result["globally_unobservable_proven"] =
          globally_unobservable_proven;
      if (!mask_complete && !globally_unobservable_proven) {
        result["bounded_search_status"] =
            skip_after_singleton_equivalence
                ? "skipped_after_singleton_equivalence"
                : (deadline_exceeded()
                       ? "wall_clock_budget_exhausted"
                       : (positive_deadline_exceeded()
                              ? "positive_phase_budget_exhausted"
                              : (scalar_wrong_mask_count +
                                             scalar_not_observable_count >
                                         0
                                     ? "atpg_scalar_validation_mismatch_bounded"
                                     : (abc_seed_attempts >=
                                                kMaxAbcSeedAttemptsPerMask
                                            ? "abc_seed_retry_limit_exhausted"
                                            : "bounded_search_exhausted"))));
      }
      if (singleton) {
        result["instance_id"] = instances[singleton_idx].spec.id;
        result["individual_cec_status"] =
            individual_cec[singleton_idx].status;
        result["planning_selected_outputs"] =
            instance_selected_outputs[singleton_idx];
        result["planning_selected_outputs_used"] = false;
      }
      mask_results.push_back(std::move(result));
    }
    const bool positive_phase_budget_exhausted =
        !positive_complete && positive_deadline_exceeded();
    const double positive_phase_seconds = std::chrono::duration<double>(
                                              std::chrono::steady_clock::now() -
                                              start_time)
                                              .count();

    json trigger_checks = json::array();
    for (const auto& instance : instances) {
      trigger_checks.push_back({{"instance_id", instance.spec.id},
                                {"literal_count", instance.literals.size()},
                                {"status", "equivalent"},
                                {"method", "structural_and_literal_match"}});
    }

    struct NearCondition {
      std::size_t instance_idx = 0;
      std::size_t literal_idx = 0;
      std::vector<std::optional<int>> partial;
      std::string status = "unknown";
      std::size_t witnesses = 0;
    };
    std::vector<NearCondition> near_conditions;
    for (std::size_t instance_idx = 0; instance_idx < instances.size();
         ++instance_idx) {
      for (std::size_t literal_idx = 0;
           literal_idx < instances[instance_idx].spec.literals.size();
           ++literal_idx) {
        NearCondition condition;
        condition.instance_idx = instance_idx;
        condition.literal_idx = literal_idx;
        z3::context trigger_ctx;
        z3::solver trigger_solver(trigger_ctx);
        std::vector<z3::expr> pi_vars;
        pi_vars.reserve(pi_order.size());
        for (std::size_t i = 0; i < pi_order.size(); ++i) {
          pi_vars.push_back(
              trigger_ctx.bool_const(("trigger_pi_" + std::to_string(i)).c_str()));
        }
        const auto& selected = instances[instance_idx].spec.literals;
        for (std::size_t i = 0; i < selected.size(); ++i) {
          const bool expected =
              i == literal_idx ? !selected[i].required_value
                               : selected[i].required_value;
          trigger_solver.add(pi_vars[pi_positions.at(selected[i].net)] ==
                             trigger_ctx.bool_val(expected));
        }
        for (const auto& instance : instances) {
          z3::expr trigger_expr = trigger_ctx.bool_val(true);
          for (const auto& literal : instance.spec.literals) {
            trigger_expr =
                trigger_expr &&
                (pi_vars[pi_positions.at(literal.net)] ==
                 trigger_ctx.bool_val(literal.required_value));
          }
          trigger_solver.add(!trigger_expr);
        }
        const z3::check_result check = trigger_solver.check();
        if (check == z3::sat) {
          condition.status = "sat";
          condition.partial.assign(pi_order.size(), std::nullopt);
          const z3::model model = trigger_solver.get_model();
          std::unordered_set<std::size_t> trigger_positions;
          for (const auto& instance : instances) {
            for (const auto& literal : instance.spec.literals) {
              trigger_positions.insert(pi_positions.at(literal.net));
            }
          }
          for (std::size_t position : trigger_positions) {
            condition.partial[position] =
                model.eval(pi_vars[position], true).is_true() ? 1 : 0;
          }
        } else {
          condition.status = check == z3::unsat ? "unsat" : "unknown";
        }
        near_conditions.push_back(std::move(condition));
      }
    }

    json hard_negatives = json::array();
    std::unordered_set<std::string> negative_bits;
    const std::string inactive_mask(instances.size(), '0');
    std::size_t satisfiable_conditions = 0;
    for (const auto& condition : near_conditions) {
      if (condition.status == "sat") ++satisfiable_conditions;
    }
    const std::size_t negative_quota =
        satisfiable_conditions == 0
            ? 0
            : (opts.hard_negative_count + satisfiable_conditions - 1) /
                  satisfiable_conditions;
    auto fill_near_condition = [&](NearCondition* condition,
                                   std::size_t target) {
      std::size_t attempts = 0;
      while (condition && condition->status == "sat" &&
             condition->witnesses < target &&
             hard_negatives.size() < opts.hard_negative_count &&
             attempts < opts.max_random_attempts && !deadline_exceeded()) {
        ++attempts;
        const std::vector<int> values = random_assignment(condition->partial);
        const std::string bits = pattern_bits_from_values(values);
        if (emitted_bits.find(bits) != emitted_bits.end() ||
            negative_bits.find(bits) != negative_bits.end()) {
          continue;
        }
        const auto& target_instance = instances[condition->instance_idx].spec;
        std::size_t unsatisfied = 0;
        for (const auto& literal : target_instance.literals) {
          if (values[pi_positions.at(literal.net)] !=
              static_cast<int>(literal.required_value)) {
            ++unsatisfied;
          }
        }
        if (unsatisfied != 1) continue;

        std::vector<std::string> scalar_mismatches;
        std::string scalar_mask;
        std::vector<std::string> scalar_active_instances;
        simulate_shared(values, &scalar_mismatches, &scalar_mask,
                        &scalar_active_instances);
        if (scalar_mask != inactive_mask || !scalar_mismatches.empty() ||
            !scalar_active_instances.empty()) {
          throw std::runtime_error(
              "trigger-off hard negative failed scalar equality validation");
        }

        negative_bits.insert(bits);
        const auto& flipped =
            target_instance.literals[condition->literal_idx];
        json pattern;
        pattern["pattern_bits"] = bits;
        pattern["activation_mask"] = inactive_mask;
        pattern["activation_mask_value"] = 0;
        pattern["active_instances"] = json::array();
        pattern["mismatched_outputs"] = json::array();
        pattern["sample_class"] = "near_miss";
        pattern["label"] = 0;
        pattern["simulated_equal"] = true;
        pattern["requested_mask"] = inactive_mask;
        pattern["near_instance"] = target_instance.id;
        pattern["flipped_literal"] = {
            {"net", flipped.net},
            {"required_value", flipped.required_value ? 1 : 0}};
        pattern["source"] =
            "constructive_trigger_only_scalar_full_po_verify";
        hard_negatives.push_back(std::move(pattern));
        ++condition->witnesses;
      }
    };
    if (opts.hard_negative_count > 0) {
      for (auto& condition : near_conditions) {
        fill_near_condition(&condition, negative_quota);
      }
      for (auto& condition : near_conditions) {
        if (hard_negatives.size() >= opts.hard_negative_count ||
            deadline_exceeded()) {
          break;
        }
        fill_near_condition(
            &condition,
            condition.witnesses + opts.hard_negative_count - hard_negatives.size());
      }
    }
    const bool negative_complete =
        hard_negatives.size() == opts.hard_negative_count;
    const bool overall_budget_exhausted =
        (!positive_complete || !negative_complete) && deadline_exceeded();

    json individual_cec_json = json::array();
    for (std::size_t instance_idx = 0; instance_idx < individual_cec.size();
         ++instance_idx) {
      const auto& cec = individual_cec[instance_idx];
      json record = {{"instance_id", specs[instance_idx].id},
                     {"individual_path", specs[instance_idx].individual_path},
                     {"status", cec.status},
                     {"elapsed_seconds", cec.elapsed_seconds},
                     {"classification_seconds", cec.classification_seconds},
                     {"exit_code", cec.exit_code},
                     {"seed_status", cec.seed_status},
                     {"seed_seconds", cec.seed_seconds},
                     {"seed_exit_code", cec.seed_exit_code},
                     {"cex_available", !cec.values.empty()}};
      if (!cec.reason.empty()) record["reason"] = cec.reason;
      if (!cec.seed_reason.empty()) record["seed_reason"] = cec.seed_reason;
      individual_cec_json.push_back(std::move(record));
    }

    json root;
    root["schema_version"] = kGroundTruthSchema;
    root["case_id"] = case_id;
    root["benchmark"] = benchmark;
    root["origin_path"] = golden_relative;
    root["trojan_path"] = combined_relative;
    root["manifest_path"] = manifest_path.filename().string();
    if (const auto hash = FileHash(manifest, golden_relative)) {
      root["origin_sha256"] = *hash;
    }
    if (const auto hash = FileHash(manifest, combined_relative)) {
      root["trojan_sha256"] = *hash;
    }
    root["pi_order"] = pi_order;
    root["po_order"] = po_order;
    root["instance_order"] = json::array();
    for (const auto& instance : instances) {
      root["instance_order"].push_back(instance.spec.id);
    }
    root["mask_encoding"] =
        "N-character binary string in instance_order; character i is instance_order[i]";
    root["patterns"] = patterns;
    root["pattern_count"] = patterns.size();
    root["mask_results"] = mask_results;
    root["complete"] = positive_complete;
    root["trigger_consistency"] = trigger_checks;
    root["individual_cec"] = individual_cec_json;
    root["solver"] = {{"name", "abc_cec_dsat_with_packed_expansion"},
                      {"requested_solver_mode", opts.solver_mode},
                      {"selected_solver_mode", "constructive"},
                      {"selection_reason",
                       opts.solver_mode == "constructive"
                           ? "explicit_constructive"
                           : (auto_large_raw ? "auto_raw_node_threshold"
                                             : "auto_sparse_node_threshold")},
                      {"raw_max_node_count", raw_max_node_count},
                      {"sparse_encoded_node_count", encoded_count},
                      {"random_seed", random_seed},
                      {"random_seed_algorithm", kStableSeedAlgorithm},
                      {"max_random_attempts_per_mask", opts.max_random_attempts},
                      {"wall_clock_ms", opts.wall_clock_ms},
                      {"positive_phase_budget_ms", positive_budget_ms},
                      {"negative_phase_reserved_ms",
                       opts.wall_clock_ms - positive_budget_ms},
                      {"positive_phase_budget_exhausted",
                       positive_phase_budget_exhausted},
                      {"overall_budget_exhausted", overall_budget_exhausted},
                      {"positive_phase_seconds", positive_phase_seconds},
                      {"abc_bin", abc_bin.string()},
                      {"abc_timeout_ms_per_invocation", opts.abc_timeout_ms},
                      {"abc_setup_status", abc_setup_status},
                      {"abc_setup_seconds", abc_setup_seconds},
                      {"abc_setup_exit_code", abc_setup_exit_code},
                      {"abc_invocations", abc_invocations},
                      {"abc_timeouts", abc_timeouts},
                      {"all_individual_not_equivalent",
                       all_individual_not_equivalent},
                      {"any_individual_equivalent", any_individual_equivalent},
                      {"z3_node_threshold", opts.z3_node_threshold},
                      {"packed_batch_capacity", packed_batch_capacity},
                      {"packed_backend",
                       packed_uses_gpu
                           ? "gpu"
                           : (packed_mixed_backend ? "mixed" : "cpu")},
                      {"packed_golden_backend",
                       golden_batch.is_gpu() ? "gpu" : "cpu"},
                      {"packed_combined_backend",
                       combined_batch.is_gpu() ? "gpu" : "cpu"},
                      {"packed_golden_max_word_blocks", golden_batch.max_wb()},
                      {"packed_combined_max_word_blocks",
                       combined_batch.max_wb()},
                      {"screened_output_scope", "all_primary_outputs"},
                      {"accepted_pattern_verification", "scalar_full_po"},
                      {"witnesses_per_mask", opts.witnesses_per_mask},
                      {"mask_set",
                       opts.explicit_masks.empty() ? opts.mask_set : "explicit"}};
    if (!abc_setup_reason.empty()) {
      root["solver"]["abc_setup_reason"] = abc_setup_reason;
    }
    if (!golden_batch.gpu_init_error().empty()) {
      root["solver"]["packed_golden_init_error"] =
          golden_batch.gpu_init_error();
    }
    if (!combined_batch.gpu_init_error().empty()) {
      root["solver"]["packed_combined_init_error"] =
          combined_batch.gpu_init_error();
    }
    if (opts.witnesses_per_singleton) {
      root["solver"]["witnesses_per_singleton"] =
          *opts.witnesses_per_singleton;
    }
    if (opts.witnesses_per_pair) {
      root["solver"]["witnesses_per_pair"] = *opts.witnesses_per_pair;
    }
    if (opts.witnesses_per_all) {
      root["solver"]["witnesses_per_all"] = *opts.witnesses_per_all;
    }
    root["cone_encoding"] = {
        {"mode", cone_mode},
        {"used_for_z3", false},
        {"outputs_per_instance", opts.outputs_per_instance},
        {"output_selection", output_selection},
        {"candidate_outputs", encoded_outputs},
        {"estimated_golden_nodes", golden_encoded_count},
        {"estimated_combined_nodes", combined_encoded_count}};
    root["time"] = std::chrono::duration<double>(
                       std::chrono::steady_clock::now() - start_time)
                       .count();
    WriteJsonAtomically(output_path, root, opts.force);
    std::cout << "Wrote " << patterns.size() << " constructive witnesses to "
              << output_path << " (complete="
              << (positive_complete ? "true" : "false") << ")\n";

    if (opts.hard_negative_count > 0) {
      json condition_results = json::array();
      for (const auto& condition : near_conditions) {
        condition_results.push_back(
            {{"instance_id", instances[condition.instance_idx].spec.id},
             {"flipped_literal",
              instances[condition.instance_idx]
                  .spec.literals[condition.literal_idx]
                  .net},
             {"status", condition.status},
             {"witness_count", condition.witnesses}});
      }
      json negative_root;
      negative_root["schema_version"] = "v4-hard-negatives-1";
      negative_root["case_id"] = case_id;
      negative_root["benchmark"] = benchmark;
      negative_root["origin_path"] = golden_relative;
      negative_root["trojan_path"] = combined_relative;
      negative_root["manifest_path"] = manifest_path.filename().string();
      if (const auto hash = FileHash(manifest, golden_relative)) {
        negative_root["origin_sha256"] = *hash;
      }
      if (const auto hash = FileHash(manifest, combined_relative)) {
        negative_root["trojan_sha256"] = *hash;
      }
      negative_root["pi_order"] = pi_order;
      negative_root["instance_order"] = root["instance_order"];
      negative_root["mask_encoding"] = root["mask_encoding"];
      negative_root["patterns"] = hard_negatives;
      negative_root["pattern_count"] = hard_negatives.size();
      negative_root["generation"] = {
          {"method", "constructive_trigger_only_scalar_full_po_verify"},
          {"requested", opts.hard_negative_count},
          {"generated", hard_negatives.size()},
          {"complete", negative_complete},
          {"wall_clock_ms", opts.wall_clock_ms},
          {"phase_reserved_ms", opts.wall_clock_ms - positive_budget_ms},
          {"budget_exhausted", !negative_complete && deadline_exceeded()},
          {"random_seed", random_seed},
          {"random_seed_algorithm", kStableSeedAlgorithm},
          {"verification", "scalar_full_po_every_pattern"},
          {"conditions", condition_results}};
      negative_root["time"] = root["time"];
      WriteJsonAtomically(negative_output_path, negative_root, opts.force);
      std::cout << "Wrote " << hard_negatives.size()
                << " constructive hard negatives to " << negative_output_path
                << " (complete=" << (negative_complete ? "true" : "false")
                << ")\n";
    }
    return positive_complete && negative_complete ? 0 : 2;
  }

  z3::context ctx;
  z3::solver solver(ctx);
  z3::params params(ctx);
  params.set("timeout", opts.timeout_ms);
  solver.set(params);

  std::vector<z3::expr> shared_pi_vars;
  shared_pi_vars.reserve(pi_order.size());
  for (std::size_t i = 0; i < pi_order.size(); ++i) {
    shared_pi_vars.push_back(ctx.bool_const(("pi_" + std::to_string(i)).c_str()));
  }
  SparseEncoding golden_encoding(ctx, golden, golden_required, "g_");
  SparseEncoding combined_encoding(ctx, combined, combined_required, "t_");
  AddCircuitConstraints(ctx, golden_encoding, pi_positions, shared_pi_vars, &solver);
  AddCircuitConstraints(ctx, combined_encoding, pi_positions, shared_pi_vars, &solver);

  std::vector<z3::expr> trigger_exprs;
  trigger_exprs.reserve(instances.size());
  json trigger_checks = json::array();
  for (const auto& instance : instances) {
    z3::expr literal_expr =
        LiteralConjunction(ctx, instance, golden_encoding, combined_encoding);
    z3::expr activation_expr = literal_expr;
    json check;
    check["instance_id"] = instance.spec.id;
    check["literal_count"] = instance.literals.size();
    if (instance.combined_trigger_idx) {
      activation_expr = combined_encoding.At(*instance.combined_trigger_idx);
      solver.push();
      solver.add(activation_expr != literal_expr);
      const z3::check_result consistency = solver.check();
      std::string reason;
      const std::string status = CheckStatus(consistency, solver, &reason);
      std::string detail;
      if (status == "sat") {
        const z3::model counterexample = solver.get_model();
        detail = ", trigger_net=" +
                 counterexample.eval(activation_expr, true).to_string() +
                 ", literals=" +
                 counterexample.eval(literal_expr, true).to_string();
      }
      solver.pop();
      check["status"] = status == "unsat" ? "equivalent" : status;
      if (!reason.empty()) check["reason"] = reason;
      if (status != "unsat") {
        throw std::runtime_error(instance.spec.id +
                                 " trigger_net is not proven equivalent to manifest literals (" +
                                 status + detail + ")");
      }
    } else {
      check["status"] = "literal_only";
    }
    trigger_checks.push_back(std::move(check));
    trigger_exprs.push_back(std::move(activation_expr));
  }

  z3::expr observable = ctx.bool_val(false);
  for (const auto& output : encoded_outputs) {
    observable = observable ||
                 (golden_encoding.At(golden.node_index(output)) !=
                  combined_encoding.At(combined.node_index(output)));
  }

  json patterns = json::array();
  json mask_results = json::array();
  std::unordered_set<std::string> emitted_bits;
  bool complete = true;

  for (std::uint64_t mask_value : requested_masks) {
    const std::string requested_mask = MaskString(mask_value, instances.size());
    const std::size_t witness_target = WitnessTarget(opts, requested_mask);
    std::cout << "Solving mask " << requested_mask << "\n";
    solver.push();
    for (std::size_t i = 0; i < trigger_exprs.size(); ++i) {
      solver.add(trigger_exprs[i] == ctx.bool_val(requested_mask[i] == '1'));
    }

    MaskEnumerationResult result;
    std::string activation_reason;
    const z3::check_result activation_check = solver.check();
    result.activation_status = CheckStatus(activation_check, solver, &activation_reason);
    if (result.activation_status != "sat") {
      result.status = result.activation_status;
      result.observable_status = "unknown";
      result.reason = activation_reason;
      complete = false;
    } else {
      solver.add(observable);
      std::string last_reason;
      for (std::size_t witness = 0; witness < witness_target; ++witness) {
        const z3::check_result check_result = solver.check();
        const std::string status = CheckStatus(check_result, solver, &last_reason);
        result.observable_status = status;
        if (status != "sat") {
          result.exhausted = status == "unsat";
          break;
        }

        const z3::model model = solver.get_model();
        std::vector<int> shared_values;
        shared_values.reserve(shared_pi_vars.size());
        std::string pattern_bits;
        pattern_bits.reserve(shared_pi_vars.size());
        z3::expr block = ctx.bool_val(false);
        for (const auto& pi : shared_pi_vars) {
          const z3::expr value = model.eval(pi, true);
          const bool bit = value.is_true();
          shared_values.push_back(bit ? 1 : 0);
          pattern_bits.push_back(bit ? '1' : '0');
          block = block || (pi != ctx.bool_val(bit));
        }
        if (!emitted_bits.insert(pattern_bits).second) {
          throw std::runtime_error("solver emitted a duplicate PI pattern across masks");
        }

        const auto golden_values = LocalPiValues(golden, pi_positions, shared_values);
        const auto combined_values = LocalPiValues(combined, pi_positions, shared_values);
        const auto golden_outputs = golden.simulate(golden_values);
        const auto combined_outputs = combined.simulate(combined_values);
        if (golden_outputs.size() != po_order.size() ||
            combined_outputs.size() != po_order.size()) {
          throw std::runtime_error("simulation PO count mismatch");
        }

        std::vector<std::string> mismatched_outputs;
        for (std::size_t i = 0; i < po_order.size(); ++i) {
          if (golden_outputs[i] != combined_outputs[i]) {
            mismatched_outputs.push_back(po_order[i]);
          }
        }
        if (mismatched_outputs.empty()) {
          throw std::runtime_error("Z3 witness failed scalar PO observability check");
        }

        std::string actual_mask(instances.size(), '0');
        std::vector<std::string> active_instances;
        for (std::size_t i = 0; i < instances.size(); ++i) {
          if (EvaluateResolvedInstance(instances[i], golden, combined)) {
            actual_mask[i] = '1';
            active_instances.push_back(instances[i].spec.id);
          }
        }
        if (actual_mask != requested_mask) {
          throw std::runtime_error("Z3 witness failed scalar activation check: requested " +
                                   requested_mask + ", got " + actual_mask);
        }

        json pattern;
        pattern["pattern_bits"] = pattern_bits;
        pattern["activation_mask"] = actual_mask;
        pattern["activation_mask_value"] = mask_value;
        pattern["active_instances"] = active_instances;
        pattern["mismatched_outputs"] = mismatched_outputs;
        pattern["output"] = mismatched_outputs.front();
        pattern["sample_class"] = SampleClass(actual_mask);
        pattern["requested_mask"] = requested_mask;
        pattern["witness_index"] = witness;
        pattern["source"] = "z3_exact_mask_miter";
        patterns.push_back(std::move(pattern));
        ++result.witness_count;
        solver.add(block);
      }
      if (result.observable_status == "unsat") {
        result.observable_status = "selected_output_unsat";
      }
      result.status = result.witness_count > 0
                          ? "sat"
                          : (result.observable_status == "selected_output_unsat"
                                 ? "unknown"
                                 : result.observable_status);
      if (result.witness_count < witness_target) complete = false;
      result.reason = last_reason;
    }
    solver.pop();

    json mask_result;
    mask_result["mask"] = requested_mask;
    mask_result["status"] = result.status;
    mask_result["activation_status"] = result.activation_status;
    mask_result["observable_status"] = result.observable_status;
    mask_result["requested_witnesses"] = witness_target;
    mask_result["witness_count"] = result.witness_count;
    mask_result["exhausted"] = result.exhausted;
    mask_result["complete"] = result.witness_count == witness_target;
    if (result.observable_status == "selected_output_unsat") {
      mask_result["bounded_search_status"] = "selected_output_unsat";
      mask_result["globally_unobservable_proven"] = false;
      mask_result["global_observability_status"] = "not_checked";
    } else if (result.witness_count < witness_target &&
               result.activation_status == "sat") {
      mask_result["bounded_search_status"] =
          result.observable_status == "timeout" ? "solver_timeout"
                                                  : "bounded_search_exhausted";
      mask_result["globally_unobservable_proven"] = false;
    }
    if (std::count(requested_mask.begin(), requested_mask.end(), '1') == 1) {
      const std::size_t instance_idx =
          static_cast<std::size_t>(requested_mask.find('1'));
      mask_result["instance_id"] = instances[instance_idx].spec.id;
      mask_result["selected_outputs"] = instance_selected_outputs[instance_idx];
      mask_result["selected_output_observability_failed"] =
          result.observable_status == "selected_output_unsat";
      if (result.witness_count == 0) {
        mask_result["remaining_candidates"] = json::array();
        const auto& candidates = output_candidates[instance_idx];
        const std::size_t start =
            std::min(opts.outputs_per_instance, candidates.size());
        const std::size_t end = std::min(start + 16, candidates.size());
        for (std::size_t rank = start; rank < end; ++rank) {
          mask_result["remaining_candidates"].push_back(
              {{"output", candidates[rank].name},
               {"forward_distance", candidates[rank].distance},
               {"fanin_nodes", candidates[rank].fanin_nodes}});
        }
      }
    }
    if (!result.reason.empty()) mask_result["reason"] = result.reason;
    mask_results.push_back(std::move(mask_result));
  }
  const bool positive_complete = complete;

  json hard_negatives = json::array();
  json hard_negative_conditions = json::array();
  std::unordered_set<std::string> negative_bits;
  const std::string inactive_mask(instances.size(), '0');
  std::vector<std::pair<std::size_t, std::size_t>> near_miss_conditions;
  for (std::size_t instance_idx = 0; instance_idx < instances.size(); ++instance_idx) {
    for (std::size_t literal_idx = 0;
         literal_idx < instances[instance_idx].literals.size(); ++literal_idx) {
      near_miss_conditions.emplace_back(instance_idx, literal_idx);
    }
  }

  auto literal_var = [&](const ResolvedLiteral& literal) -> const z3::expr& {
    return literal.side == CircuitSide::kCombined
               ? combined_encoding.At(literal.node_idx)
               : golden_encoding.At(literal.node_idx);
  };
  auto add_near_miss_constraints = [&](std::size_t instance_idx,
                                       std::size_t flipped_literal) {
    const auto& selected = instances[instance_idx];
    for (std::size_t literal_idx = 0; literal_idx < selected.literals.size();
         ++literal_idx) {
      const auto& literal = selected.literals[literal_idx];
      const bool expected = literal_idx == flipped_literal
                                ? !literal.required_value
                                : literal.required_value;
      solver.add(literal_var(literal) == ctx.bool_val(expected));
    }
    for (const auto& trigger : trigger_exprs) solver.add(!trigger);
    solver.add(!observable);
  };
  auto assignment_block = [&](const std::string& bits) {
    z3::expr block = ctx.bool_val(false);
    for (std::size_t i = 0; i < bits.size(); ++i) {
      block = block || (shared_pi_vars[i] != ctx.bool_val(bits[i] == '1'));
    }
    return block;
  };
  auto append_hard_negative = [&](const z3::model& model,
                                  std::size_t instance_idx,
                                  std::size_t literal_idx,
                                  std::string* bits_out) -> bool {
    std::vector<int> shared_values;
    shared_values.reserve(shared_pi_vars.size());
    std::string bits;
    bits.reserve(shared_pi_vars.size());
    for (const auto& pi : shared_pi_vars) {
      const bool bit = model.eval(pi, true).is_true();
      shared_values.push_back(bit ? 1 : 0);
      bits.push_back(bit ? '1' : '0');
    }
    if (bits_out) *bits_out = bits;
    if (emitted_bits.find(bits) != emitted_bits.end() ||
        !negative_bits.insert(bits).second) {
      return false;
    }

    const auto golden_values = LocalPiValues(golden, pi_positions, shared_values);
    const auto combined_values = LocalPiValues(combined, pi_positions, shared_values);
    const auto golden_outputs = golden.simulate(golden_values);
    const auto combined_outputs = combined.simulate(combined_values);
    if (golden_outputs != combined_outputs) {
      throw std::runtime_error("near-miss hard negative failed scalar golden==combined check");
    }
    for (const auto& instance : instances) {
      if (EvaluateResolvedInstance(instance, golden, combined)) {
        throw std::runtime_error("near-miss hard negative unexpectedly activated " +
                                 instance.spec.id);
      }
    }
    std::size_t unsatisfied = 0;
    for (const auto& literal : instances[instance_idx].literals) {
      const circuit& source = literal.side == CircuitSide::kCombined ? combined : golden;
      const bool actual = source.get_cell(literal.node_idx).val != 0;
      if (actual != literal.required_value) ++unsatisfied;
    }
    if (unsatisfied != 1) {
      throw std::runtime_error("near-miss witness does not differ by exactly one literal");
    }

    const auto& flipped = instances[instance_idx].literals[literal_idx];
    json entry;
    entry["pattern_bits"] = bits;
    entry["activation_mask"] = inactive_mask;
    entry["activation_mask_value"] = 0;
    entry["active_instances"] = json::array();
    entry["mismatched_outputs"] = json::array();
    entry["sample_class"] = "near_miss";
    entry["label"] = 0;
    entry["simulated_equal"] = true;
    entry["requested_mask"] = inactive_mask;
    entry["near_instance"] = instances[instance_idx].spec.id;
    entry["flipped_literal"] = {
        {"net", flipped.net}, {"required_value", flipped.required_value ? 1 : 0}};
    entry["source"] = "z3_all_but_one_literal_equal_miter";
    hard_negatives.push_back(std::move(entry));
    return true;
  };

  if (opts.hard_negative_count > 0) {
    if (near_miss_conditions.empty()) {
      throw std::runtime_error("cannot generate hard negatives without trigger literals");
    }
    const std::size_t quota =
        (opts.hard_negative_count + near_miss_conditions.size() - 1) /
        near_miss_conditions.size();
    for (const auto& condition : near_miss_conditions) {
      if (hard_negatives.size() >= opts.hard_negative_count) break;
      const std::size_t instance_idx = condition.first;
      const std::size_t literal_idx = condition.second;
      solver.push();
      add_near_miss_constraints(instance_idx, literal_idx);
      std::size_t generated = 0;
      std::string end_status = "sat";
      std::string end_reason;
      while (generated < quota && hard_negatives.size() < opts.hard_negative_count) {
        const z3::check_result check = solver.check();
        end_status = CheckStatus(check, solver, &end_reason);
        if (end_status != "sat") break;
        const z3::model model = solver.get_model();
        std::string bits;
        const bool appended =
            append_hard_negative(model, instance_idx, literal_idx, &bits);
        solver.add(assignment_block(bits));
        if (appended) ++generated;
      }
      solver.pop();
      json condition_result;
      condition_result["instance_id"] = instances[instance_idx].spec.id;
      condition_result["flipped_literal"] =
          instances[instance_idx].literals[literal_idx].net;
      condition_result["witness_count"] = generated;
      condition_result["status"] = end_status;
      if (!end_reason.empty()) condition_result["reason"] = end_reason;
      hard_negative_conditions.push_back(std::move(condition_result));
    }

    // A condition can be UNSAT when triggers overlap. Fill any remainder from
    // other satisfiable near-miss conditions while blocking all prior vectors.
    if (hard_negatives.size() < opts.hard_negative_count) {
      for (const auto& condition : near_miss_conditions) {
        if (hard_negatives.size() >= opts.hard_negative_count) break;
        solver.push();
        add_near_miss_constraints(condition.first, condition.second);
        for (const auto& bits : negative_bits) solver.add(assignment_block(bits));
        while (hard_negatives.size() < opts.hard_negative_count) {
          const z3::check_result check = solver.check();
          if (check != z3::sat) break;
          const z3::model model = solver.get_model();
          std::string bits;
          const bool appended = append_hard_negative(
              model, condition.first, condition.second, &bits);
          solver.add(assignment_block(bits));
          if (!appended && bits.empty()) break;
        }
        solver.pop();
      }
    }
  }
  const bool negative_complete =
      hard_negatives.size() == opts.hard_negative_count;

  json root;
  root["schema_version"] = kGroundTruthSchema;
  root["case_id"] = case_id;
  root["benchmark"] = benchmark;
  root["origin_path"] = golden_relative;
  root["trojan_path"] = combined_relative;
  root["manifest_path"] = manifest_path.filename().string();
  if (const auto hash = FileHash(manifest, golden_relative)) root["origin_sha256"] = *hash;
  if (const auto hash = FileHash(manifest, combined_relative)) root["trojan_sha256"] = *hash;
  root["pi_order"] = pi_order;
  root["po_order"] = po_order;
  root["instance_order"] = json::array();
  for (const auto& instance : instances) root["instance_order"].push_back(instance.spec.id);
  root["mask_encoding"] =
      "N-character binary string in instance_order; character i is instance_order[i]";
  root["patterns"] = patterns;
  root["pattern_count"] = patterns.size();
  root["mask_results"] = mask_results;
  root["complete"] = positive_complete;
  root["trigger_consistency"] = trigger_checks;
  root["solver"] = {
      {"name", "Z3"},
      {"requested_solver_mode", opts.solver_mode},
      {"selected_solver_mode", "z3"},
      {"selection_reason",
       opts.solver_mode == "z3" ? "explicit_z3"
                                 : "auto_below_raw_and_sparse_thresholds"},
      {"raw_max_node_count", raw_max_node_count},
      {"sparse_encoded_node_count", encoded_count},
      {"timeout_ms_per_check", opts.timeout_ms},
      {"witnesses_per_mask", opts.witnesses_per_mask},
      {"mask_set", opts.explicit_masks.empty() ? opts.mask_set : "explicit"}};
  if (opts.witnesses_per_singleton) {
    root["solver"]["witnesses_per_singleton"] = *opts.witnesses_per_singleton;
  }
  if (opts.witnesses_per_pair) {
    root["solver"]["witnesses_per_pair"] = *opts.witnesses_per_pair;
  }
  if (opts.witnesses_per_all) {
    root["solver"]["witnesses_per_all"] = *opts.witnesses_per_all;
  }
  root["cone_encoding"] = {
      {"mode", cone_mode},
      {"outputs_per_instance", opts.outputs_per_instance},
      {"output_selection", output_selection},
      {"encoded_outputs", encoded_outputs},
      {"encoded_output_count", encoded_outputs.size()},
      {"total_output_count", po_order.size()},
      {"golden_encoded_nodes", golden_encoded_count},
      {"combined_encoded_nodes", combined_encoded_count},
      {"max_encoded_nodes", opts.max_encoded_nodes}};
  const auto end_time = std::chrono::steady_clock::now();
  root["time"] = std::chrono::duration<double>(end_time - start_time).count();

  WriteJsonAtomically(output_path, root, opts.force);
  std::cout << "Wrote " << patterns.size() << " witnesses to " << output_path
            << " (complete=" << (positive_complete ? "true" : "false") << ")\n";

  if (opts.hard_negative_count > 0) {
    json negative_root;
    negative_root["schema_version"] = "v4-hard-negatives-1";
    negative_root["case_id"] = case_id;
    negative_root["benchmark"] = benchmark;
    negative_root["origin_path"] = golden_relative;
    negative_root["trojan_path"] = combined_relative;
    negative_root["manifest_path"] = manifest_path.filename().string();
    if (const auto hash = FileHash(manifest, golden_relative)) {
      negative_root["origin_sha256"] = *hash;
    }
    if (const auto hash = FileHash(manifest, combined_relative)) {
      negative_root["trojan_sha256"] = *hash;
    }
    negative_root["pi_order"] = pi_order;
    negative_root["instance_order"] = root["instance_order"];
    negative_root["mask_encoding"] = root["mask_encoding"];
    negative_root["patterns"] = hard_negatives;
    negative_root["pattern_count"] = hard_negatives.size();
    negative_root["generation"] = {
        {"method", "z3_all_but_one_literal_equal_miter"},
        {"requested", opts.hard_negative_count},
        {"generated", hard_negatives.size()},
        {"complete", negative_complete},
        {"timeout_ms_per_check", opts.timeout_ms},
        {"conditions", hard_negative_conditions}};
    negative_root["cone_encoding"] = root["cone_encoding"];
    negative_root["time"] = root["time"];
    WriteJsonAtomically(negative_output_path, negative_root, opts.force);
    std::cout << "Wrote " << hard_negatives.size() << " hard negatives to "
              << negative_output_path << " (complete="
              << (negative_complete ? "true" : "false") << ")\n";
  }
  return positive_complete && negative_complete ? 0 : 2;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    std::cout << std::unitbuf;
    const Options opts = ParseArgs(argc, argv);
    if (opts.show_help) {
      std::cout << Usage(argv[0]);
      return 0;
    }
    return Run(opts);
  } catch (const std::exception& e) {
    std::cerr << "generate_multi_gt: " << e.what() << "\n\n"
              << Usage(argv[0]);
    return 1;
  }
}
