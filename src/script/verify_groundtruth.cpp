#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../core/circuit.hpp"
#include "../core/packed_circuit.hpp"
#include "../io/bench_parser.hpp"
#include "../io/parallel_collect_log.hpp"

namespace fs = std::filesystem;

struct Options {
  std::string log_path;
  std::string golden_path;
  std::string trojan_path;
  std::size_t max_patterns = 0;
  std::size_t sample_patterns = 0;
  std::uint64_t seed = 0;
  bool seed_set = false;
  bool ignore_output = false;
  std::size_t show_failures = 10;
  bool show_help = false;
};

struct Failure {
  std::size_t index = 0;
  std::string reason;
  std::string output_name;
  std::string pattern_bits;
  std::vector<std::string> mismatched_outputs;
};

struct CheckStats {
  std::size_t total = 0;
  std::size_t simulated = 0;
  std::size_t any_mismatch = 0;
  std::size_t any_match = 0;
  std::size_t output_mismatch = 0;
  std::size_t output_match = 0;
  std::size_t output_missing = 0;
  std::size_t invalid_pattern = 0;
};

std::string Usage(const char* argv0) {
  std::ostringstream out;
  out << "Usage: " << argv0
      << " <error_patterns.json> [--golden path] [--trojan path]\n"
         "       [--max N] [--sample N] [--seed N] [--ignore-output]\n"
         "       [--show-failures N]\n";
  return out.str();
}

bool ParseArgs(int argc, char** argv, Options* opts, std::string* error) {
  if (!opts) {
    if (error) {
      *error = "options is null";
    }
    return false;
  }
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      opts->show_help = true;
      return true;
    }
    if (arg == "--golden") {
      if (i + 1 >= argc) {
        if (error) {
          *error = "--golden requires a path";
        }
        return false;
      }
      opts->golden_path = argv[++i];
      continue;
    }
    if (arg == "--trojan") {
      if (i + 1 >= argc) {
        if (error) {
          *error = "--trojan requires a path";
        }
        return false;
      }
      opts->trojan_path = argv[++i];
      continue;
    }
    if (arg == "--max") {
      if (i + 1 >= argc) {
        if (error) {
          *error = "--max requires a value";
        }
        return false;
      }
      opts->max_patterns = static_cast<std::size_t>(std::stoull(argv[++i]));
      continue;
    }
    if (arg == "--sample") {
      if (i + 1 >= argc) {
        if (error) {
          *error = "--sample requires a value";
        }
        return false;
      }
      opts->sample_patterns =
          static_cast<std::size_t>(std::stoull(argv[++i]));
      continue;
    }
    if (arg == "--seed") {
      if (i + 1 >= argc) {
        if (error) {
          *error = "--seed requires a value";
        }
        return false;
      }
      opts->seed = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      opts->seed_set = true;
      continue;
    }
    if (arg == "--ignore-output") {
      opts->ignore_output = true;
      continue;
    }
    if (arg == "--show-failures") {
      if (i + 1 >= argc) {
        if (error) {
          *error = "--show-failures requires a value";
        }
        return false;
      }
      opts->show_failures =
          static_cast<std::size_t>(std::stoull(argv[++i]));
      continue;
    }
    if (!arg.empty() && arg[0] == '-') {
      if (error) {
        *error = "unknown flag: " + arg;
      }
      return false;
    }
    if (opts->log_path.empty()) {
      opts->log_path = arg;
      continue;
    }
    if (error) {
      *error = "unexpected positional argument: " + arg;
    }
    return false;
  }
  if (opts->log_path.empty() && !opts->show_help) {
    if (error) {
      *error = "missing error_patterns.json path";
    }
    return false;
  }
  return true;
}

bool FileExists(const std::string& path) {
  std::error_code ec;
  return fs::exists(path, ec) && fs::is_regular_file(path, ec);
}

std::vector<std::string> FindByBasename(const fs::path& root,
                                        const std::string& basename) {
  std::vector<std::string> matches;
  std::error_code ec;
  if (!fs::exists(root, ec)) {
    return matches;
  }
  for (const auto& entry : fs::recursive_directory_iterator(root, ec)) {
    if (ec) {
      break;
    }
    if (!entry.is_regular_file(ec)) {
      continue;
    }
    if (entry.path().filename() == basename) {
      matches.push_back(entry.path().string());
    }
  }
  return matches;
}

fs::path ReplacePathComponent(const fs::path& path,
                              const std::string& from,
                              const std::string& to) {
  fs::path out;
  for (const auto& part : path) {
    if (part.string() == from) {
      out /= to;
    } else {
      out /= part;
    }
  }
  return out;
}

bool EndsWith(const std::string& text, const std::string& suffix) {
  if (text.size() < suffix.size()) {
    return false;
  }
  return text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::optional<std::string> GuessTrojanFromLogPath(const std::string& log_path) {
  fs::path logp(log_path);
  std::string filename = logp.filename().string();
  const std::string suffix = "_error_patterns.json";
  if (!EndsWith(filename, suffix)) {
    return std::nullopt;
  }
  std::string base = filename.substr(0, filename.size() - suffix.size());
  fs::path guessed = logp.parent_path() / (base + ".bench");
  fs::path replaced = ReplacePathComponent(guessed, "groundtruth",
                                           "trojaned_bench");
  return replaced.string();
}

std::optional<std::string> GuessGoldenFromLogPath(const std::string& log_path) {
  fs::path logp(log_path);
  fs::path parent = logp.parent_path();
  if (parent.empty()) {
    return std::nullopt;
  }
  std::string bench_name = parent.filename().string();
  if (bench_name.empty()) {
    return std::nullopt;
  }
  fs::path guessed = fs::path("benchmarks") / (bench_name + ".bench");
  return guessed.string();
}

std::optional<std::string> GetStringField(const json& obj,
                                          const std::string& key) {
  auto it = obj.find(key);
  if (it == obj.end() || !it->is_string()) {
    return std::nullopt;
  }
  return it->get<std::string>();
}

bool ResolveGoldenPath(const Options& opts,
                       const ParallelCollectLog& log,
                       const Summary& summary,
                       std::string* out,
                       std::string* error) {
  if (!opts.golden_path.empty()) {
    if (!FileExists(opts.golden_path)) {
      if (error) {
        *error = "golden bench not found: " + opts.golden_path;
      }
      return false;
    }
    *out = opts.golden_path;
    return true;
  }
  if (log.origin_path() && FileExists(*log.origin_path())) {
    *out = *log.origin_path();
    return true;
  }
  if (summary.benchmark) {
    fs::path candidate = fs::path("benchmarks") /
                         (*summary.benchmark + ".bench");
    if (FileExists(candidate.string())) {
      *out = candidate.string();
      return true;
    }
  }
  if (log.origin_path()) {
    fs::path origin(*log.origin_path());
    std::string basename = origin.filename().string();
    auto matches = FindByBasename("benchmarks", basename);
    if (matches.size() == 1U) {
      *out = matches.front();
      return true;
    }
    if (matches.size() > 1U) {
      if (error) {
        *error = "multiple golden benches found for " + basename;
      }
      return false;
    }
  }
  auto guessed = GuessGoldenFromLogPath(opts.log_path);
  if (guessed && FileExists(*guessed)) {
    *out = *guessed;
    return true;
  }
  if (error) {
    *error = "unable to resolve golden bench path; pass --golden";
  }
  return false;
}

bool ResolveTrojanPath(const Options& opts,
                       const ParallelCollectLog& log,
                       std::string* out,
                       std::string* error) {
  if (!opts.trojan_path.empty()) {
    if (!FileExists(opts.trojan_path)) {
      if (error) {
        *error = "trojan bench not found: " + opts.trojan_path;
      }
      return false;
    }
    *out = opts.trojan_path;
    return true;
  }
  if (log.trojan_path() && FileExists(*log.trojan_path())) {
    *out = *log.trojan_path();
    return true;
  }
  auto guessed = GuessTrojanFromLogPath(opts.log_path);
  if (guessed && FileExists(*guessed)) {
    *out = *guessed;
    return true;
  }
  if (log.trojan_path()) {
    fs::path trojan(*log.trojan_path());
    std::string basename = trojan.filename().string();
    auto matches = FindByBasename("trojaned_bench", basename);
    if (matches.size() == 1U) {
      *out = matches.front();
      return true;
    }
    if (matches.size() > 1U) {
      if (error) {
        std::ostringstream msg;
        msg << "multiple trojan benches found for " << basename << ":\n";
        for (const auto& path : matches) {
          msg << "  - " << path << "\n";
        }
        *error = msg.str();
      }
      return false;
    }
  }
  fs::path logp(opts.log_path);
  std::string filename = logp.filename().string();
  const std::string suffix = "_error_patterns.json";
  if (EndsWith(filename, suffix)) {
    std::string basename =
        filename.substr(0, filename.size() - suffix.size()) + ".bench";
    auto matches = FindByBasename("trojaned_bench", basename);
    if (matches.size() == 1U) {
      *out = matches.front();
      return true;
    }
    if (matches.size() > 1U) {
      if (error) {
        std::ostringstream msg;
        msg << "multiple trojan benches found for " << basename << ":\n";
        for (const auto& path : matches) {
          msg << "  - " << path << "\n";
        }
        *error = msg.str();
      }
      return false;
    }
  }
  if (error) {
    *error = "unable to resolve trojan bench path; pass --trojan";
  }
  return false;
}

bool BuildLogToCircuitMap(const circuit& net,
                          const std::vector<std::string>& log_pi_order,
                          std::vector<std::size_t>* log_to_circuit,
                          std::string* error) {
  if (error) {
    error->clear();
  }
  if (!log_to_circuit) {
    if (error) {
      *error = "log_to_circuit is null";
    }
    return false;
  }
  if (log_pi_order.empty()) {
    if (error) {
      *error = "pi_order is empty in groundtruth log";
    }
    return false;
  }
  const auto& pi_indices = net.pi_indices();
  std::unordered_map<std::string, std::size_t> pi_name_to_pos;
  pi_name_to_pos.reserve(pi_indices.size());
  for (std::size_t pos = 0; pos < pi_indices.size(); ++pos) {
    pi_name_to_pos[net.node_name(pi_indices[pos])] = pos;
  }

  log_to_circuit->clear();
  log_to_circuit->reserve(log_pi_order.size());
  std::vector<int> seen_pos(pi_indices.size(), 0);
  for (const auto& name : log_pi_order) {
    auto it = pi_name_to_pos.find(name);
    if (it == pi_name_to_pos.end()) {
      if (error) {
        *error = "pi_order entry not found in circuit: " + name;
      }
      return false;
    }
    log_to_circuit->push_back(it->second);
    if (it->second < seen_pos.size()) {
      seen_pos[it->second] += 1;
    }
  }
  for (std::size_t pos = 0; pos < seen_pos.size(); ++pos) {
    if (seen_pos[pos] == 0) {
      if (error) {
        *error = "circuit PI missing from groundtruth pi_order: " +
                 net.node_name(pi_indices[pos]);
      }
      return false;
    }
  }
  return true;
}

bool PatternBitsToValues(const std::string& bits,
                         const std::vector<std::size_t>& log_to_circuit,
                         std::size_t pi_count,
                         std::vector<int>* out,
                         std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out) {
    if (error) {
      *error = "output vector is null";
    }
    return false;
  }
  if (bits.size() != log_to_circuit.size()) {
    if (error) {
      *error = "pattern_bits length does not match pi_order";
    }
    return false;
  }
  out->assign(pi_count, 0);
  for (std::size_t i = 0; i < log_to_circuit.size(); ++i) {
    char bit = bits[i];
    if (bit != '0' && bit != '1') {
      if (error) {
        *error = "pattern_bits contains invalid character";
      }
      return false;
    }
    out->at(log_to_circuit[i]) = (bit == '1') ? 1 : 0;
  }
  return true;
}

void RecordFailure(std::vector<Failure>* failures,
                   std::size_t max_failures,
                   Failure&& failure) {
  if (!failures || max_failures == 0U) {
    return;
  }
  if (failures->size() >= max_failures) {
    return;
  }
  failures->push_back(std::move(failure));
}

int main(int argc, char** argv) {
  Options opts;
  std::string error;
  if (!ParseArgs(argc, argv, &opts, &error)) {
    std::cerr << error << "\n";
    std::cerr << Usage(argv[0]);
    return 1;
  }
  if (opts.show_help) {
    std::cout << Usage(argv[0]);
    return 0;
  }

  ParallelCollectLog log(opts.log_path);
  Summary summary = log.summary();

  std::string golden_path;
  std::string trojan_path;
  if (!ResolveGoldenPath(opts, log, summary, &golden_path, &error)) {
    std::cerr << "Failed to resolve golden bench: " << error << "\n";
    return 1;
  }
  if (!ResolveTrojanPath(opts, log, &trojan_path, &error)) {
    std::cerr << "Failed to resolve trojan bench: " << error << "\n";
    return 1;
  }

  circuit golden;
  circuit trojan;
  if (!bench_io::parse_bench_file(golden_path, golden, &error)) {
    std::cerr << "Golden parse error: " << error << "\n";
    return 1;
  }
  if (!bench_io::parse_bench_file(trojan_path, trojan, &error)) {
    std::cerr << "Trojan parse error: " << error << "\n";
    return 1;
  }

  if (golden.pi_count() != trojan.pi_count()) {
    std::cerr << "PI count mismatch between golden and trojan\n";
    return 1;
  }
  if (golden.po_count() != trojan.po_count()) {
    std::cerr << "PO count mismatch between golden and trojan\n";
    return 1;
  }

  std::vector<std::size_t> log_to_circuit;
  if (!BuildLogToCircuitMap(trojan, log.pi_order(), &log_to_circuit, &error)) {
    std::cerr << "Groundtruth pi_order mismatch: " << error << "\n";
    return 1;
  }
  if (log_to_circuit.size() != golden.pi_count()) {
    std::cerr << "Groundtruth pi_order size mismatch with circuit PIs\n";
    return 1;
  }

  std::vector<std::string> po_names;
  po_names.reserve(golden.po_count());
  std::unordered_map<std::string, std::size_t> po_name_to_pos;
  po_name_to_pos.reserve(golden.po_count());
  const auto& po_indices = golden.po_indices();
  for (std::size_t pos = 0; pos < po_indices.size(); ++pos) {
    const std::string& name = golden.node_name(po_indices[pos]);
    po_names.push_back(name);
    po_name_to_pos[name] = pos;
  }

  std::size_t available = log.size();
  if (opts.max_patterns > 0 && opts.max_patterns < available) {
    available = opts.max_patterns;
  }
  std::vector<std::size_t> indices(available);
  std::iota(indices.begin(), indices.end(), 0);
  if (opts.sample_patterns > 0 && opts.sample_patterns < indices.size()) {
    std::mt19937_64 rng;
    if (opts.seed_set) {
      rng.seed(opts.seed);
    } else {
      std::random_device rd;
      rng.seed(rd());
    }
    std::shuffle(indices.begin(), indices.end(), rng);
    indices.resize(opts.sample_patterns);
  }

  circuit golden_eval = golden;
  circuit trojan_eval = trojan;
  packed_circuit golden_packed(golden_eval);
  packed_circuit trojan_packed(trojan_eval);

  CheckStats stats;
  std::vector<Failure> failures;
  std::vector<std::vector<int>> block_patterns;
  std::vector<std::size_t> block_indices;
  std::vector<int> block_output_pos;
  std::vector<std::string> block_output_name;
  std::vector<std::string> block_bits;

  auto process_block = [&]() {
    if (block_patterns.empty()) {
      return;
    }
    bool packed_ok = true;
    std::string packed_error;
    try {
      golden_packed.simulate(block_patterns);
      trojan_packed.simulate(block_patterns);
    } catch (const std::exception& e) {
      packed_ok = false;
      packed_error = e.what();
    }

    if (!packed_ok) {
      for (std::size_t i = 0; i < block_patterns.size(); ++i) {
        stats.simulated += 1;
        bool any_mismatch = false;
        std::vector<std::string> mismatched_outputs;
        try {
          const std::vector<int> g_out =
              golden_eval.simulate(block_patterns[i]);
          const std::vector<int> t_out =
              trojan_eval.simulate(block_patterns[i]);
          for (std::size_t o = 0; o < g_out.size(); ++o) {
            if (g_out[o] != t_out[o]) {
              any_mismatch = true;
              mismatched_outputs.push_back(po_names[o]);
            }
          }
        } catch (const std::exception& e) {
          Failure failure;
          failure.index = block_indices[i];
          failure.reason = std::string("simulation error: ") + e.what();
          failure.output_name = block_output_name[i];
          failure.pattern_bits = block_bits[i];
          RecordFailure(&failures, opts.show_failures, std::move(failure));
          continue;
        }

        if (any_mismatch) {
          stats.any_mismatch += 1;
        } else {
          stats.any_match += 1;
        }

        bool output_ok = true;
        if (!opts.ignore_output) {
          int pos = block_output_pos[i];
          if (pos < 0 || static_cast<std::size_t>(pos) >= po_names.size()) {
            stats.output_missing += 1;
            output_ok = false;
          } else if (std::find(mismatched_outputs.begin(),
                               mismatched_outputs.end(),
                               po_names[static_cast<std::size_t>(pos)]) ==
                     mismatched_outputs.end()) {
            stats.output_match += 1;
            output_ok = false;
          } else {
            stats.output_mismatch += 1;
          }
        }

        if (!any_mismatch || !output_ok) {
          Failure failure;
          failure.index = block_indices[i];
          if (!any_mismatch) {
            failure.reason = "no output mismatch";
          } else if (!opts.ignore_output) {
            int pos = block_output_pos[i];
            if (pos < 0 || static_cast<std::size_t>(pos) >= po_names.size()) {
              failure.reason = "output name not found in circuit";
            } else {
              failure.reason = "expected output not mismatched";
            }
          }
          failure.output_name = block_output_name[i];
          failure.pattern_bits = block_bits[i];
          failure.mismatched_outputs = mismatched_outputs;
          RecordFailure(&failures, opts.show_failures, std::move(failure));
        }
      }

      block_patterns.clear();
      block_indices.clear();
      block_output_pos.clear();
      block_output_name.clear();
      block_bits.clear();
      return;
    }

    const std::size_t block_size = block_patterns.size();
    const packed_circuit::word_t mask =
        packed_circuit::mask_for_count(block_size);
    packed_circuit::word_t any_diff_mask = 0;
    std::vector<packed_circuit::word_t> output_diff;
    if (!opts.ignore_output || opts.show_failures > 0) {
      output_diff.resize(po_names.size(), 0);
    }
    for (std::size_t o = 0; o < po_names.size(); ++o) {
      packed_circuit::word_t diff =
          golden_packed.po_bits(o) ^ trojan_packed.po_bits(o);
      any_diff_mask |= diff;
      if (!output_diff.empty()) {
        output_diff[o] = diff;
      }
    }
    any_diff_mask &= mask;

    for (std::size_t i = 0; i < block_size; ++i) {
      stats.simulated += 1;
      const bool any_mismatch =
          ((any_diff_mask >> i) & 1ULL) != 0ULL;
      if (any_mismatch) {
        stats.any_mismatch += 1;
      } else {
        stats.any_match += 1;
      }

      bool output_ok = true;
      bool output_mismatch = false;
      if (!opts.ignore_output) {
        int pos = block_output_pos[i];
        if (pos < 0 || static_cast<std::size_t>(pos) >= po_names.size()) {
          stats.output_missing += 1;
          output_ok = false;
        } else {
          output_mismatch =
              ((output_diff[static_cast<std::size_t>(pos)] >> i) & 1ULL) !=
              0ULL;
          if (output_mismatch) {
            stats.output_mismatch += 1;
          } else {
            stats.output_match += 1;
            output_ok = false;
          }
        }
      }

      if (!any_mismatch || !output_ok) {
        Failure failure;
        failure.index = block_indices[i];
        if (!any_mismatch) {
          failure.reason = "no output mismatch";
        } else if (!opts.ignore_output) {
          int pos = block_output_pos[i];
          if (pos < 0 || static_cast<std::size_t>(pos) >= po_names.size()) {
            failure.reason = "output name not found in circuit";
          } else {
            failure.reason = "expected output not mismatched";
          }
        }
        failure.output_name = block_output_name[i];
        failure.pattern_bits = block_bits[i];
        if (!output_diff.empty()) {
          for (std::size_t o = 0; o < po_names.size(); ++o) {
            if (((output_diff[o] >> i) & 1ULL) != 0ULL) {
              failure.mismatched_outputs.push_back(po_names[o]);
            }
          }
        }
        RecordFailure(&failures, opts.show_failures, std::move(failure));
      }
    }

    block_patterns.clear();
    block_indices.clear();
    block_output_pos.clear();
    block_output_name.clear();
    block_bits.clear();
  };

  for (std::size_t idx : indices) {
    stats.total += 1;
    const json& entry =
        log.get_pattern(static_cast<int>(idx));
    auto bits_opt = log.get_pattern_bits(static_cast<int>(idx));
    if (!bits_opt) {
      stats.invalid_pattern += 1;
      Failure failure;
      failure.index = idx;
      failure.reason = "pattern_bits missing";
      auto output_opt = GetStringField(entry, "output");
      failure.output_name = output_opt ? *output_opt : "<missing>";
      RecordFailure(&failures, opts.show_failures, std::move(failure));
      continue;
    }

    std::vector<int> pi_values;
    if (!PatternBitsToValues(*bits_opt, log_to_circuit, golden.pi_count(),
                             &pi_values, &error)) {
      stats.invalid_pattern += 1;
      Failure failure;
      failure.index = idx;
      failure.reason = error;
      auto output_opt = GetStringField(entry, "output");
      failure.output_name = output_opt ? *output_opt : "<missing>";
      failure.pattern_bits = *bits_opt;
      RecordFailure(&failures, opts.show_failures, std::move(failure));
      continue;
    }

    std::string output_name = "<missing>";
    int output_pos = -1;
    auto output_opt = GetStringField(entry, "output");
    if (output_opt) {
      output_name = *output_opt;
      auto it = po_name_to_pos.find(output_name);
      if (it != po_name_to_pos.end()) {
        output_pos = static_cast<int>(it->second);
      }
    }

    block_patterns.push_back(std::move(pi_values));
    block_indices.push_back(idx);
    block_output_pos.push_back(output_pos);
    block_output_name.push_back(output_name);
    block_bits.push_back(*bits_opt);

    if (block_patterns.size() >= packed_circuit::kWordBits) {
      process_block();
    }
  }

  process_block();

  std::cout << "groundtruth: " << opts.log_path << "\n";
  std::cout << "golden: " << golden_path << "\n";
  std::cout << "trojan: " << trojan_path << "\n";
  std::cout << "patterns_total: " << stats.total << "\n";
  std::cout << "patterns_simulated: " << stats.simulated << "\n";
  std::cout << "invalid_patterns: " << stats.invalid_pattern << "\n";
  std::cout << "any_mismatch: " << stats.any_mismatch << "\n";
  std::cout << "no_mismatch: " << stats.any_match << "\n";
  if (!opts.ignore_output) {
    std::cout << "expected_output_mismatch: " << stats.output_mismatch << "\n";
    std::cout << "expected_output_match: " << stats.output_match << "\n";
    std::cout << "missing_output: " << stats.output_missing << "\n";
  }
  if (!failures.empty()) {
    std::cout << "failures_shown: " << failures.size() << "\n";
    for (const auto& failure : failures) {
      std::cout << "  - index " << failure.index << " reason "
                << failure.reason;
      if (!failure.output_name.empty()) {
        std::cout << " output " << failure.output_name;
      }
      if (!failure.pattern_bits.empty()) {
        std::cout << " bits " << failure.pattern_bits;
      }
      if (!failure.mismatched_outputs.empty()) {
        std::cout << " mismatched_outputs ";
        for (std::size_t i = 0; i < failure.mismatched_outputs.size(); ++i) {
          if (i > 0) {
            std::cout << ",";
          }
          std::cout << failure.mismatched_outputs[i];
        }
      }
      std::cout << "\n";
    }
  }

  bool ok = (stats.invalid_pattern == 0 && stats.any_match == 0);
  if (!opts.ignore_output) {
    ok = ok && (stats.output_match == 0) && (stats.output_missing == 0);
  }
  return ok ? 0 : 2;
}
