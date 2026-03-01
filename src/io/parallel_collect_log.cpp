#include "parallel_collect_log.hpp"

#include <fstream>
#include <stdexcept>
#include <sstream>

namespace {

std::optional<std::string> GetStringField(const json& obj,
                                          const std::string& key) {
  auto it = obj.find(key);
  if (it == obj.end() || !it->is_string()) {
    return std::nullopt;
  }
  return it->get<std::string>();
}

}  // namespace

ParallelCollectLog::ParallelCollectLog(const std::string& path) : path_(path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("Unable to open file: " + path);
  }
  json root = json::parse(input);
  if (!root.is_object()) {
    throw std::runtime_error("Top-level JSON value is not an object");
  }

  auto patterns_it = root.find("patterns");
  if (patterns_it != root.end() && patterns_it->is_array()) {
    for (auto& elem : *patterns_it) {
      patterns_.push_back(std::move(elem));
    }
  }

  auto pi_it = root.find("pi_order");
  if (pi_it != root.end() && pi_it->is_array()) {
    for (const auto& value : *pi_it) {
      if (value.is_string()) {
        pi_order_.push_back(value.get<std::string>());
      }
    }
  }

  auto time_it = root.find("time");
  if (time_it != root.end() && time_it->is_number()) {
    elapsed_seconds_ = time_it->get<double>();
  }

  auto benchmark_it = root.find("benchmark");
  if (benchmark_it != root.end() && benchmark_it->is_string()) {
    benchmark_ = benchmark_it->get<std::string>();
  }

  auto round_it = root.find("round");
  if (round_it != root.end() && round_it->is_number()) {
    round_ = round_it->get<int>();
  }

  auto origin_it = root.find("origin_path");
  if (origin_it != root.end() && origin_it->is_string()) {
    origin_path_ = origin_it->get<std::string>();
  }

  auto trojan_it = root.find("trojan_path");
  if (trojan_it != root.end() && trojan_it->is_string()) {
    trojan_path_ = trojan_it->get<std::string>();
  }
}

const json& ParallelCollectLog::get_pattern(int index,
                                            bool one_based) const {
  int idx = one_based ? index - 1 : index;
  if (idx < 0) {
    idx = static_cast<int>(patterns_.size()) + idx;
  }
  if (idx < 0 || idx >= static_cast<int>(patterns_.size())) {
    throw std::out_of_range("pattern index out of range");
  }
  return patterns_[static_cast<std::size_t>(idx)];
}

std::optional<std::string> ParallelCollectLog::get_pattern_bits(
    int index,
    bool one_based) const {
  const json& entry = get_pattern(index, one_based);
  return GetStringField(entry, "pattern_bits");
}

std::unordered_map<std::string, int> ParallelCollectLog::get_pattern_inputs(
    int index,
    bool one_based) const {
  std::optional<std::string> bits = get_pattern_bits(index, one_based);
  if (!bits) {
    throw std::runtime_error("pattern_bits not found for this entry");
  }
  return pattern_bits_to_dict(*bits);
}

std::unordered_map<std::string, int> ParallelCollectLog::pattern_bits_to_dict(
    const std::string& pattern_bits) const {
  if (pi_order_.empty()) {
    throw std::runtime_error("pi_order not available in this log");
  }
  if (pattern_bits.size() != pi_order_.size()) {
    throw std::runtime_error("pattern_bits length does not match pi_order");
  }
  std::unordered_map<std::string, int> result;
  result.reserve(pi_order_.size());
  for (std::size_t i = 0; i < pi_order_.size(); ++i) {
    result[pi_order_[i]] = (pattern_bits[i] == '1') ? 1 : 0;
  }
  return result;
}

std::unordered_set<std::string> ParallelCollectLog::unique_pattern_bits()
    const {
  std::unordered_set<std::string> bits;
  for (const auto& entry : patterns_) {
    auto pattern_bits = GetStringField(entry, "pattern_bits");
    if (pattern_bits) {
      bits.insert(*pattern_bits);
    }
  }
  return bits;
}

std::unordered_set<ErrorKey, ErrorKeyHash>
ParallelCollectLog::unique_error_keys() const {
  std::unordered_set<ErrorKey, ErrorKeyHash> keys;
  for (const auto& entry : patterns_) {
    auto pattern_bits = GetStringField(entry, "pattern_bits");
    auto output = GetStringField(entry, "output");
    if (pattern_bits && output) {
      keys.insert(ErrorKey{*output, *pattern_bits});
    }
  }
  return keys;
}

std::size_t ParallelCollectLog::unique_patterns() const {
  return unique_pattern_bits().size();
}

std::size_t ParallelCollectLog::unique_errors() const {
  return unique_error_keys().size();
}

std::unordered_map<std::string, int> ParallelCollectLog::output_counts() const {
  std::unordered_map<std::string, int> counts;
  for (const auto& entry : patterns_) {
    auto output = GetStringField(entry, "output");
    if (!output) {
      continue;
    }
    ++counts[*output];
  }
  return counts;
}

std::vector<const json*> ParallelCollectLog::filter_by_output(
    const std::string& output) const {
  std::vector<const json*> results;
  for (const auto& entry : patterns_) {
    auto entry_output = GetStringField(entry, "output");
    if (entry_output && *entry_output == output) {
      results.push_back(&entry);
    }
  }
  return results;
}

std::vector<const json*> ParallelCollectLog::find_by_pattern_bits(
    const std::string& pattern_bits) const {
  std::vector<const json*> results;
  for (const auto& entry : patterns_) {
    auto entry_bits = GetStringField(entry, "pattern_bits");
    if (entry_bits && *entry_bits == pattern_bits) {
      results.push_back(&entry);
    }
  }
  return results;
}

Summary ParallelCollectLog::summary() const {
  Summary result;
  result.benchmark = benchmark_;
  result.round = round_;
  result.time_seconds = elapsed_seconds_;
  result.pattern_count = total_patterns();
  result.unique_patterns = unique_patterns();
  result.unique_errors = unique_errors();
  result.output_counts = output_counts();
  result.pi_count = pi_order_.size();
  return result;
}
