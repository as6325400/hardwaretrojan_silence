#pragma once

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../../extern/nlohmann/json.hpp"

using json = nlohmann::json;

struct ErrorKey {
  std::string output;
  std::string pattern_bits;

  bool operator==(const ErrorKey& other) const {
    return output == other.output && pattern_bits == other.pattern_bits;
  }
};

struct ErrorKeyHash {
  std::size_t operator()(const ErrorKey& key) const {
    std::size_t h1 = std::hash<std::string>{}(key.output);
    std::size_t h2 = std::hash<std::string>{}(key.pattern_bits);
    return h1 ^ (h2 << 1);
  }
};

struct Summary {
  std::optional<std::string> benchmark;
  std::optional<int> round;
  std::optional<double> time_seconds;
  std::size_t pattern_count = 0;
  std::size_t unique_patterns = 0;
  std::size_t unique_errors = 0;
  std::unordered_map<std::string, int> output_counts;
  std::size_t pi_count = 0;
};

// Reader for logs produced by run_parallel_collect.py.
class ParallelCollectLog {
 public:
  explicit ParallelCollectLog(const std::string& path);

  std::size_t size() const { return patterns_.size(); }
  std::size_t total_patterns() const { return patterns_.size(); }
  std::optional<double> elapsed_time() const { return elapsed_seconds_; }
  const std::vector<std::string>& pi_order() const { return pi_order_; }
  const std::vector<json>& patterns() const { return patterns_; }
  const std::optional<std::string>& origin_path() const { return origin_path_; }
  const std::optional<std::string>& trojan_path() const { return trojan_path_; }

  const json& get_pattern(int index, bool one_based = false) const;
  std::optional<std::string> get_pattern_bits(int index,
                                              bool one_based = false) const;
  std::unordered_map<std::string, int> get_pattern_inputs(
      int index,
      bool one_based = false) const;
  std::unordered_map<std::string, int> pattern_bits_to_dict(
      const std::string& pattern_bits) const;
  std::unordered_set<std::string> unique_pattern_bits() const;
  std::unordered_set<ErrorKey, ErrorKeyHash> unique_error_keys() const;
  std::size_t unique_patterns() const;
  std::size_t unique_errors() const;
  std::unordered_map<std::string, int> output_counts() const;
  std::vector<const json*> filter_by_output(
      const std::string& output) const;
  std::vector<const json*> find_by_pattern_bits(
      const std::string& pattern_bits) const;
  Summary summary() const;

 private:
  std::string path_;
  std::vector<json> patterns_;
  std::vector<std::string> pi_order_;
  std::optional<double> elapsed_seconds_;
  std::optional<std::string> benchmark_;
  std::optional<int> round_;
  std::optional<std::string> origin_path_;
  std::optional<std::string> trojan_path_;
};
