#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct JsonValue {
  enum class Type { kNull, kBool, kNumber, kString, kArray, kObject };

  Type type = Type::kNull;
  bool bool_value = false;
  double number_value = 0.0;
  std::string string_value;
  std::vector<JsonValue> array_value;
  std::unordered_map<std::string, std::unique_ptr<JsonValue>> object_value;

  bool IsNull() const { return type == Type::kNull; }
  bool IsBool() const { return type == Type::kBool; }
  bool IsNumber() const { return type == Type::kNumber; }
  bool IsString() const { return type == Type::kString; }
  bool IsArray() const { return type == Type::kArray; }
  bool IsObject() const { return type == Type::kObject; }

  const JsonValue* Get(const std::string& key) const {
    if (!IsObject()) {
      return nullptr;
    }
    auto it = object_value.find(key);
    if (it == object_value.end()) {
      return nullptr;
    }
    if (!it->second) {
      return nullptr;
    }
    return it->second.get();
  }
};

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
// Example usage (reads JSON from the groundtruth folder):
// ParallelCollectLog log("groundtruth/c880_trojan0_error_patterns.json");
// auto summary = log.summary();
// auto bits = log.get_pattern_bits(0);
// auto inputs = log.get_pattern_inputs(0);
class ParallelCollectLog {
 public:
  explicit ParallelCollectLog(const std::string& path);

  std::size_t size() const { return patterns_.size(); }
  std::size_t total_patterns() const { return patterns_.size(); }
  std::optional<double> elapsed_time() const { return elapsed_seconds_; }
  const std::vector<std::string>& pi_order() const { return pi_order_; }
  const std::vector<JsonValue>& patterns() const { return patterns_; }

  const JsonValue& get_pattern(int index, bool one_based = false) const;
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
  std::vector<const JsonValue*> filter_by_output(
      const std::string& output) const;
  std::vector<const JsonValue*> find_by_pattern_bits(
      const std::string& pattern_bits) const;
  Summary summary() const;

 private:
  std::string path_;
  std::vector<JsonValue> patterns_;
  std::vector<std::string> pi_order_;
  std::optional<double> elapsed_seconds_;
  std::optional<std::string> benchmark_;
  std::optional<int> round_;
};
