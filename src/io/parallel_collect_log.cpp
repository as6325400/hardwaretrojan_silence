#include "parallel_collect_log.hpp"

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace {

int HexValue(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

void AppendCodepoint(std::string& out, unsigned int codepoint) {
  if (codepoint <= 0x7F) {
    out.push_back(static_cast<char>(codepoint));
    return;
  }
  if (codepoint <= 0x7FF) {
    out.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    return;
  }
  if (codepoint <= 0xFFFF) {
    out.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    return;
  }
  if (codepoint <= 0x10FFFF) {
    out.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    return;
  }
  throw std::runtime_error("Invalid Unicode codepoint");
}

class JsonParser {
 public:
  explicit JsonParser(const std::string& input) : input_(input) {}

  JsonValue Parse() {
    SkipWhitespace();
    JsonValue value = ParseValue();
    SkipWhitespace();
    if (pos_ != input_.size()) {
      throw std::runtime_error("Trailing characters after JSON");
    }
    return value;
  }

 private:
  const std::string& input_;
  std::size_t pos_ = 0;

  char Peek() const {
    if (pos_ >= input_.size()) {
      return '\0';
    }
    return input_[pos_];
  }

  char Get() {
    if (pos_ >= input_.size()) {
      throw std::runtime_error("Unexpected end of JSON");
    }
    return input_[pos_++];
  }

  void SkipWhitespace() {
    while (pos_ < input_.size() &&
           std::isspace(static_cast<unsigned char>(input_[pos_]))) {
      ++pos_;
    }
  }

  void Expect(char expected) {
    char c = Get();
    if (c != expected) {
      std::string message = "Expected '";
      message.push_back(expected);
      message.push_back('\'');
      throw std::runtime_error(message);
    }
  }

  JsonValue ParseValue() {
    char c = Peek();
    if (c == '{') {
      return ParseObject();
    }
    if (c == '[') {
      return ParseArray();
    }
    if (c == '"') {
      JsonValue value;
      value.type = JsonValue::Type::kString;
      value.string_value = ParseString();
      return value;
    }
    if (c == 't') {
      return ParseLiteral("true", JsonValue::Type::kBool, true);
    }
    if (c == 'f') {
      return ParseLiteral("false", JsonValue::Type::kBool, false);
    }
    if (c == 'n') {
      return ParseLiteral("null", JsonValue::Type::kNull, false);
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
      return ParseNumber();
    }
    throw std::runtime_error("Invalid JSON value");
  }

  JsonValue ParseLiteral(const char* literal,
                         JsonValue::Type type,
                         bool bool_value) {
    for (std::size_t i = 0; literal[i] != '\0'; ++i) {
      if (Get() != literal[i]) {
        throw std::runtime_error("Invalid literal");
      }
    }
    JsonValue value;
    value.type = type;
    value.bool_value = bool_value;
    return value;
  }

  JsonValue ParseNumber() {
    const char* start = input_.c_str() + pos_;
    char* end = nullptr;
    double number = std::strtod(start, &end);
    if (end == start) {
      throw std::runtime_error("Invalid number");
    }
    pos_ = static_cast<std::size_t>(end - input_.c_str());
    JsonValue value;
    value.type = JsonValue::Type::kNumber;
    value.number_value = number;
    return value;
  }

  std::string ParseString() {
    Expect('"');
    std::string result;
    while (true) {
      if (pos_ >= input_.size()) {
        throw std::runtime_error("Unterminated string");
      }
      char c = Get();
      if (c == '"') {
        break;
      }
      if (c == '\\') {
        if (pos_ >= input_.size()) {
          throw std::runtime_error("Unterminated escape");
        }
        char esc = Get();
        switch (esc) {
          case '"':
            result.push_back('"');
            break;
          case '\\':
            result.push_back('\\');
            break;
          case '/':
            result.push_back('/');
            break;
          case 'b':
            result.push_back('\b');
            break;
          case 'f':
            result.push_back('\f');
            break;
          case 'n':
            result.push_back('\n');
            break;
          case 'r':
            result.push_back('\r');
            break;
          case 't':
            result.push_back('\t');
            break;
          case 'u': {
            unsigned int codepoint = 0;
            for (int i = 0; i < 4; ++i) {
              int value = HexValue(Get());
              if (value < 0) {
                throw std::runtime_error("Invalid Unicode escape");
              }
              codepoint = (codepoint << 4) | static_cast<unsigned int>(value);
            }
            AppendCodepoint(result, codepoint);
            break;
          }
          default:
            throw std::runtime_error("Invalid escape sequence");
        }
      } else {
        result.push_back(c);
      }
    }
    return result;
  }

  JsonValue ParseArray() {
    JsonValue value;
    value.type = JsonValue::Type::kArray;
    Expect('[');
    SkipWhitespace();
    if (Peek() == ']') {
      Get();
      return value;
    }
    while (true) {
      SkipWhitespace();
      value.array_value.push_back(ParseValue());
      SkipWhitespace();
      char c = Get();
      if (c == ']') {
        break;
      }
      if (c != ',') {
        throw std::runtime_error("Expected ',' or ']'");
      }
    }
    return value;
  }

  JsonValue ParseObject() {
    JsonValue value;
    value.type = JsonValue::Type::kObject;
    Expect('{');
    SkipWhitespace();
    if (Peek() == '}') {
      Get();
      return value;
    }
    while (true) {
      SkipWhitespace();
      if (Peek() != '"') {
        throw std::runtime_error("Expected string key");
      }
      std::string key = ParseString();
      SkipWhitespace();
      Expect(':');
      SkipWhitespace();
      value.object_value[std::move(key)] =
          std::make_unique<JsonValue>(ParseValue());
      SkipWhitespace();
      char c = Get();
      if (c == '}') {
        break;
      }
      if (c != ',') {
        throw std::runtime_error("Expected ',' or '}'");
      }
    }
    return value;
  }
};

std::string ReadFile(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("Unable to open file: " + path);
  }
  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

std::optional<std::string> GetStringField(const JsonValue& obj,
                                          const std::string& key) {
  const JsonValue* value = obj.Get(key);
  if (!value || !value->IsString()) {
    return std::nullopt;
  }
  return value->string_value;
}

}  // namespace

ParallelCollectLog::ParallelCollectLog(const std::string& path) : path_(path) {
  std::string contents = ReadFile(path);
  JsonParser parser(contents);
  JsonValue root = parser.Parse();
  if (!root.IsObject()) {
    throw std::runtime_error("Top-level JSON value is not an object");
  }

  auto patterns_it = root.object_value.find("patterns");
  if (patterns_it != root.object_value.end() && patterns_it->second &&
      patterns_it->second->IsArray()) {
    patterns_ = std::move(patterns_it->second->array_value);
  }

  auto pi_it = root.object_value.find("pi_order");
  if (pi_it != root.object_value.end() && pi_it->second &&
      pi_it->second->IsArray()) {
    for (const auto& value : pi_it->second->array_value) {
      if (value.IsString()) {
        pi_order_.push_back(value.string_value);
      }
    }
  }

  auto time_it = root.object_value.find("time");
  if (time_it != root.object_value.end() && time_it->second &&
      time_it->second->IsNumber()) {
    elapsed_seconds_ = time_it->second->number_value;
  }

  auto benchmark_it = root.object_value.find("benchmark");
  if (benchmark_it != root.object_value.end() && benchmark_it->second &&
      benchmark_it->second->IsString()) {
    benchmark_ = benchmark_it->second->string_value;
  }

  auto round_it = root.object_value.find("round");
  if (round_it != root.object_value.end() && round_it->second &&
      round_it->second->IsNumber()) {
    round_ = static_cast<int>(round_it->second->number_value);
  }

  auto origin_it = root.object_value.find("origin_path");
  if (origin_it != root.object_value.end() && origin_it->second &&
      origin_it->second->IsString()) {
    origin_path_ = origin_it->second->string_value;
  }

  auto trojan_it = root.object_value.find("trojan_path");
  if (trojan_it != root.object_value.end() && trojan_it->second &&
      trojan_it->second->IsString()) {
    trojan_path_ = trojan_it->second->string_value;
  }
}

const JsonValue& ParallelCollectLog::get_pattern(int index,
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
  const JsonValue& entry = get_pattern(index, one_based);
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

std::vector<const JsonValue*> ParallelCollectLog::filter_by_output(
    const std::string& output) const {
  std::vector<const JsonValue*> results;
  for (const auto& entry : patterns_) {
    auto entry_output = GetStringField(entry, "output");
    if (entry_output && *entry_output == output) {
      results.push_back(&entry);
    }
  }
  return results;
}

std::vector<const JsonValue*> ParallelCollectLog::find_by_pattern_bits(
    const std::string& pattern_bits) const {
  std::vector<const JsonValue*> results;
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
