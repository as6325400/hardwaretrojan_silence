#include "bench_parser.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace bench_io {
namespace {

std::string trim(const std::string& text) {
  std::size_t start = 0;
  while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start]))) {
    ++start;
  }
  std::size_t end = text.size();
  while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
    --end;
  }
  return text.substr(start, end - start);
}

bool starts_with(const std::string& text, const std::string& prefix) {
  return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

std::string to_upper(const std::string& text) {
  std::string out = text;
  for (char& c : out) {
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  }
  return out;
}

std::string to_lower(const std::string& text) {
  std::string out = text;
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

bool is_const_name(const std::string& name, int* value, std::string* canonical) {
  const std::string lower = to_lower(name);
  if (lower == "vdd") {
    if (value) {
      *value = 1;
    }
    if (canonical) {
      *canonical = "vdd";
    }
    return true;
  }
  if (lower == "gnd") {
    if (value) {
      *value = 0;
    }
    if (canonical) {
      *canonical = "gnd";
    }
    return true;
  }
  return false;
}

bool gate_type_from_string(const std::string& name, GType* out) {
  if (name == "AND") {
    *out = GType::AND;
    return true;
  }
  if (name == "OR") {
    *out = GType::OR;
    return true;
  }
  if (name == "NAND") {
    *out = GType::NAND;
    return true;
  }
  if (name == "NOR") {
    *out = GType::NOR;
    return true;
  }
  if (name == "NOT") {
    *out = GType::NOT;
    return true;
  }
  if (name == "BUFF" || name == "BUF") {
    *out = GType::BUFF;
    return true;
  }
  if (name == "XOR") {
    *out = GType::XOR;
    return true;
  }
  if (name == "XNOR") {
    *out = GType::XNOR;
    return true;
  }
  return false;
}

std::vector<std::string> split_args(const std::string& text) {
  std::vector<std::string> args;
  std::string token;
  std::stringstream ss(text);
  while (std::getline(ss, token, ',')) {
    const std::string trimmed = trim(token);
    if (!trimmed.empty()) {
      args.push_back(trimmed);
    }
  }
  return args;
}

std::string parse_parenthesized_name(const std::string& line, const std::string& keyword) {
  const std::size_t lparen = line.find('(');
  const std::size_t rparen = line.rfind(')');
  if (lparen == std::string::npos || rparen == std::string::npos || rparen <= lparen) {
    throw std::runtime_error("invalid " + keyword + " line");
  }
  return trim(line.substr(lparen + 1, rparen - lparen - 1));
}

}  // namespace

bool parse_bench_file(const std::string& path, circuit& out, std::string* error) {
  out.clear();
  std::ifstream in(path);
  if (!in) {
    if (error) {
      *error = "failed to open file: " + path;
    }
    return false;
  }

  std::string line;
  int line_no = 0;
  try {
    while (std::getline(in, line)) {
      ++line_no;
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      const std::size_t hash = line.find('#');
      if (hash != std::string::npos) {
        line = line.substr(0, hash);
      }
      line = trim(line);
      if (line.empty()) {
        continue;
      }

      if (starts_with(line, "INPUT")) {
        std::string name = parse_parenthesized_name(line, "INPUT");
        int value = 0;
        std::string canonical;
        if (is_const_name(name, &value, &canonical)) {
          out.define_const(canonical, value);
        } else {
          out.define_pi(name);
        }
        continue;
      }

      if (starts_with(line, "OUTPUT")) {
        std::string name = parse_parenthesized_name(line, "OUTPUT");
        int value = 0;
        std::string canonical;
        if (is_const_name(name, &value, &canonical)) {
          out.define_const(canonical, value);
          out.add_output_name(canonical);
        } else {
          out.add_output_name(name);
        }
        continue;
      }

      const std::size_t eq = line.find('=');
      if (eq == std::string::npos) {
        throw std::runtime_error("expected '=' in assignment");
      }
      const std::string lhs = trim(line.substr(0, eq));
      const std::string rhs = trim(line.substr(eq + 1));
      if (lhs.empty() || rhs.empty()) {
        throw std::runtime_error("empty assignment side");
      }

      const std::size_t lparen = rhs.find('(');
      if (lparen == std::string::npos) {
        int value = 0;
        std::string canonical;
        if (is_const_name(rhs, &value, &canonical)) {
          out.define_const(lhs, value);
        } else {
          const int input_idx = out.ensure_node(rhs);
          out.define_gate(lhs, GType::BUFF, std::vector<int>{input_idx});
        }
        continue;
      }

      const std::size_t rparen = rhs.rfind(')');
      if (rparen == std::string::npos || rparen <= lparen) {
        throw std::runtime_error("invalid gate line");
      }
      const std::string gate_name = trim(rhs.substr(0, lparen));
      const std::string args_text = rhs.substr(lparen + 1, rparen - lparen - 1);
      const std::string gate_upper = to_upper(gate_name);
      GType gtype = GType::AND;
      if (!gate_type_from_string(gate_upper, &gtype)) {
        throw std::runtime_error("unsupported gate: " + gate_name);
      }
      const std::vector<std::string> args = split_args(args_text);
      if (args.empty()) {
        throw std::runtime_error("gate with no inputs");
      }
      std::vector<int> input_indices;
      input_indices.reserve(args.size());
      for (const auto& arg : args) {
        int value = 0;
        std::string canonical;
        if (is_const_name(arg, &value, &canonical)) {
          out.define_const(canonical, value);
          input_indices.push_back(out.node_index(canonical));
        } else {
          input_indices.push_back(out.ensure_node(arg));
        }
      }
      out.define_gate(lhs, gtype, input_indices);
    }

    out.finalize_outputs();
    return true;
  } catch (const std::exception& e) {
    if (error) {
      *error = "line " + std::to_string(line_no) + ": " + e.what();
    }
    return false;
  }
}

}  // namespace bench_io
