#include "eqn_parser.hpp"

#include <cctype>
#include <fstream>
#include <memory>
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

std::vector<std::string> split_names(const std::string& text) {
  std::string clean = text;
  for (char& c : clean) {
    if (c == ',' || c == ';') {
      c = ' ';
    }
  }
  std::stringstream ss(clean);
  std::vector<std::string> names;
  std::string token;
  while (ss >> token) {
    names.push_back(token);
  }
  return names;
}

struct Node {
  enum class Type { VAR, CONST, NOT, AND, OR };
  Type type = Type::VAR;
  std::string name;
  int value = 0;
  std::vector<std::unique_ptr<Node>> children;
};

class ExprParser {
public:
  explicit ExprParser(const std::string& text) : text_(text) {}

  std::unique_ptr<Node> parse(std::string* error) {
    error_ = error;
    auto node = parse_expr();
    skip_ws();
    if (!node || pos_ < text_.size()) {
      fail("unexpected token");
      return nullptr;
    }
    return node;
  }

private:
  std::unique_ptr<Node> parse_expr() {
    auto left = parse_term();
    if (!left) {
      return nullptr;
    }
    std::vector<std::unique_ptr<Node>> terms;
    terms.push_back(std::move(left));
    while (true) {
      skip_ws();
      if (peek() != '+') {
        break;
      }
      ++pos_;
      auto right = parse_term();
      if (!right) {
        return nullptr;
      }
      if (right->type == Node::Type::OR) {
        for (auto& child : right->children) {
          terms.push_back(std::move(child));
        }
      } else {
        terms.push_back(std::move(right));
      }
    }
    if (terms.size() == 1U) {
      return std::move(terms[0]);
    }
    auto node = std::make_unique<Node>();
    node->type = Node::Type::OR;
    node->children = std::move(terms);
    return node;
  }

  std::unique_ptr<Node> parse_term() {
    auto left = parse_factor();
    if (!left) {
      return nullptr;
    }
    std::vector<std::unique_ptr<Node>> factors;
    factors.push_back(std::move(left));
    while (true) {
      skip_ws();
      if (peek() != '*') {
        break;
      }
      ++pos_;
      auto right = parse_factor();
      if (!right) {
        return nullptr;
      }
      if (right->type == Node::Type::AND) {
        for (auto& child : right->children) {
          factors.push_back(std::move(child));
        }
      } else {
        factors.push_back(std::move(right));
      }
    }
    if (factors.size() == 1U) {
      return std::move(factors[0]);
    }
    auto node = std::make_unique<Node>();
    node->type = Node::Type::AND;
    node->children = std::move(factors);
    return node;
  }

  std::unique_ptr<Node> parse_factor() {
    skip_ws();
    char c = peek();
    if (c == '!') {
      ++pos_;
      auto child = parse_factor();
      if (!child) {
        return nullptr;
      }
      auto node = std::make_unique<Node>();
      node->type = Node::Type::NOT;
      node->children.push_back(std::move(child));
      return node;
    }
    if (c == '(') {
      ++pos_;
      auto inner = parse_expr();
      if (!inner) {
        return nullptr;
      }
      skip_ws();
      if (peek() != ')') {
        fail("missing ')'");
        return nullptr;
      }
      ++pos_;
      return inner;
    }
    std::string ident = parse_ident();
    if (ident.empty()) {
      fail("expected identifier");
      return nullptr;
    }
    auto node = std::make_unique<Node>();
    if (ident == "0" || ident == "1") {
      node->type = Node::Type::CONST;
      node->value = (ident == "1") ? 1 : 0;
    } else {
      node->type = Node::Type::VAR;
      node->name = ident;
    }
    return node;
  }

  std::string parse_ident() {
    skip_ws();
    std::size_t start = pos_;
    while (pos_ < text_.size()) {
      char c = text_[pos_];
      if (std::isspace(static_cast<unsigned char>(c)) || c == '+' || c == '*' || c == '!' ||
          c == '(' || c == ')' || c == '=') {
        break;
      }
      ++pos_;
    }
    if (pos_ == start) {
      return "";
    }
    return text_.substr(start, pos_ - start);
  }

  char peek() const {
    if (pos_ >= text_.size()) {
      return '\0';
    }
    return text_[pos_];
  }

  void skip_ws() {
    while (pos_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos_]))) {
      ++pos_;
    }
  }

  void fail(const std::string& message) {
    if (error_) {
      *error_ = message;
    }
  }

  const std::string& text_;
  std::size_t pos_ = 0;
  std::string* error_ = nullptr;
};

int ensure_const_node(circuit& net, int value) {
  const std::string name = (value != 0) ? "vdd" : "gnd";
  if (!net.has_node(name)) {
    net.define_const(name, value);
  }
  return net.node_index(name);
}

int build_node(const Node& node, circuit& net, const std::string* forced_name) {
  switch (node.type) {
    case Node::Type::VAR: {
      int idx = net.ensure_node(node.name);
      if (forced_name && *forced_name != node.name) {
        net.define_gate(*forced_name, GType::BUFF, std::vector<int>{idx});
        return net.node_index(*forced_name);
      }
      return idx;
    }
    case Node::Type::CONST: {
      if (forced_name) {
        net.define_const(*forced_name, node.value);
        return net.node_index(*forced_name);
      }
      return ensure_const_node(net, node.value);
    }
    case Node::Type::NOT: {
      if (node.children.size() != 1U) {
        throw std::runtime_error("NOT expects 1 operand");
      }
      int child = build_node(*node.children[0], net, nullptr);
      if (forced_name) {
        net.define_gate(*forced_name, GType::NOT, std::vector<int>{child});
        return net.node_index(*forced_name);
      }
      return net.add_gate_auto("eqn_not_", GType::NOT, std::vector<int>{child});
    }
    case Node::Type::AND:
    case Node::Type::OR: {
      std::vector<int> inputs;
      inputs.reserve(node.children.size());
      for (const auto& child : node.children) {
        inputs.push_back(build_node(*child, net, nullptr));
      }
      if (inputs.empty()) {
        throw std::runtime_error("AND/OR expects operands");
      }
      if (inputs.size() == 1U) {
        if (forced_name) {
          net.define_gate(*forced_name, GType::BUFF, std::vector<int>{inputs[0]});
          return net.node_index(*forced_name);
        }
        return inputs[0];
      }
      const GType gtype = (node.type == Node::Type::AND) ? GType::AND : GType::OR;
      if (forced_name) {
        net.define_gate(*forced_name, gtype, inputs);
        return net.node_index(*forced_name);
      }
      return net.add_gate_auto("eqn_gate_", gtype, inputs);
    }
  }
  throw std::runtime_error("unknown node type");
}

}  // namespace

bool parse_eqn_file(const std::string& path, circuit& out, std::string* error) {
  out.clear();
  std::ifstream in(path);
  if (!in) {
    if (error) {
      *error = "failed to open file: " + path;
    }
    return false;
  }

  std::vector<std::string> inorder;
  std::vector<std::string> outorder;
  std::vector<std::pair<std::string, std::string>> assigns;
  std::string line;
  int line_no = 0;

  try {
    std::string buffer;
    enum class ListMode { None, Inorder, Outorder };
    ListMode list_mode = ListMode::None;
    std::string list_buffer;
    auto append_list = [&](const std::string& text) {
      const std::string chunk = trim(text);
      if (chunk.empty()) {
        return;
      }
      if (!list_buffer.empty()) {
        list_buffer += ' ';
      }
      list_buffer += chunk;
    };
    auto flush_list = [&](ListMode mode) {
      if (list_buffer.empty()) {
        list_mode = ListMode::None;
        return;
      }
      const auto names = split_names(list_buffer);
      if (mode == ListMode::Inorder) {
        inorder.insert(inorder.end(), names.begin(), names.end());
      } else if (mode == ListMode::Outorder) {
        outorder.insert(outorder.end(), names.begin(), names.end());
      }
      list_buffer.clear();
      list_mode = ListMode::None;
    };
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
      if (!line.empty() && line.back() == '\\') {
        line.pop_back();
        buffer += line;
        continue;
      }
      if (!buffer.empty()) {
        line = buffer + line;
        buffer.clear();
      }
      line = trim(line);
      if (line.empty()) {
        continue;
      }

      if (list_mode != ListMode::None) {
        const std::size_t semi = line.find(';');
        if (semi == std::string::npos) {
          append_list(line);
          continue;
        }
        append_list(line.substr(0, semi));
        flush_list(list_mode);
        continue;
      }

      if (starts_with(line, "INORDER")) {
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) {
          throw std::runtime_error("invalid INORDER line");
        }
        const std::string rhs = trim(line.substr(eq + 1));
        const std::size_t semi = rhs.find(';');
        if (semi == std::string::npos) {
          list_mode = ListMode::Inorder;
          append_list(rhs);
        } else {
          append_list(rhs.substr(0, semi));
          flush_list(ListMode::Inorder);
        }
        continue;
      }
      if (starts_with(line, "OUTORDER")) {
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) {
          throw std::runtime_error("invalid OUTORDER line");
        }
        const std::string rhs = trim(line.substr(eq + 1));
        const std::size_t semi = rhs.find(';');
        if (semi == std::string::npos) {
          list_mode = ListMode::Outorder;
          append_list(rhs);
        } else {
          append_list(rhs.substr(0, semi));
          flush_list(ListMode::Outorder);
        }
        continue;
      }

      const std::size_t eq = line.find('=');
      if (eq == std::string::npos) {
        continue;
      }
      std::string lhs = trim(line.substr(0, eq));
      std::string rhs = trim(line.substr(eq + 1));
      if (!rhs.empty() && rhs.back() == ';') {
        rhs.pop_back();
        rhs = trim(rhs);
      }
      if (lhs.empty() || rhs.empty()) {
        throw std::runtime_error("empty assignment");
      }
      assigns.emplace_back(lhs, rhs);
    }

    for (const auto& name : inorder) {
      out.define_pi(name);
    }

    std::vector<std::string> lhs_order;
    lhs_order.reserve(assigns.size());
    for (const auto& assign : assigns) {
      lhs_order.push_back(assign.first);
      ExprParser parser(assign.second);
      std::string parse_error;
      auto expr = parser.parse(&parse_error);
      if (!expr) {
        throw std::runtime_error("parse error: " + parse_error);
      }
      build_node(*expr, out, &assign.first);
    }

    if (outorder.empty()) {
      outorder = lhs_order;
    }
    for (const auto& name : outorder) {
      out.add_output_name(name);
    }

    for (std::size_t i = 0; i < out.node_count(); ++i) {
      if (out.get_cell(static_cast<int>(i)).ctype == CType::UNDEF) {
        out.define_pi(out.node_name(static_cast<int>(i)));
      }
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
