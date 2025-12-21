#include "bench_writer.hpp"

#include <fstream>
#include <sstream>

namespace bench_io {
namespace {

std::string gate_name(GType type) {
  switch (type) {
    case GType::AND:
      return "AND";
    case GType::OR:
      return "OR";
    case GType::NAND:
      return "NAND";
    case GType::NOR:
      return "NOR";
    case GType::NOT:
      return "NOT";
    case GType::BUFF:
      return "BUFF";
    case GType::XOR:
      return "XOR";
    case GType::XNOR:
      return "XNOR";
  }
  return "AND";
}

bool is_builtin_const_name(const std::string& name) {
  return name == "vdd" || name == "gnd";
}

}  // namespace

bool write_bench_file(const std::string& path, circuit& net, std::string* error) {
  std::ofstream out(path);
  if (!out) {
    if (error) {
      *error = "failed to open output file: " + path;
    }
    return false;
  }

  try {
    net.ensure_eval_order();
  } catch (const std::exception& e) {
    if (error) {
      *error = std::string("topology error: ") + e.what();
    }
    return false;
  }

  for (int idx : net.pi_indices()) {
    out << "INPUT(" << net.node_name(idx) << ")\n";
  }
  out << "\n";
  for (int idx : net.po_indices()) {
    out << "OUTPUT(" << net.node_name(idx) << ")\n";
  }
  out << "\n";

  for (std::size_t i = 0; i < net.node_count(); ++i) {
    const cell& c = net.get_cell(static_cast<int>(i));
    if (c.ctype != CType::CONST) {
      continue;
    }
    const std::string name = net.node_name(static_cast<int>(i));
    if (is_builtin_const_name(name)) {
      continue;
    }
    const char* literal = (c.val != 0) ? "vdd" : "gnd";
    out << name << " = " << literal << "\n";
  }

  if (!net.eval_order().empty()) {
    out << "\n";
  }

  for (int idx : net.eval_order()) {
    const cell& c = net.get_cell(idx);
    if (c.ctype != CType::GATE) {
      continue;
    }
    if (c.inputs.empty()) {
      if (error) {
        *error = "gate has no inputs: " + net.node_name(idx);
      }
      return false;
    }
    std::ostringstream line;
    line << net.node_name(idx) << " = " << gate_name(c.gtype) << "(";
    for (std::size_t k = 0; k < c.inputs.size(); ++k) {
      if (k != 0) {
        line << ", ";
      }
      line << net.node_name(c.inputs[k]);
    }
    line << ")";
    out << line.str() << "\n";
  }

  return true;
}

}  // namespace bench_io
