#include "circuit.hpp"

#include <algorithm>
#include <queue>
#include <stdexcept>

void circuit::clear() {
  cells_.clear();
  names_.clear();
  name_to_index_.clear();
  pi_.clear();
  po_.clear();
  po_names_.clear();
  eval_order_.clear();
  unique_id_ = 0;
  gate_count_cached_ = 0;
}

int circuit::ensure_node(const std::string& name) {
  auto it = name_to_index_.find(name);
  if (it != name_to_index_.end()) {
    return it->second;
  }
  const int idx = static_cast<int>(cells_.size());
  cells_.push_back(cell{});
  names_.push_back(name);
  name_to_index_[name] = idx;
  return idx;
}

bool circuit::has_node(const std::string& name) const {
  return name_to_index_.find(name) != name_to_index_.end();
}

int circuit::node_index(const std::string& name) const {
  auto it = name_to_index_.find(name);
  if (it == name_to_index_.end()) {
    throw std::runtime_error("unknown node: " + name);
  }
  return it->second;
}

const std::string& circuit::node_name(int idx) const {
  if (idx < 0 || static_cast<std::size_t>(idx) >= names_.size()) {
    throw std::runtime_error("node index out of range");
  }
  return names_[static_cast<std::size_t>(idx)];
}

void circuit::define_pi(const std::string& name) {
  const int idx = ensure_node(name);
  if (cells_[idx].ctype != CType::UNDEF && cells_[idx].ctype != CType::PI) {
    throw std::runtime_error("redefined node: " + name);
  }
  cells_[idx].ctype = CType::PI;
  if (std::find(pi_.begin(), pi_.end(), idx) == pi_.end()) {
    pi_.push_back(idx);
  }
}

void circuit::define_const(const std::string& name, int value) {
  const int idx = ensure_node(name);
  if (cells_[idx].ctype != CType::UNDEF && cells_[idx].ctype != CType::CONST) {
    throw std::runtime_error("redefined node: " + name);
  }
  if (cells_[idx].ctype == CType::CONST && cells_[idx].val != (value ? 1 : 0)) {
    throw std::runtime_error("conflicting constant value for node: " + name);
  }
  cells_[idx].ctype = CType::CONST;
  cells_[idx].val = value ? 1 : 0;
}

void circuit::define_gate(const std::string& name, GType gtype, const std::vector<int>& inputs) {
  const int idx = ensure_node(name);
  if (cells_[idx].ctype != CType::UNDEF) {
    throw std::runtime_error("redefined node: " + name);
  }
  cells_[idx].ctype = CType::GATE;
  cells_[idx].gtype = gtype;
  cells_[idx].inputs = inputs;
  eval_order_.push_back(idx);
}

void circuit::force_gate_const(int idx, int value) {
  if (idx < 0 || static_cast<std::size_t>(idx) >= cells_.size()) {
    throw std::runtime_error("node index out of range");
  }
  cell& c = cells_[idx];
  if (c.ctype != CType::GATE) {
    throw std::runtime_error("node is not a gate: " + node_name(idx));
  }
  c.ctype = CType::CONST;
  c.val = value ? 1 : 0;
  c.inputs.clear();
  gate_count_cached_ = 0;
}

void circuit::add_output_name(const std::string& name) {
  po_names_.push_back(name);
}

void circuit::finalize_outputs() {
  po_.clear();
  for (const auto& name : po_names_) {
    const int idx = node_index(name);
    if (cells_[idx].ctype == CType::UNDEF) {
      throw std::runtime_error("output references undefined node: " + name);
    }
    po_.push_back(idx);
  }
  for (std::size_t i = 0; i < cells_.size(); ++i) {
    if (cells_[i].ctype == CType::UNDEF) {
      throw std::runtime_error("undefined node: " + names_[i]);
    }
  }
  rebuild_eval_order();
}

const std::vector<int>& circuit::pi_indices() const { return pi_; }
const std::vector<int>& circuit::po_indices() const { return po_; }
std::size_t circuit::pi_count() const { return pi_.size(); }
std::size_t circuit::po_count() const { return po_.size(); }
const cell& circuit::get_cell(int idx) const { return cells_[static_cast<std::size_t>(idx)]; }
std::size_t circuit::node_count() const { return cells_.size(); }
const std::vector<int>& circuit::eval_order() const { return eval_order_; }

std::size_t circuit::level() const {
  if (cells_.empty()) {
    return 0;
  }

  std::vector<std::size_t> levels(cells_.size(), 0);
  for (int idx : eval_order_) {
    if (idx < 0 || static_cast<std::size_t>(idx) >= cells_.size()) {
      throw std::runtime_error("gate index out of range");
    }
    const cell& c = cells_[idx];
    if (c.ctype != CType::GATE) {
      continue;
    }
    if (c.inputs.empty()) {
      throw std::runtime_error("gate with no inputs: " + node_name(idx));
    }
    std::size_t max_in = 0;
    for (int input_idx : c.inputs) {
      if (input_idx < 0 || static_cast<std::size_t>(input_idx) >= levels.size()) {
        throw std::runtime_error("input index out of range for node: " + node_name(idx));
      }
      max_in = std::max(max_in, levels[static_cast<std::size_t>(input_idx)]);
    }
    levels[static_cast<std::size_t>(idx)] = max_in + 1;
  }

  std::size_t max_level = 0;
  if (!po_.empty()) {
    for (int idx : po_) {
      if (idx < 0 || static_cast<std::size_t>(idx) >= levels.size()) {
        throw std::runtime_error("output index out of range");
      }
      max_level = std::max(max_level, levels[static_cast<std::size_t>(idx)]);
    }
  } else {
    for (int idx : eval_order_) {
      if (idx < 0 || static_cast<std::size_t>(idx) >= levels.size()) {
        continue;
      }
      max_level = std::max(max_level, levels[static_cast<std::size_t>(idx)]);
    }
  }

  return max_level;
}

std::size_t circuit::area() const {
  std::size_t count = 0;
  for (const auto& c : cells_) {
    if (c.ctype == CType::GATE) {
      ++count;
    }
  }
  return count;
}

void circuit::ensure_eval_order() {
  if (gate_count_cached_ != area()) {
    rebuild_eval_order();
  }
}

void circuit::rebuild_eval_order() {
  eval_order_.clear();

  const std::size_t gate_count = area();
  if (gate_count == 0) {
    gate_count_cached_ = 0;
    return;
  }

  std::vector<int> indegree(cells_.size(), 0);
  std::vector<std::vector<int>> fanout(cells_.size());

  for (std::size_t idx = 0; idx < cells_.size(); ++idx) {
    const cell& c = cells_[idx];
    if (c.ctype != CType::GATE) {
      continue;
    }
    if (c.inputs.empty()) {
      throw std::runtime_error("gate with no inputs: " + node_name(static_cast<int>(idx)));
    }
    for (int input_idx : c.inputs) {
      if (input_idx < 0 || static_cast<std::size_t>(input_idx) >= cells_.size()) {
        throw std::runtime_error("input index out of range for node: " +
                                 node_name(static_cast<int>(idx)));
      }
      if (cells_[input_idx].ctype == CType::GATE) {
        ++indegree[idx];
        fanout[input_idx].push_back(static_cast<int>(idx));
      }
    }
  }

  std::queue<int> ready;
  for (std::size_t idx = 0; idx < cells_.size(); ++idx) {
    if (cells_[idx].ctype == CType::GATE && indegree[idx] == 0) {
      ready.push(static_cast<int>(idx));
    }
  }

  while (!ready.empty()) {
    int node_idx = ready.front();
    ready.pop();
    eval_order_.push_back(node_idx);
    for (int next_idx : fanout[node_idx]) {
      if (--indegree[next_idx] == 0) {
        ready.push(next_idx);
      }
    }
  }

  if (eval_order_.size() != gate_count) {
    throw std::runtime_error("topological sort failed: cycle detected");
  }

  gate_count_cached_ = gate_count;
}

int circuit::add_gate_auto(const std::string& prefix, GType gtype, const std::vector<int>& inputs) {
  std::string name;
  do {
    name = prefix + std::to_string(unique_id_++);
  } while (has_node(name));
  define_gate(name, gtype, inputs);
  return node_index(name);
}

int circuit::add_const_auto(const std::string& prefix, int value) {
  std::string name;
  do {
    name = prefix + std::to_string(unique_id_++);
  } while (has_node(name));
  define_const(name, value);
  return node_index(name);
}

void circuit::set_po_index(std::size_t pos, int idx) {
  if (pos >= po_.size()) {
    throw std::runtime_error("PO index out of range");
  }
  if (idx < 0 || static_cast<std::size_t>(idx) >= cells_.size()) {
    throw std::runtime_error("new PO node index out of range");
  }
  po_[pos] = idx;
  if (pos < po_names_.size()) {
    po_names_[pos] = node_name(idx);
  }
}

void circuit::replace_gate_inputs(int old_idx, int new_idx, std::size_t max_node) {
  if (old_idx == new_idx) {
    return;
  }
  if (old_idx < 0 || new_idx < 0) {
    throw std::runtime_error("gate input replacement index out of range");
  }
  const std::size_t max_limit =
      std::min(max_node, static_cast<std::size_t>(cells_.size()));
  for (std::size_t idx = 0; idx < max_limit; ++idx) {
    cell& c = cells_[idx];
    if (c.ctype != CType::GATE) {
      continue;
    }
    for (int& input_idx : c.inputs) {
      if (input_idx == old_idx) {
        input_idx = new_idx;
      }
    }
  }
}

std::vector<int> circuit::simulate(const std::vector<int>& pi_values) {
  ensure_eval_order();
  if (pi_values.size() != pi_.size()) {
    throw std::runtime_error("PI vector size mismatch");
  }

  for (auto& c : cells_) {
    if (c.ctype != CType::CONST) {
      c.val = -1;
    }
  }
  for (std::size_t i = 0; i < pi_.size(); ++i) {
    cells_[pi_[i]].val = pi_values[i] ? 1 : 0;
  }

  for (int idx : eval_order_) {
    cell& c = cells_[idx];
    if (c.ctype != CType::GATE) {
      continue;
    }
    if (c.inputs.empty()) {
      throw std::runtime_error("gate with no inputs: " + node_name(idx));
    }
    auto read_input = [&](int input_idx) -> int {
      int val = cells_[input_idx].val;
      if (val < 0) {
        throw std::runtime_error("uninitialized input for node: " + node_name(idx));
      }
      return val ? 1 : 0;
    };
    int out = 0;
    switch (c.gtype) {
      case GType::AND: {
        out = 1;
        for (int input_idx : c.inputs) {
          out &= read_input(input_idx);
        }
        break;
      }
      case GType::OR: {
        out = 0;
        for (int input_idx : c.inputs) {
          out |= read_input(input_idx);
        }
        break;
      }
      case GType::NAND: {
        out = 1;
        for (int input_idx : c.inputs) {
          out &= read_input(input_idx);
        }
        out = out ? 0 : 1;
        break;
      }
      case GType::NOR: {
        out = 0;
        for (int input_idx : c.inputs) {
          out |= read_input(input_idx);
        }
        out = out ? 0 : 1;
        break;
      }
      case GType::NOT: {
        if (c.inputs.size() != 1U) {
          throw std::runtime_error("NOT gate expects 1 input: " + node_name(idx));
        }
        out = read_input(c.inputs[0]) ? 0 : 1;
        break;
      }
      case GType::BUFF: {
        if (c.inputs.size() != 1U) {
          throw std::runtime_error("BUFF gate expects 1 input: " + node_name(idx));
        }
        out = read_input(c.inputs[0]);
        break;
      }
      case GType::XOR: {
        out = 0;
        for (int input_idx : c.inputs) {
          out ^= read_input(input_idx);
        }
        break;
      }
      case GType::XNOR: {
        out = 0;
        for (int input_idx : c.inputs) {
          out ^= read_input(input_idx);
        }
        out = out ? 0 : 1;
        break;
      }
    }
    c.val = out;
  }

  std::vector<int> outputs;
  outputs.reserve(po_.size());
  for (int idx : po_) {
    int val = cells_[idx].val;
    if (val < 0) {
      throw std::runtime_error("output not evaluated: " + node_name(idx));
    }
    outputs.push_back(val);
  }
  return outputs;
}
