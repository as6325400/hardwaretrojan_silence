#include "packed_circuit.hpp"

#include <algorithm>
#include <stdexcept>

packed_circuit::packed_circuit(circuit& base) : base_(&base) {
  static_assert(sizeof(word_t) * 8U == 64U,
                "packed_circuit requires 64-bit unsigned long long");
  base_->ensure_eval_order();
  values_.assign(base_->node_count(), 0);
}

packed_circuit::word_t packed_circuit::mask_for_count(std::size_t count) {
  if (count == 0) {
    return 0;
  }
  if (count >= kWordBits) {
    return ~word_t(0);
  }
  return (word_t(1) << count) - word_t(1);
}

void packed_circuit::ensure_node_index(int node_idx) const {
  if (node_idx < 0 ||
      static_cast<std::size_t>(node_idx) >= values_.size()) {
    throw std::runtime_error("node index out of range");
  }
}

void packed_circuit::simulate(const std::vector<std::vector<int>>& patterns) {
  const std::size_t count = patterns.size();
  if (count > kWordBits) {
    throw std::runtime_error("pattern count exceeds 64");
  }

  const auto& pi_indices = base_->pi_indices();
  for (const auto& pattern : patterns) {
    if (pattern.size() != pi_indices.size()) {
      throw std::runtime_error("PI vector size mismatch");
    }
  }

  std::vector<word_t> pi_bits(pi_indices.size(), 0);
  for (std::size_t p = 0; p < count; ++p) {
    const auto& pattern = patterns[p];
    for (std::size_t i = 0; i < pi_indices.size(); ++i) {
      if (pattern[i]) {
        pi_bits[i] |= (word_t(1) << p);
      }
    }
  }

  simulate_bits(pi_bits, count);
}

void packed_circuit::simulate_bits(const std::vector<word_t>& pi_bits,
                                   std::size_t pattern_count) {
  if (pattern_count > kWordBits) {
    throw std::runtime_error("pattern count exceeds 64");
  }

  base_->ensure_eval_order();
  if (values_.size() != base_->node_count()) {
    values_.assign(base_->node_count(), 0);
  } else {
    std::fill(values_.begin(), values_.end(), 0);
  }

  pattern_count_ = pattern_count;
  pattern_mask_ = mask_for_count(pattern_count);

  const auto& pi_indices = base_->pi_indices();
  if (pi_bits.size() != pi_indices.size()) {
    throw std::runtime_error("PI vector size mismatch");
  }

  for (std::size_t i = 0; i < pi_indices.size(); ++i) {
    const int idx = pi_indices[i];
    ensure_node_index(idx);
    values_[idx] = pi_bits[i] & pattern_mask_;
  }

  for (std::size_t idx = 0; idx < base_->node_count(); ++idx) {
    const cell& c = base_->get_cell(static_cast<int>(idx));
    if (c.ctype == CType::CONST) {
      values_[idx] = c.val ? pattern_mask_ : word_t(0);
    }
  }

  for (int idx : base_->eval_order()) {
    ensure_node_index(idx);
    const cell& c = base_->get_cell(idx);
    if (c.ctype != CType::GATE) {
      continue;
    }
    if (c.inputs.empty()) {
      throw std::runtime_error("gate with no inputs: " + base_->node_name(idx));
    }

    word_t out = 0;
    switch (c.gtype) {
      case GType::AND: {
        out = pattern_mask_;
        for (int input_idx : c.inputs) {
          ensure_node_index(input_idx);
          out &= values_[input_idx];
        }
        break;
      }
      case GType::OR: {
        out = 0;
        for (int input_idx : c.inputs) {
          ensure_node_index(input_idx);
          out |= values_[input_idx];
        }
        break;
      }
      case GType::NAND: {
        out = pattern_mask_;
        for (int input_idx : c.inputs) {
          ensure_node_index(input_idx);
          out &= values_[input_idx];
        }
        out = (~out) & pattern_mask_;
        break;
      }
      case GType::NOR: {
        out = 0;
        for (int input_idx : c.inputs) {
          ensure_node_index(input_idx);
          out |= values_[input_idx];
        }
        out = (~out) & pattern_mask_;
        break;
      }
      case GType::NOT: {
        if (c.inputs.size() != 1U) {
          throw std::runtime_error("NOT gate expects 1 input: " +
                                   base_->node_name(idx));
        }
        ensure_node_index(c.inputs[0]);
        out = (~values_[c.inputs[0]]) & pattern_mask_;
        break;
      }
      case GType::BUFF: {
        if (c.inputs.size() != 1U) {
          throw std::runtime_error("BUFF gate expects 1 input: " +
                                   base_->node_name(idx));
        }
        ensure_node_index(c.inputs[0]);
        out = values_[c.inputs[0]];
        break;
      }
      case GType::XOR: {
        out = 0;
        for (int input_idx : c.inputs) {
          ensure_node_index(input_idx);
          out ^= values_[input_idx];
        }
        break;
      }
      case GType::XNOR: {
        out = 0;
        for (int input_idx : c.inputs) {
          ensure_node_index(input_idx);
          out ^= values_[input_idx];
        }
        out = (~out) & pattern_mask_;
        break;
      }
    }
    values_[idx] = out;
  }
}

packed_circuit::word_t packed_circuit::node_bits(int node_idx) const {
  ensure_node_index(node_idx);
  return values_[node_idx];
}

int packed_circuit::node_value(int node_idx, std::size_t pattern_idx) const {
  ensure_node_index(node_idx);
  if (pattern_idx >= pattern_count_) {
    throw std::runtime_error("pattern index out of range");
  }
  return (values_[node_idx] & (word_t(1) << pattern_idx)) ? 1 : 0;
}

packed_circuit::word_t packed_circuit::gate_bits(int node_idx) const {
  ensure_node_index(node_idx);
  const cell& c = base_->get_cell(node_idx);
  if (c.ctype != CType::GATE) {
    throw std::runtime_error("node is not a gate: " + base_->node_name(node_idx));
  }
  return values_[node_idx];
}

int packed_circuit::gate_value(int node_idx, std::size_t pattern_idx) const {
  gate_bits(node_idx);
  return node_value(node_idx, pattern_idx);
}

packed_circuit::word_t packed_circuit::pi_bits(std::size_t pi_pos) const {
  const auto& pi_indices = base_->pi_indices();
  if (pi_pos >= pi_indices.size()) {
    throw std::runtime_error("PI index out of range");
  }
  return node_bits(pi_indices[pi_pos]);
}

int packed_circuit::pi_value(std::size_t pi_pos, std::size_t pattern_idx) const {
  const auto& pi_indices = base_->pi_indices();
  if (pi_pos >= pi_indices.size()) {
    throw std::runtime_error("PI index out of range");
  }
  return node_value(pi_indices[pi_pos], pattern_idx);
}

packed_circuit::word_t packed_circuit::po_bits(std::size_t po_pos) const {
  const auto& po_indices = base_->po_indices();
  if (po_pos >= po_indices.size()) {
    throw std::runtime_error("PO index out of range");
  }
  return node_bits(po_indices[po_pos]);
}

int packed_circuit::po_value(std::size_t po_pos, std::size_t pattern_idx) const {
  const auto& po_indices = base_->po_indices();
  if (po_pos >= po_indices.size()) {
    throw std::runtime_error("PO index out of range");
  }
  return node_value(po_indices[po_pos], pattern_idx);
}

std::vector<int> packed_circuit::pi_values(std::size_t pattern_idx) const {
  const auto& pi_indices = base_->pi_indices();
  std::vector<int> values;
  values.reserve(pi_indices.size());
  for (std::size_t i = 0; i < pi_indices.size(); ++i) {
    values.push_back(pi_value(i, pattern_idx));
  }
  return values;
}

std::vector<int> packed_circuit::po_values(std::size_t pattern_idx) const {
  const auto& po_indices = base_->po_indices();
  std::vector<int> values;
  values.reserve(po_indices.size());
  for (std::size_t i = 0; i < po_indices.size(); ++i) {
    values.push_back(po_value(i, pattern_idx));
  }
  return values;
}
