#include "matching.hpp"

#include <stdexcept>

bool apply_pattern_fix(const std::vector<int>& pattern,
                       const circuit& golden,
                       circuit& trojan,
                       std::string* error) {
  if (pattern.size() != golden.pi_count()) {
    if (error) {
      *error = "pattern size mismatch with golden PI count";
    }
    return false;
  }
  if (pattern.size() != trojan.pi_count()) {
    if (error) {
      *error = "pattern size mismatch with trojan PI count";
    }
    return false;
  }
  if (golden.po_count() != trojan.po_count()) {
    if (error) {
      *error = "PO count mismatch between golden and trojan";
    }
    return false;
  }

  circuit golden_sim = golden;
  circuit trojan_sim = trojan;

  std::vector<int> golden_outputs;
  std::vector<int> trojan_outputs;
  try {
    golden_outputs = golden_sim.simulate(pattern);
    trojan_outputs = trojan_sim.simulate(pattern);
  } catch (const std::exception& e) {
    if (error) {
      *error = std::string("simulation error: ") + e.what();
    }
    return false;
  }

  std::vector<std::size_t> mismatch_indices;
  mismatch_indices.reserve(golden_outputs.size());
  for (std::size_t i = 0; i < golden_outputs.size(); ++i) {
    if (golden_outputs[i] != trojan_outputs[i]) {
      mismatch_indices.push_back(i);
    }
  }

  if (mismatch_indices.empty()) {
    return true;
  }

  const auto& pi_indices = trojan.pi_indices();
  std::vector<int> literals;
  literals.reserve(pi_indices.size());
  for (std::size_t i = 0; i < pi_indices.size(); ++i) {
    const int value = pattern[i];
    if (value == 1) {
      literals.push_back(pi_indices[i]);
    } else if (value == 0) {
      int not_idx = trojan.add_gate_auto("match_not_", GType::NOT, std::vector<int>{pi_indices[i]});
      literals.push_back(not_idx);
    } else {
      if (error) {
        *error = "pattern value must be 0 or 1";
      }
      return false;
    }
  }

  int match_idx = -1;
  if (literals.empty()) {
    match_idx = trojan.add_const_auto("match_const_", 1);
  } else {
    std::vector<int> current = literals;
    while (current.size() > 1U) {
      std::vector<int> next;
      next.reserve((current.size() + 1U) / 2U);
      for (std::size_t i = 0; i < current.size(); i += 2U) {
        if (i + 1U < current.size()) {
          int and_idx = trojan.add_gate_auto("match_and_", GType::AND,
                                             std::vector<int>{current[i], current[i + 1U]});
          next.push_back(and_idx);
        } else {
          next.push_back(current[i]);
        }
      }
      current.swap(next);
    }
    match_idx = current[0];
  }

  int not_match_idx = -1;
  const auto& po_indices = trojan.po_indices();
  for (std::size_t pos : mismatch_indices) {
    if (pos >= po_indices.size()) {
      if (error) {
        *error = "PO index out of range during patch";
      }
      return false;
    }
    const int po_idx = po_indices[pos];
    int fixed_idx = -1;
    if (golden_outputs[pos] == 1) {
      fixed_idx = trojan.add_gate_auto("fix_or_", GType::OR, std::vector<int>{po_idx, match_idx});
    } else {
      if (not_match_idx < 0) {
        not_match_idx = trojan.add_gate_auto("match_not_", GType::NOT, std::vector<int>{match_idx});
      }
      fixed_idx = trojan.add_gate_auto("fix_and_", GType::AND, std::vector<int>{po_idx, not_match_idx});
    }
    trojan.set_po_index(pos, fixed_idx);
  }

  return true;
}
