#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "circuit.hpp"

class packed_circuit {
 public:
  using word_t = unsigned long long;
  static constexpr std::size_t kWordBits = sizeof(word_t) * 8U;

  explicit packed_circuit(circuit& base);

  void simulate(const std::vector<std::vector<int>>& patterns);
  void simulate_bits(const std::vector<word_t>& pi_bits,
                     std::size_t pattern_count);

  std::size_t pattern_count() const { return pattern_count_; }
  word_t pattern_mask() const { return pattern_mask_; }

  word_t node_bits(int node_idx) const;
  int node_value(int node_idx, std::size_t pattern_idx) const;

  word_t gate_bits(int node_idx) const;
  int gate_value(int node_idx, std::size_t pattern_idx) const;

  word_t pi_bits(std::size_t pi_pos) const;
  int pi_value(std::size_t pi_pos, std::size_t pattern_idx) const;

  word_t po_bits(std::size_t po_pos) const;
  int po_value(std::size_t po_pos, std::size_t pattern_idx) const;

  std::vector<int> pi_values(std::size_t pattern_idx) const;
  std::vector<int> po_values(std::size_t pattern_idx) const;

  const circuit& base() const { return *base_; }

  static word_t mask_for_count(std::size_t count);

 private:
  void ensure_node_index(int node_idx) const;

  circuit* base_;
  std::vector<word_t> values_;
  std::size_t pattern_count_ = 0;
  word_t pattern_mask_ = 0;
};
