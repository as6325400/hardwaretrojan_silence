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

  // Prepare for repeated simulate_bits calls (call once before a loop).
  void prepare_batch();
  // Fast simulate that skips ensure_eval_order (call prepare_batch first).
  void simulate_bits_fast(const word_t* pi_bits, std::size_t pattern_count);

  // Multi-word-block simulation: processes num_wb * 64 patterns in one pass.
  // pi_bits layout: pi_bits[pi_index * num_wb + wb]
  // Results stored in multi_values_[node * num_wb + wb].
  // Call prepare_batch() first.
  void simulate_multi_fast(const word_t* pi_bits, std::size_t num_wb,
                           word_t last_wb_mask);

  // Accessors for multi-wb results.
  word_t node_bits_multi(int node_idx, std::size_t wb) const {
    return multi_values_[static_cast<std::size_t>(node_idx) * multi_wb_ + wb];
  }
  word_t po_bits_multi(std::size_t po_pos, std::size_t wb) const {
    return multi_values_[static_cast<std::size_t>(
        base_->po_indices()[po_pos]) * multi_wb_ + wb];
  }
  std::size_t multi_wb() const { return multi_wb_; }
  const word_t* multi_values_data() const { return multi_values_.data(); }

  std::size_t pattern_count() const { return pattern_count_; }
  word_t pattern_mask() const { return pattern_mask_; }

  const word_t* values_data() const { return values_.data(); }
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
  std::vector<word_t> multi_values_;
  std::size_t multi_wb_ = 0;
  std::size_t pattern_count_ = 0;
  word_t pattern_mask_ = 0;
};
