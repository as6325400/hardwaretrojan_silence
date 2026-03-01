#pragma once

#include <cstddef>
#include <vector>

#include "circuit.hpp"

// ── GpuCircuit ────────────────────────────────────────────────────────────────
// Holds a circuit flattened into GPU-friendly CSR + topological level groups.
//
// Memory layout for node values (maximises coalesced access):
//   d_values_[ node_idx * num_wb + wb_id ]
// Consecutive threads (same node, adjacent wb_id) → coalesced 512-bit reads.
//
// simulate() runs:
//   kernel_zero_values → kernel_set_pi → kernel_set_const
//   → for each level: kernel_eval_level
class GpuCircuit {
 public:
  using word_t = unsigned long long;

  GpuCircuit(const circuit& base, std::size_t max_word_blocks);
  ~GpuCircuit();

  GpuCircuit(const GpuCircuit&)            = delete;
  GpuCircuit& operator=(const GpuCircuit&) = delete;

  // Simulate num_wb word blocks (each holds 64 patterns).
  // d_pi_bits must be a device pointer with layout [pi_idx * num_wb + wb_id].
  void simulate(const word_t* d_pi_bits, std::size_t num_wb);

  // Same as simulate() but uses a single kernel (one thread per wb).
  // Better for low-wb scenarios where kernel launch overhead dominates.
  void simulate_serial(const word_t* d_pi_bits, std::size_t num_wb);

  word_t*       d_values()            { return d_values_; }
  const word_t* d_values() const      { return d_values_; }
  const int*    d_po_indices() const  { return d_po_indices_; }

  std::size_t num_nodes()       const { return num_nodes_; }
  std::size_t num_pis()         const { return num_pis_; }
  std::size_t num_pos()         const { return num_pos_; }
  std::size_t max_word_blocks() const { return max_word_blocks_; }

 private:
  // ── device allocations ──
  word_t* d_values_     = nullptr;   // [num_nodes * max_wb]
  int*    d_pi_indices_ = nullptr;   // [num_pis]
  int*    d_po_indices_ = nullptr;   // [num_pos]
  int*    d_const_map_  = nullptr;   // [num_const]  node indices
  int*    d_const_val_  = nullptr;   // [num_const]  0 or 1

  // Gate CSR — all gates sorted by topological level
  int*    d_gate_dest_  = nullptr;   // [num_gates]
  int*    d_gate_gtype_ = nullptr;   // [num_gates]  GType as int
  int*    d_gate_ioff_  = nullptr;   // [num_gates]  offset into d_inputs_
  int*    d_gate_inum_  = nullptr;   // [num_gates]  input count
  int*    d_inputs_     = nullptr;   // [total_inputs]

  // Host-side level boundaries.
  // Gates [ level_start_[l], level_start_[l+1] ) belong to level l
  // and can be evaluated in one kernel launch (zero dependency within level).
  std::vector<int> level_start_;

  std::size_t num_nodes_       = 0;
  std::size_t num_pis_         = 0;
  std::size_t num_pos_         = 0;
  std::size_t num_const_       = 0;
  std::size_t num_gates_       = 0;
  std::size_t max_word_blocks_ = 0;
};

// ── Standalone GPU utilities ──────────────────────────────────────────────────

// Return max word blocks that fit in 80% of free VRAM for two circuits
// plus PI/feature buffers.
std::size_t gpu_compute_max_word_blocks(std::size_t golden_nodes,
                                        std::size_t trojan_nodes,
                                        std::size_t num_pis,
                                        std::size_t num_feature_nodes);

// Fill d_pi[ pi_idx * num_wb + wb_id ] with Philox random 64-bit words.
// d_pi must be a device pointer (size = num_pis * num_wb).
void gpu_generate_random_pi(GpuCircuit::word_t* d_pi,
                            std::size_t          num_pis,
                            std::size_t          num_wb,
                            unsigned long long   seed);

// diff_mask[wb] = OR_over_pos( golden_PO[o] XOR trojan_PO[o] ) & pmask.
// All pointers are device pointers.
void gpu_compare_po(const GpuCircuit& golden,
                    const GpuCircuit& trojan,
                    GpuCircuit::word_t* d_diff_mask,
                    std::size_t         num_wb,
                    GpuCircuit::word_t  pmask);

// d_out[ feat_idx * num_wb + wb_id ] = d_values[ node_indices[feat_idx] * num_wb + wb_id ].
void gpu_gather_nodes(const GpuCircuit::word_t* d_values,
                      const int*                d_node_indices,
                      std::size_t               num_gather,
                      std::size_t               num_wb,
                      GpuCircuit::word_t*       d_out);

// Evaluate AND/OR virtual-node combinations.
// CSR layout: inputs_flat[ offsets[vn] .. offsets[vn]+counts[vn] ],
// inversion flags in d_vn_input_inverted (1 = invert that input).
// d_out[ vn_idx * num_wb + wb_id ] = computed value.
void gpu_compute_virtual_features(const GpuCircuit::word_t* d_values,
                                  const int*   d_vn_input_nodes,
                                  const int*   d_vn_input_inverted,
                                  const int*   d_vn_offsets,
                                  const int*   d_vn_counts,
                                  const int*   d_vn_gtypes,
                                  std::size_t  num_vn,
                                  std::size_t  num_wb,
                                  GpuCircuit::word_t pmask,
                                  GpuCircuit::word_t* d_out);

// Pack host patterns into PI bit layout [pi_idx * num_wb + wb_id].
// patterns[i] is a vector of 0/1 per PI.  Packs patterns[offset..offset+count).
// h_pi_bits must be pre-zeroed, size = num_pis * num_wb.
void gpu_pack_pi_patterns(const std::vector<std::vector<int>>& patterns,
                          std::size_t offset, std::size_t count,
                          std::size_t num_pis,
                          GpuCircuit::word_t* h_pi_bits,
                          std::size_t num_wb);

// Per-gate popcount accumulation on GPU.
// For each gate g in [0, num_gates): atomically adds popcount of
// d_values[d_gate_indices[g] * num_wb + wb] to h_accum[g] (host).
// pmask masks out unused bits in the last word block.
// d_gate_indices is a device pointer [num_gates].
// d_accum is a device pointer [num_gates] — caller manages alloc/download.
void gpu_accumulate_gate_ones(const GpuCircuit::word_t* d_values,
                              const int*  d_gate_indices,
                              std::size_t num_gates,
                              std::size_t num_wb,
                              std::size_t total_nodes,
                              GpuCircuit::word_t pmask,
                              unsigned long long* d_accum);

// Same as above but with per-word-block mask array (for selective accumulation).
// d_masks[wb] is ANDed with each gate value before popcounting.
void gpu_accumulate_gate_ones_masked(const GpuCircuit::word_t* d_values,
                                     const int*  d_gate_indices,
                                     std::size_t num_gates,
                                     std::size_t num_wb,
                                     std::size_t total_nodes,
                                     const GpuCircuit::word_t* d_masks,
                                     unsigned long long* d_accum);
