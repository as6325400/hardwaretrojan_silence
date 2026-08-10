#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "circuit.hpp"
#include "packed_circuit.hpp"

#ifdef USE_CUDA
#include "gpu_circuit.cuh"
#endif

class batch_simulator {
 public:
  using word_t = unsigned long long;
  static constexpr std::size_t kBits = 64;
  static constexpr std::size_t kGpuThreshold = 50000;

  // Auto-selects GPU (node_count >= kGpuThreshold) or CPU.
  // partner_nodes: other circuit's node count, for shared VRAM budgeting.
  explicit batch_simulator(circuit& c, std::size_t partner_nodes = 0,
                           std::size_t max_word_blocks_hint = 0);
  ~batch_simulator();

  batch_simulator(const batch_simulator&) = delete;
  batch_simulator& operator=(const batch_simulator&) = delete;

  bool is_gpu() const { return use_gpu_; }
  const std::string& gpu_init_error() const { return gpu_init_error_; }
  std::size_t max_wb() const { return max_wb_; }
  std::size_t num_nodes() const;
  std::size_t num_pis() const;
  std::size_t num_pos() const;

  // Pack patterns[offset..offset+count) into internal PI buffer.
  // count must be <= max_wb() * kBits.
  // Returns chunk_wb (number of word-blocks used).
  std::size_t pack_patterns(const std::vector<std::vector<int>>& patterns,
                            std::size_t offset, std::size_t count);

  // Pack non-contiguous patterns: patterns[indices[0]], patterns[indices[1]], ...
  // count = number of indices to pack.
  std::size_t pack_indexed_patterns(
      const std::vector<std::vector<int>>& patterns,
      const std::size_t* indices, std::size_t count);

  // Share PI bits from another simulator (avoids double-packing).
  // Copies h_pi into internal buffer; uploads to GPU if in GPU mode.
  void upload_pi(const word_t* h_pi, std::size_t num_wb);

  // Run simulation for num_wb word-blocks using current PI buffer.
  // pattern_count: actual number of patterns (for last-wb mask).
  void simulate(std::size_t num_wb, std::size_t pattern_count);

  // Result access (valid after simulate()).
  word_t po_bits(std::size_t po_pos, std::size_t wb) const;
  word_t node_bits(int node_idx, std::size_t wb) const;

  // Per-pattern accessors (convenience).
  int po_value(std::size_t po_pos, std::size_t pattern_idx) const;
  int node_value(int node_idx, std::size_t pattern_idx) const;

  // Access host PI buffer (for sharing with partner simulator).
  const word_t* h_pi_data() const { return h_pi_.data(); }

  // Compute last-wb mask for a pattern count.
  static word_t pmask_for(std::size_t count);

#ifdef USE_CUDA
  GpuCircuit& gpu() { return *gpu_; }
  const GpuCircuit& gpu() const { return *gpu_; }
#endif

 private:
  circuit* base_;
  bool use_gpu_ = false;
  std::string gpu_init_error_;
  std::size_t max_wb_ = 0;
  std::size_t last_num_wb_ = 0;
  std::size_t last_count_ = 0;
  word_t last_pmask_ = 0;

  // Host PI buffer (shared between GPU and CPU paths).
  std::vector<word_t> h_pi_;

  // CPU mode: OpenMP results buffer [node * last_num_wb_ + wb].
  mutable std::vector<word_t> cpu_values_;

#ifdef USE_CUDA
  // GPU mode.
  GpuCircuit* gpu_ = nullptr;
  word_t* d_pi_bits_ = nullptr;
  // Lazy-downloaded host values for GPU result access.
  mutable std::vector<word_t> gpu_host_values_;
  mutable bool gpu_values_dirty_ = true;
  void ensure_gpu_host_values() const;
#endif
};

// ── Convenience functions ──────────────────────────────────────────────────

// Compare PO outputs of two circuits on all patterns.
// Returns true if all POs match on all patterns.
bool batch_verify_po(circuit& a, circuit& b,
                     const std::vector<std::vector<int>>& patterns,
                     std::size_t* mismatch_idx = nullptr,
                     std::string* error = nullptr);

// Compute PO output vectors for all patterns.
// out[pattern_idx] = vector of PO values (0/1).
void batch_compute_po(circuit& c,
                      const std::vector<std::vector<int>>& patterns,
                      std::vector<std::vector<int>>& out);
