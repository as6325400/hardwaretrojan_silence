#include "batch_simulator.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#ifdef USE_CUDA
#include <cuda_runtime.h>
#endif

// ---------------------------------------------------------------------------
// batch_simulator
// ---------------------------------------------------------------------------

batch_simulator::batch_simulator(circuit& c, std::size_t partner_nodes)
    : base_(&c) {
  base_->ensure_eval_order();
  const std::size_t nodes = base_->node_count();
  const std::size_t pis = base_->pi_count();

#ifdef USE_CUDA
  if (nodes >= kGpuThreshold) {
    try {
      max_wb_ = gpu_compute_max_word_blocks(nodes, partner_nodes, pis, 0);
      gpu_ = new GpuCircuit(*base_, max_wb_);
      cudaMalloc(&d_pi_bits_, pis * max_wb_ * sizeof(word_t));
      h_pi_.resize(pis * max_wb_, 0);
      use_gpu_ = true;
      return;
    } catch (...) {
      // GPU init failed — fall through to CPU.
      if (gpu_) { delete gpu_; gpu_ = nullptr; }
      if (d_pi_bits_) { cudaFree(d_pi_bits_); d_pi_bits_ = nullptr; }
    }
  }
#endif

  // CPU path (OpenMP parallel).
  max_wb_ = 256;  // 256 * 64 = 16384 patterns per chunk.
  h_pi_.resize(pis * max_wb_, 0);
}

batch_simulator::~batch_simulator() {
#ifdef USE_CUDA
  delete gpu_;
  if (d_pi_bits_) cudaFree(d_pi_bits_);
#endif
}

std::size_t batch_simulator::num_nodes() const { return base_->node_count(); }
std::size_t batch_simulator::num_pis() const { return base_->pi_count(); }
std::size_t batch_simulator::num_pos() const { return base_->po_count(); }

batch_simulator::word_t batch_simulator::pmask_for(std::size_t count) {
  return packed_circuit::mask_for_count(count);
}

std::size_t batch_simulator::pack_patterns(
    const std::vector<std::vector<int>>& patterns,
    std::size_t offset, std::size_t count) {
  if (count == 0) return 0;
  const std::size_t chunk_wb = (count + kBits - 1) / kBits;
  const std::size_t pis = num_pis();

  std::memset(h_pi_.data(), 0, pis * chunk_wb * sizeof(word_t));

#ifdef USE_CUDA
  gpu_pack_pi_patterns(patterns, offset, count, pis, h_pi_.data(), chunk_wb);
#else
  for (std::size_t p = 0; p < count; ++p) {
    const auto& pat = patterns[offset + p];
    const std::size_t wb = p / kBits;
    const word_t bit = word_t(1) << (p % kBits);
    for (std::size_t i = 0; i < pis; ++i) {
      if (pat[i]) h_pi_[i * chunk_wb + wb] |= bit;
    }
  }
#endif

#ifdef USE_CUDA
  if (use_gpu_) {
    cudaMemcpy(d_pi_bits_, h_pi_.data(),
               pis * chunk_wb * sizeof(word_t),
               cudaMemcpyHostToDevice);
  }
#endif

  return chunk_wb;
}

std::size_t batch_simulator::pack_indexed_patterns(
    const std::vector<std::vector<int>>& patterns,
    const std::size_t* indices, std::size_t count) {
  if (count == 0) return 0;
  const std::size_t chunk_wb = (count + kBits - 1) / kBits;
  const std::size_t pis = num_pis();

  std::memset(h_pi_.data(), 0, pis * chunk_wb * sizeof(word_t));

  for (std::size_t p = 0; p < count; ++p) {
    const auto& pat = patterns[indices[p]];
    const std::size_t wb = p / kBits;
    const word_t bit = word_t(1) << (p % kBits);
    for (std::size_t i = 0; i < pis; ++i) {
      if (pat[i]) h_pi_[i * chunk_wb + wb] |= bit;
    }
  }

#ifdef USE_CUDA
  if (use_gpu_) {
    cudaMemcpy(d_pi_bits_, h_pi_.data(),
               pis * chunk_wb * sizeof(word_t),
               cudaMemcpyHostToDevice);
  }
#endif

  return chunk_wb;
}

void batch_simulator::upload_pi(const word_t* h_pi, std::size_t num_wb) {
  const std::size_t pis = num_pis();
  std::memcpy(h_pi_.data(), h_pi, pis * num_wb * sizeof(word_t));

#ifdef USE_CUDA
  if (use_gpu_) {
    cudaMemcpy(d_pi_bits_, h_pi_.data(),
               pis * num_wb * sizeof(word_t),
               cudaMemcpyHostToDevice);
  }
#endif
}

void batch_simulator::simulate(std::size_t num_wb, std::size_t pattern_count) {
  last_num_wb_ = num_wb;
  last_count_ = pattern_count;

#ifdef USE_CUDA
  if (use_gpu_) {
    gpu_->simulate(d_pi_bits_, num_wb);
    gpu_values_dirty_ = true;
    return;
  }
#endif

  // CPU path: OpenMP parallel per-word-block simulation.
  const std::size_t nodes = num_nodes();
  const std::size_t pis = num_pis();
  cpu_values_.resize(nodes * num_wb);

  #pragma omp parallel
  {
    packed_circuit local_pc(*base_);
    local_pc.prepare_batch();
    std::vector<word_t> pi_wb(pis);

    #pragma omp for schedule(dynamic, 4)
    for (std::size_t wb = 0; wb < num_wb; ++wb) {
      // Extract PI bits for this single word-block.
      for (std::size_t i = 0; i < pis; ++i) {
        pi_wb[i] = h_pi_[i * num_wb + wb];
      }
      const std::size_t cnt = (wb < num_wb - 1)
          ? kBits
          : ((pattern_count % kBits == 0) ? kBits : pattern_count % kBits);
      local_pc.simulate_bits_fast(pi_wb.data(), cnt);

      // Bulk copy results into shared buffer (contiguous per wb).
      std::memcpy(&cpu_values_[wb * nodes], local_pc.values_data(),
                  nodes * sizeof(word_t));
    }
  }
}

// ---------------------------------------------------------------------------
// Result access
// ---------------------------------------------------------------------------

#ifdef USE_CUDA
void batch_simulator::ensure_gpu_host_values() const {
  if (!gpu_values_dirty_) return;
  const std::size_t n = gpu_->num_nodes() * last_num_wb_;
  gpu_host_values_.resize(n);
  cudaMemcpy(gpu_host_values_.data(), gpu_->d_values(),
             n * sizeof(word_t), cudaMemcpyDeviceToHost);
  gpu_values_dirty_ = false;
}
#endif

batch_simulator::word_t batch_simulator::po_bits(
    std::size_t po_pos, std::size_t wb) const {
  const auto& po_idx = base_->po_indices();
  if (po_pos >= po_idx.size()) {
    throw std::runtime_error("PO index out of range");
  }
  return node_bits(po_idx[po_pos], wb);
}

batch_simulator::word_t batch_simulator::node_bits(
    int node_idx, std::size_t wb) const {
  if (node_idx < 0 ||
      static_cast<std::size_t>(node_idx) >= base_->node_count()) {
    throw std::runtime_error("node index out of range");
  }

#ifdef USE_CUDA
  if (use_gpu_) {
    ensure_gpu_host_values();
    return gpu_host_values_[static_cast<std::size_t>(node_idx) * last_num_wb_ +
                            wb];
  }
#endif

  return cpu_values_[wb * base_->node_count() +
                     static_cast<std::size_t>(node_idx)];
}

int batch_simulator::po_value(std::size_t po_pos,
                              std::size_t pattern_idx) const {
  const std::size_t wb = pattern_idx / kBits;
  const std::size_t bit = pattern_idx % kBits;
  return (po_bits(po_pos, wb) >> bit) & 1;
}

int batch_simulator::node_value(int node_idx,
                                std::size_t pattern_idx) const {
  const std::size_t wb = pattern_idx / kBits;
  const std::size_t bit = pattern_idx % kBits;
  return (node_bits(node_idx, wb) >> bit) & 1;
}

// ---------------------------------------------------------------------------
// Convenience: batch_verify_po
// ---------------------------------------------------------------------------

bool batch_verify_po(circuit& a, circuit& b,
                     const std::vector<std::vector<int>>& patterns,
                     std::size_t* mismatch_idx,
                     std::string* error) {
  if (error) error->clear();
  if (mismatch_idx) *mismatch_idx = 0;
  if (patterns.empty()) return true;

  if (a.pi_count() != b.pi_count()) {
    if (error) *error = "PI count mismatch";
    return false;
  }
  if (a.po_count() != b.po_count()) {
    if (error) *error = "PO count mismatch";
    return false;
  }

  const std::size_t num_pos = a.po_count();
  const std::size_t total = patterns.size();

  batch_simulator sim_a(a, b.node_count());
  batch_simulator sim_b(b, a.node_count());

  const std::size_t mwb = std::min(sim_a.max_wb(), sim_b.max_wb());

  std::size_t offset = 0;
  while (offset < total) {
    const std::size_t chunk = std::min(mwb * batch_simulator::kBits,
                                       total - offset);
    const std::size_t chunk_wb = sim_a.pack_patterns(patterns, offset, chunk);
    sim_b.upload_pi(sim_a.h_pi_data(), chunk_wb);

    sim_a.simulate(chunk_wb, chunk);
    sim_b.simulate(chunk_wb, chunk);

    const std::size_t tail = chunk % batch_simulator::kBits;
    const batch_simulator::word_t pmask = batch_simulator::pmask_for(
        tail == 0 ? batch_simulator::kBits : tail);

    for (std::size_t w = 0; w < chunk_wb; ++w) {
      batch_simulator::word_t diff = 0;
      for (std::size_t o = 0; o < num_pos; ++o) {
        diff |= (sim_a.po_bits(o, w) ^ sim_b.po_bits(o, w));
      }
      if (w == chunk_wb - 1) diff &= pmask;
      if (diff != 0) {
        const std::size_t bit =
            static_cast<std::size_t>(__builtin_ctzll(diff));
        if (mismatch_idx) *mismatch_idx = offset + w * batch_simulator::kBits + bit;
        if (error) *error = "groundtruth mismatch";
        return false;
      }
    }

    offset += chunk;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Convenience: batch_compute_po
// ---------------------------------------------------------------------------

void batch_compute_po(circuit& c,
                      const std::vector<std::vector<int>>& patterns,
                      std::vector<std::vector<int>>& out) {
  const std::size_t total = patterns.size();
  const std::size_t num_pos = c.po_count();
  out.resize(total);

  batch_simulator sim(c);
  const std::size_t mwb = sim.max_wb();

  std::size_t offset = 0;
  while (offset < total) {
    const std::size_t chunk = std::min(mwb * batch_simulator::kBits,
                                       total - offset);
    const std::size_t chunk_wb = sim.pack_patterns(patterns, offset, chunk);
    sim.simulate(chunk_wb, chunk);

    for (std::size_t p = 0; p < chunk; ++p) {
      out[offset + p].resize(num_pos);
      for (std::size_t o = 0; o < num_pos; ++o) {
        out[offset + p][o] = sim.po_value(o, p);
      }
    }

    offset += chunk;
  }
}
