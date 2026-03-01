#include "gpu_circuit.cuh"
#include "circuit.hpp"

#include <cuda_runtime.h>
#include <curand_kernel.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

// GType enum values must match circuit.hpp order:
// AND=0 OR=1 NAND=2 NOR=3 NOT=4 BUFF=5 XOR=6 XNOR=7

namespace {

inline void cuda_check(cudaError_t err, const char* msg) {
  if (err != cudaSuccess) {
    throw std::runtime_error(std::string(msg) + ": " +
                             cudaGetErrorString(err));
  }
}

// ── kernels ───────────────────────────────────────────────────────────────────

__global__ void kernel_zero_values(unsigned long long* vals,
                                   int total_elems) {
  int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < total_elems) vals[i] = 0ULL;
}

// 2-D: (wb, pi)
__global__ void kernel_set_pi(unsigned long long*       vals,
                              const int*                pi_indices,
                              int                       num_pis,
                              const unsigned long long* pi_bits,
                              int                       num_wb,
                              unsigned long long        pmask) {
  int pi = blockIdx.y * blockDim.y + threadIdx.y;
  int wb = blockIdx.x * blockDim.x + threadIdx.x;
  if (pi < num_pis && wb < num_wb)
    vals[pi_indices[pi] * num_wb + wb] = pi_bits[pi * num_wb + wb] & pmask;
}

// 2-D: (wb, ci)
__global__ void kernel_set_const(unsigned long long* vals,
                                 const int*          const_map,
                                 const int*          const_val,
                                 int                 num_const,
                                 int                 num_wb,
                                 unsigned long long  pmask) {
  int ci = blockIdx.y * blockDim.y + threadIdx.y;
  int wb = blockIdx.x * blockDim.x + threadIdx.x;
  if (ci < num_const && wb < num_wb)
    vals[const_map[ci] * num_wb + wb] = const_val[ci] ? pmask : 0ULL;
}

// 2-D: (wb, gi) — all gates at the same topological level
__global__ void kernel_eval_level(unsigned long long* vals,
                                  const int*          gate_dest,
                                  const int*          gate_gtype,
                                  const int*          gate_ioff,
                                  const int*          gate_inum,
                                  const int*          flat_inputs,
                                  int                 num_gates,
                                  int                 gate_offset,
                                  int                 num_wb,
                                  unsigned long long  pmask) {
  int gi = blockIdx.y * blockDim.y + threadIdx.y;
  int wb = blockIdx.x * blockDim.x + threadIdx.x;
  if (gi >= num_gates || wb >= num_wb) return;

  int g     = gate_offset + gi;
  int dest  = gate_dest[g];
  int gtype = gate_gtype[g];
  int ioff  = gate_ioff[g];
  int inum  = gate_inum[g];

  unsigned long long out = 0ULL;
  switch (gtype) {
    case 0: /* AND */
      out = pmask;
      for (int i = 0; i < inum; ++i) out &= vals[flat_inputs[ioff+i]*num_wb+wb];
      break;
    case 1: /* OR */
      for (int i = 0; i < inum; ++i) out |= vals[flat_inputs[ioff+i]*num_wb+wb];
      break;
    case 2: /* NAND */
      out = pmask;
      for (int i = 0; i < inum; ++i) out &= vals[flat_inputs[ioff+i]*num_wb+wb];
      out = (~out) & pmask;
      break;
    case 3: /* NOR */
      for (int i = 0; i < inum; ++i) out |= vals[flat_inputs[ioff+i]*num_wb+wb];
      out = (~out) & pmask;
      break;
    case 4: /* NOT */
      out = (~vals[flat_inputs[ioff]*num_wb+wb]) & pmask;
      break;
    case 5: /* BUFF */
      out = vals[flat_inputs[ioff]*num_wb+wb];
      break;
    case 6: /* XOR */
      for (int i = 0; i < inum; ++i) out ^= vals[flat_inputs[ioff+i]*num_wb+wb];
      break;
    case 7: /* XNOR */
      for (int i = 0; i < inum; ++i) out ^= vals[flat_inputs[ioff+i]*num_wb+wb];
      out = (~out) & pmask;
      break;
  }
  vals[dest * num_wb + wb] = out;
}

// 1-D: one thread per word block — full circuit simulation.
// Each thread evaluates the ENTIRE circuit in topological order for its 64 patterns.
// All threads follow the same gate sequence → coalesced memory access
// (same node, adjacent wb → contiguous addresses).
__global__ void kernel_simulate_full(
    unsigned long long*       vals,
    const int*                pi_indices,
    int                       num_pis,
    const unsigned long long* pi_bits,
    const int*                const_map,
    const int*                const_val,
    int                       num_const,
    const int*                gate_dest,
    const int*                gate_gtype,
    const int*                gate_ioff,
    const int*                gate_inum,
    const int*                flat_inputs,
    int                       num_gates,
    int                       num_wb,
    unsigned long long        pmask)
{
  int wb = blockIdx.x * blockDim.x + threadIdx.x;
  if (wb >= num_wb) return;

  // Set PIs
  for (int pi = 0; pi < num_pis; ++pi)
    vals[pi_indices[pi] * num_wb + wb] = pi_bits[pi * num_wb + wb] & pmask;

  // Set CONSTs
  for (int ci = 0; ci < num_const; ++ci)
    vals[const_map[ci] * num_wb + wb] = const_val[ci] ? pmask : 0ULL;

  // Evaluate all gates in topological order
  for (int g = 0; g < num_gates; ++g) {
    int dest  = gate_dest[g];
    int gtype = gate_gtype[g];
    int ioff  = gate_ioff[g];
    int inum  = gate_inum[g];

    unsigned long long out = 0ULL;
    switch (gtype) {
      case 0: /* AND */
        out = pmask;
        for (int i = 0; i < inum; ++i) out &= vals[flat_inputs[ioff+i]*num_wb+wb];
        break;
      case 1: /* OR */
        for (int i = 0; i < inum; ++i) out |= vals[flat_inputs[ioff+i]*num_wb+wb];
        break;
      case 2: /* NAND */
        out = pmask;
        for (int i = 0; i < inum; ++i) out &= vals[flat_inputs[ioff+i]*num_wb+wb];
        out = (~out) & pmask;
        break;
      case 3: /* NOR */
        for (int i = 0; i < inum; ++i) out |= vals[flat_inputs[ioff+i]*num_wb+wb];
        out = (~out) & pmask;
        break;
      case 4: /* NOT */
        out = (~vals[flat_inputs[ioff]*num_wb+wb]) & pmask;
        break;
      case 5: /* BUFF */
        out = vals[flat_inputs[ioff]*num_wb+wb];
        break;
      case 6: /* XOR */
        for (int i = 0; i < inum; ++i) out ^= vals[flat_inputs[ioff+i]*num_wb+wb];
        break;
      case 7: /* XNOR */
        for (int i = 0; i < inum; ++i) out ^= vals[flat_inputs[ioff+i]*num_wb+wb];
        out = (~out) & pmask;
        break;
    }
    vals[dest * num_wb + wb] = out;
  }
}

// 1-D: (wb)
// gpo_indices: PO node indices in golden circuit
// tpo_indices: PO node indices in trojan circuit (may differ — trojan has extra nodes)
__global__ void kernel_compare_po(const unsigned long long* gvals,
                                   const unsigned long long* tvals,
                                   const int*                gpo_indices,
                                   const int*                tpo_indices,
                                   int                       num_pos,
                                   int                       num_wb,
                                   unsigned long long        pmask,
                                   unsigned long long*       diff_mask) {
  int wb = blockIdx.x * blockDim.x + threadIdx.x;
  if (wb >= num_wb) return;
  unsigned long long diff = 0ULL;
  for (int o = 0; o < num_pos; ++o)
    diff |= (gvals[gpo_indices[o]*num_wb+wb] ^ tvals[tpo_indices[o]*num_wb+wb]);
  diff_mask[wb] = diff & pmask;
}

// 2-D: (wb, fi)
__global__ void kernel_gather_nodes(const unsigned long long* vals,
                                     const int*                node_indices,
                                     int                       num_gather,
                                     int                       num_wb,
                                     unsigned long long*       out) {
  int fi = blockIdx.y * blockDim.y + threadIdx.y;
  int wb = blockIdx.x * blockDim.x + threadIdx.x;
  if (fi < num_gather && wb < num_wb)
    out[fi * num_wb + wb] = vals[node_indices[fi] * num_wb + wb];
}

// 2-D: (wb, pi) — Philox random PI generation
__global__ void kernel_gen_random_pi(unsigned long long* d_pi,
                                      int                 num_pis,
                                      int                 num_wb,
                                      unsigned long long  seed) {
  int pi = blockIdx.y * blockDim.y + threadIdx.y;
  int wb = blockIdx.x * blockDim.x + threadIdx.x;
  if (pi >= num_pis || wb >= num_wb) return;
  curandStatePhilox4_32_10_t st;
  curand_init(seed, (long long)pi * num_wb + wb, 0, &st);
  unsigned int lo = curand(&st);
  unsigned int hi = curand(&st);
  d_pi[pi * num_wb + wb] = ((unsigned long long)hi << 32) | lo;
}

// 2-D: (wb, vn) — AND/OR virtual nodes with optional input inversion
__global__ void kernel_virtual_features(const unsigned long long* vals,
                                         const int* vn_inp_nodes,
                                         const int* vn_inp_inv,
                                         const int* vn_offsets,
                                         const int* vn_counts,
                                         const int* vn_gtypes,
                                         int        num_vn,
                                         int        num_wb,
                                         unsigned long long pmask,
                                         unsigned long long* out) {
  int vn = blockIdx.y * blockDim.y + threadIdx.y;
  int wb = blockIdx.x * blockDim.x + threadIdx.x;
  if (vn >= num_vn || wb >= num_wb) return;

  int ioff  = vn_offsets[vn];
  int inum  = vn_counts[vn];
  int gtype = vn_gtypes[vn];
  unsigned long long acc = (gtype == 1 /* OR */) ? 0ULL : pmask;
  for (int i = 0; i < inum; ++i) {
    unsigned long long v = vals[vn_inp_nodes[ioff+i] * num_wb + wb];
    if (vn_inp_inv[ioff+i]) v = (~v) & pmask;
    if (gtype == 1) acc |= v; else acc &= v;
  }
  out[vn * num_wb + wb] = acc;
}

// 2-D: (wb, gi) — per-gate popcount accumulation (single pmask for last wb)
__global__ void kernel_accumulate_gate_ones(
    const unsigned long long* vals,
    const int*                gate_indices,
    int                       num_gates,
    int                       num_wb,
    unsigned long long        pmask,
    unsigned long long*       accum) {
  int gi = blockIdx.y * blockDim.y + threadIdx.y;
  int wb = blockIdx.x * blockDim.x + threadIdx.x;
  if (gi >= num_gates || wb >= num_wb) return;
  unsigned long long v = vals[gate_indices[gi] * num_wb + wb];
  if (wb == num_wb - 1) v &= pmask;
  unsigned long long cnt = static_cast<unsigned long long>(__popcll(v));
  if (cnt > 0) atomicAdd(&accum[gi], cnt);
}

// 2-D: (wb, gi) — per-gate popcount with per-wb mask array
__global__ void kernel_accumulate_gate_ones_masked(
    const unsigned long long* vals,
    const int*                gate_indices,
    int                       num_gates,
    int                       num_wb,
    const unsigned long long* masks,
    unsigned long long*       accum) {
  int gi = blockIdx.y * blockDim.y + threadIdx.y;
  int wb = blockIdx.x * blockDim.x + threadIdx.x;
  if (gi >= num_gates || wb >= num_wb) return;
  unsigned long long v = vals[gate_indices[gi] * num_wb + wb] & masks[wb];
  unsigned long long cnt = static_cast<unsigned long long>(__popcll(v));
  if (cnt > 0) atomicAdd(&accum[gi], cnt);
}

}  // namespace

// ── GpuCircuit constructor ────────────────────────────────────────────────────

GpuCircuit::GpuCircuit(const circuit& base, std::size_t max_wb)
    : max_word_blocks_(max_wb) {
  // ensure_eval_order is logically const (just lazily computes order)
  const_cast<circuit&>(base).ensure_eval_order();

  num_nodes_ = base.node_count();
  num_pis_   = base.pi_count();
  num_pos_   = base.po_count();

  // ── collect CONST nodes ──
  std::vector<int> const_map_h, const_val_h;
  for (std::size_t i = 0; i < num_nodes_; ++i) {
    const cell& c = base.get_cell(static_cast<int>(i));
    if (c.ctype == CType::CONST) {
      const_map_h.push_back(static_cast<int>(i));
      const_val_h.push_back(c.val ? 1 : 0);
    }
  }
  num_const_ = const_map_h.size();

  // ── compute topological levels ──
  std::vector<int> node_level(num_nodes_, 0);
  int max_level = 0;
  for (int gidx : base.eval_order()) {
    const cell& c = base.get_cell(gidx);
    if (c.ctype != CType::GATE) continue;
    int lev = 0;
    for (int inp : c.inputs)
      if (node_level[inp] + 1 > lev) lev = node_level[inp] + 1;
    node_level[gidx] = lev;
    if (lev > max_level) max_level = lev;
  }

  // ── build level-grouped CSR ──
  std::vector<std::vector<int>> by_level(max_level + 1);
  for (int gidx : base.eval_order()) {
    const cell& c = base.get_cell(gidx);
    if (c.ctype == CType::GATE)
      by_level[node_level[gidx]].push_back(gidx);
  }

  std::vector<int> gate_dest_h, gate_gtype_h, gate_ioff_h, gate_inum_h;
  std::vector<int> flat_inputs_h;
  level_start_.resize(max_level + 2, 0);

  for (int lev = 0; lev <= max_level; ++lev) {
    level_start_[lev] = static_cast<int>(gate_dest_h.size());
    for (int gidx : by_level[lev]) {
      const cell& c = base.get_cell(gidx);
      gate_dest_h.push_back(gidx);
      gate_gtype_h.push_back(static_cast<int>(c.gtype));
      gate_ioff_h.push_back(static_cast<int>(flat_inputs_h.size()));
      gate_inum_h.push_back(static_cast<int>(c.inputs.size()));
      for (int inp : c.inputs) flat_inputs_h.push_back(inp);
    }
  }
  level_start_[max_level + 1] = static_cast<int>(gate_dest_h.size());
  num_gates_ = gate_dest_h.size();

  // ── upload to GPU ──
  const auto& pi_h = base.pi_indices();
  const auto& po_h = base.po_indices();

  cuda_check(cudaMalloc(&d_values_,
                        num_nodes_ * max_wb * sizeof(word_t)),
             "cudaMalloc d_values_");

  cuda_check(cudaMalloc(&d_pi_indices_, num_pis_ * sizeof(int)),
             "cudaMalloc d_pi_indices_");
  cuda_check(cudaMemcpy(d_pi_indices_, pi_h.data(),
                        num_pis_ * sizeof(int), cudaMemcpyHostToDevice),
             "cudaMemcpy pi_indices");

  cuda_check(cudaMalloc(&d_po_indices_, num_pos_ * sizeof(int)),
             "cudaMalloc d_po_indices_");
  cuda_check(cudaMemcpy(d_po_indices_, po_h.data(),
                        num_pos_ * sizeof(int), cudaMemcpyHostToDevice),
             "cudaMemcpy po_indices");

  if (num_const_ > 0) {
    cuda_check(cudaMalloc(&d_const_map_, num_const_ * sizeof(int)),
               "cudaMalloc d_const_map_");
    cuda_check(cudaMemcpy(d_const_map_, const_map_h.data(),
                          num_const_ * sizeof(int), cudaMemcpyHostToDevice),
               "cudaMemcpy const_map");
    cuda_check(cudaMalloc(&d_const_val_, num_const_ * sizeof(int)),
               "cudaMalloc d_const_val_");
    cuda_check(cudaMemcpy(d_const_val_, const_val_h.data(),
                          num_const_ * sizeof(int), cudaMemcpyHostToDevice),
               "cudaMemcpy const_val");
  }

  if (num_gates_ > 0) {
    auto alloc_and_copy = [](int** d, const std::vector<int>& h,
                              const char* name) {
      cuda_check(cudaMalloc(d, h.size() * sizeof(int)), name);
      cuda_check(cudaMemcpy(*d, h.data(), h.size() * sizeof(int),
                             cudaMemcpyHostToDevice), name);
    };
    alloc_and_copy(&d_gate_dest_,  gate_dest_h,  "gate_dest");
    alloc_and_copy(&d_gate_gtype_, gate_gtype_h, "gate_gtype");
    alloc_and_copy(&d_gate_ioff_,  gate_ioff_h,  "gate_ioff");
    alloc_and_copy(&d_gate_inum_,  gate_inum_h,  "gate_inum");
    alloc_and_copy(&d_inputs_,     flat_inputs_h,"flat_inputs");
  }
}

// ── GpuCircuit destructor ────────────────────────────────────────────────────

GpuCircuit::~GpuCircuit() {
  if (d_values_)     cudaFree(d_values_);
  if (d_pi_indices_) cudaFree(d_pi_indices_);
  if (d_po_indices_) cudaFree(d_po_indices_);
  if (d_const_map_)  cudaFree(d_const_map_);
  if (d_const_val_)  cudaFree(d_const_val_);
  if (d_gate_dest_)  cudaFree(d_gate_dest_);
  if (d_gate_gtype_) cudaFree(d_gate_gtype_);
  if (d_gate_ioff_)  cudaFree(d_gate_ioff_);
  if (d_gate_inum_)  cudaFree(d_gate_inum_);
  if (d_inputs_)     cudaFree(d_inputs_);
}

// ── GpuCircuit::simulate ─────────────────────────────────────────────────────

void GpuCircuit::simulate(const word_t* d_pi_bits, std::size_t num_wb) {
  const int nwb  = static_cast<int>(num_wb);
  const int tot  = static_cast<int>(num_nodes_ * num_wb);
  const word_t pmask = ~word_t(0);

  // Zero values
  kernel_zero_values<<<(tot + 255) / 256, 256>>>(d_values_, tot);

  // Set PIs
  if (num_pis_ > 0) {
    dim3 blk(32, 8);
    dim3 grd((nwb + 31) / 32,
             (static_cast<int>(num_pis_) + 7) / 8);
    kernel_set_pi<<<grd, blk>>>(d_values_, d_pi_indices_,
                                 static_cast<int>(num_pis_),
                                 d_pi_bits, nwb, pmask);
  }

  // Set CONSTs
  if (num_const_ > 0) {
    dim3 blk(32, 8);
    dim3 grd((nwb + 31) / 32,
             (static_cast<int>(num_const_) + 7) / 8);
    kernel_set_const<<<grd, blk>>>(d_values_, d_const_map_, d_const_val_,
                                    static_cast<int>(num_const_), nwb, pmask);
  }

  // Evaluate level by level (high parallelism: gate × wb per level).
  for (std::size_t lev = 0; lev + 1 < level_start_.size(); ++lev) {
    const int gs = level_start_[lev];
    const int ge = level_start_[lev + 1];
    const int ng = ge - gs;
    if (ng == 0) continue;
    dim3 blk(32, 8);
    dim3 grd((nwb + 31) / 32, (ng + 7) / 8);
    kernel_eval_level<<<grd, blk>>>(d_values_,
                                     d_gate_dest_, d_gate_gtype_,
                                     d_gate_ioff_,  d_gate_inum_,
                                     d_inputs_,
                                     ng, gs, nwb, pmask);
  }
  cuda_check(cudaDeviceSynchronize(), "simulate sync");
}

void GpuCircuit::simulate_serial(const word_t* d_pi_bits, std::size_t num_wb) {
  const int nwb = static_cast<int>(num_wb);
  const word_t pmask = ~word_t(0);

  cuda_check(cudaMemset(d_values_, 0,
                        num_nodes_ * num_wb * sizeof(word_t)),
             "memset d_values");

  if (nwb > 0) {
    const int threads = 256;
    const int blocks  = (nwb + threads - 1) / threads;
    kernel_simulate_full<<<blocks, threads>>>(
        d_values_,
        d_pi_indices_, static_cast<int>(num_pis_),
        d_pi_bits,
        d_const_map_, d_const_val_, static_cast<int>(num_const_),
        d_gate_dest_, d_gate_gtype_, d_gate_ioff_, d_gate_inum_,
        d_inputs_, static_cast<int>(num_gates_),
        nwb, pmask);
  }
  cuda_check(cudaDeviceSynchronize(), "simulate_serial sync");
}

// ── standalone utilities ─────────────────────────────────────────────────────

std::size_t gpu_compute_max_word_blocks(std::size_t golden_nodes,
                                        std::size_t trojan_nodes,
                                        std::size_t num_pis,
                                        std::size_t num_feature_nodes) {
  std::size_t free_b = 0, total_b = 0;
  cudaMemGetInfo(&free_b, &total_b);
  // Use 80% of free VRAM
  const std::size_t usable = (free_b * 4) / 5;
  // Per word-block bytes: 2 circuits + pi_bits + feature_bits + diff_mask
  const std::size_t per_wb =
      (golden_nodes + trojan_nodes + num_pis + num_feature_nodes + 1) *
      sizeof(GpuCircuit::word_t);
  if (per_wb == 0) return 16384;
  const std::size_t max_wb = usable / per_wb;
  // Clamp: at least 64, at most 16K word blocks (plan.md design point).
  // A larger cap explodes PCIe download time for feature_bits.
  return std::max<std::size_t>(64, std::min(max_wb, std::size_t(16384)));
}

void gpu_generate_random_pi(GpuCircuit::word_t* d_pi,
                            std::size_t          num_pis,
                            std::size_t          num_wb,
                            unsigned long long   seed) {
  if (num_pis == 0 || num_wb == 0) return;
  dim3 blk(32, 8);
  dim3 grd((static_cast<int>(num_wb)  + 31) / 32,
           (static_cast<int>(num_pis) +  7) /  8);
  kernel_gen_random_pi<<<grd, blk>>>(d_pi,
                                      static_cast<int>(num_pis),
                                      static_cast<int>(num_wb),
                                      seed);
  cuda_check(cudaDeviceSynchronize(), "gen_random_pi");
}

void gpu_compare_po(const GpuCircuit& golden,
                    const GpuCircuit& trojan,
                    GpuCircuit::word_t* d_diff_mask,
                    std::size_t         num_wb,
                    GpuCircuit::word_t  pmask) {
  if (num_wb == 0) return;
  const int nwb = static_cast<int>(num_wb);
  kernel_compare_po<<<(nwb + 255) / 256, 256>>>(
      golden.d_values(), trojan.d_values(),
      golden.d_po_indices(), trojan.d_po_indices(),
      static_cast<int>(golden.num_pos()), nwb, pmask, d_diff_mask);
  cuda_check(cudaDeviceSynchronize(), "compare_po");
}

void gpu_gather_nodes(const GpuCircuit::word_t* d_values,
                      const int*                d_node_indices,
                      std::size_t               num_gather,
                      std::size_t               num_wb,
                      GpuCircuit::word_t*       d_out) {
  if (num_gather == 0 || num_wb == 0) return;
  dim3 blk(32, 8);
  dim3 grd((static_cast<int>(num_wb)     + 31) / 32,
           (static_cast<int>(num_gather) +  7) /  8);
  kernel_gather_nodes<<<grd, blk>>>(d_values, d_node_indices,
                                     static_cast<int>(num_gather),
                                     static_cast<int>(num_wb), d_out);
  cuda_check(cudaDeviceSynchronize(), "gather_nodes");
}

void gpu_compute_virtual_features(const GpuCircuit::word_t* d_values,
                                  const int*   d_vn_input_nodes,
                                  const int*   d_vn_input_inverted,
                                  const int*   d_vn_offsets,
                                  const int*   d_vn_counts,
                                  const int*   d_vn_gtypes,
                                  std::size_t  num_vn,
                                  std::size_t  num_wb,
                                  GpuCircuit::word_t pmask,
                                  GpuCircuit::word_t* d_out) {
  if (num_vn == 0 || num_wb == 0) return;
  dim3 blk(32, 8);
  dim3 grd((static_cast<int>(num_wb) + 31) / 32,
           (static_cast<int>(num_vn) +  7) /  8);
  kernel_virtual_features<<<grd, blk>>>(d_values,
                                         d_vn_input_nodes,
                                         d_vn_input_inverted,
                                         d_vn_offsets,
                                         d_vn_counts,
                                         d_vn_gtypes,
                                         static_cast<int>(num_vn),
                                         static_cast<int>(num_wb),
                                         pmask, d_out);
  cuda_check(cudaDeviceSynchronize(), "virtual_features");
}

void gpu_pack_pi_patterns(const std::vector<std::vector<int>>& patterns,
                          std::size_t offset, std::size_t count,
                          std::size_t num_pis,
                          GpuCircuit::word_t* h_pi_bits,
                          std::size_t num_wb) {
  constexpr std::size_t kBits = 64;
  for (std::size_t i = 0; i < count; ++i) {
    const std::size_t wb  = i / kBits;
    const std::size_t bit = i % kBits;
    const auto& pat = patterns[offset + i];
    for (std::size_t p = 0; p < num_pis && p < pat.size(); ++p) {
      if (pat[p])
        h_pi_bits[p * num_wb + wb] |= (GpuCircuit::word_t(1) << bit);
    }
  }
}

void gpu_accumulate_gate_ones(const GpuCircuit::word_t* d_values,
                              const int*  d_gate_indices,
                              std::size_t num_gates,
                              std::size_t num_wb,
                              std::size_t /*total_nodes*/,
                              GpuCircuit::word_t pmask,
                              unsigned long long* d_accum) {
  if (num_gates == 0 || num_wb == 0) return;
  dim3 blk(32, 8);
  dim3 grd((static_cast<int>(num_wb)    + 31) / 32,
           (static_cast<int>(num_gates) +  7) /  8);
  kernel_accumulate_gate_ones<<<grd, blk>>>(
      d_values, d_gate_indices,
      static_cast<int>(num_gates),
      static_cast<int>(num_wb),
      pmask, d_accum);
  cuda_check(cudaDeviceSynchronize(), "accumulate_gate_ones");
}

void gpu_accumulate_gate_ones_masked(const GpuCircuit::word_t* d_values,
                                     const int*  d_gate_indices,
                                     std::size_t num_gates,
                                     std::size_t num_wb,
                                     std::size_t /*total_nodes*/,
                                     const GpuCircuit::word_t* d_masks,
                                     unsigned long long* d_accum) {
  if (num_gates == 0 || num_wb == 0) return;
  dim3 blk(32, 8);
  dim3 grd((static_cast<int>(num_wb)    + 31) / 32,
           (static_cast<int>(num_gates) +  7) /  8);
  kernel_accumulate_gate_ones_masked<<<grd, blk>>>(
      d_values, d_gate_indices,
      static_cast<int>(num_gates),
      static_cast<int>(num_wb),
      d_masks, d_accum);
  cuda_check(cudaDeviceSynchronize(), "accumulate_gate_ones_masked");
}
