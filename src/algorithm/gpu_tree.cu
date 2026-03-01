#include "gpu_tree.cuh"

#include <cuda_runtime.h>

#include <cfloat>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

inline void gtree_check(cudaError_t err, const char* msg) {
  if (err != cudaSuccess)
    throw std::runtime_error(std::string(msg) + ": " +
                             cudaGetErrorString(err));
}

__device__ inline double gini_dev(int pos, int neg) {
  int tot = pos + neg;
  if (tot <= 0) return 0.0;
  double p = (double)pos / tot;
  double q = (double)neg / tot;
  return 1.0 - (p * p + q * q);
}

// One thread per feature.
// Each thread iterates over packed_words and accumulates total1/pos1 via
// __popcll, then computes the Gini gain.
__global__ void kernel_find_split(
    const unsigned long long* col_data,
    const unsigned long long* sample_mask,
    const unsigned long long* sample_pos_mask,
    int     packed_words,
    int     n_features,
    int     total_samples,
    int     pos_count,
    int     neg_count,
    double  parent_impurity,
    double* gains)
{
  int fi = blockIdx.x * blockDim.x + threadIdx.x;
  if (fi >= n_features) return;

  const unsigned long long* col = col_data + fi * packed_words;
  int total1 = 0, pos1 = 0;
  for (int w = 0; w < packed_words; ++w) {
    unsigned long long feat_in_sample = col[w] & sample_mask[w];
    total1 += __popcll(feat_in_sample);
    pos1   += __popcll(feat_in_sample & sample_pos_mask[w]);
  }

  int neg1   = total1 - pos1;
  int pos0   = pos_count - pos1;
  int neg0   = neg_count - neg1;
  int total0 = pos0 + neg0;

  if (total0 == 0 || total1 == 0) {
    gains[fi] = -DBL_MAX;
    return;
  }

  double weighted =
      ((double)total0 / total_samples) * gini_dev(pos0, neg0) +
      ((double)total1 / total_samples) * gini_dev(pos1, neg1);
  gains[fi] = parent_impurity - weighted;
}

}  // namespace

// ── Persistent per-tree workspace (avoid per-call cudaMalloc overhead) ────────
// Allocated on first use, grown as needed, never freed (process lifetime).
namespace {
struct TreeWorkspace {
  GpuWord* d_col   = nullptr;
  GpuWord* d_smask = nullptr;
  GpuWord* d_spos  = nullptr;
  double*  d_gains = nullptr;
  std::size_t cap_col   = 0;  // bytes
  std::size_t cap_mask  = 0;
  std::size_t cap_gains = 0;  // bytes

  void ensure(std::size_t col_bytes, std::size_t mask_bytes,
              std::size_t gains_bytes) {
    if (col_bytes > cap_col) {
      if (d_col) cudaFree(d_col);
      cudaMalloc(&d_col, col_bytes);
      cap_col = col_bytes;
    }
    if (mask_bytes > cap_mask) {
      if (d_smask) cudaFree(d_smask);
      if (d_spos)  cudaFree(d_spos);
      cudaMalloc(&d_smask, mask_bytes);
      cudaMalloc(&d_spos,  mask_bytes);
      cap_mask = mask_bytes;
    }
    if (gains_bytes > cap_gains) {
      if (d_gains) cudaFree(d_gains);
      cudaMalloc(&d_gains, gains_bytes);
      cap_gains = gains_bytes;
    }
  }
};
// One workspace per thread to be OpenMP-safe (though build_node is serial).
thread_local TreeWorkspace g_tw;
}  // namespace

GpuSplitResult gpu_find_best_split(
    const GpuWord* col_data_h,
    const GpuWord* sample_mask_h,
    const GpuWord* sample_pos_mask_h,
    std::size_t    packed_words,
    std::size_t    n_features,
    std::size_t    total_samples,
    std::size_t    pos_count,
    std::size_t    neg_count,
    double         parent_impurity)
{
  const std::size_t col_bytes  = n_features * packed_words * sizeof(GpuWord);
  const std::size_t mask_bytes = packed_words * sizeof(GpuWord);
  const std::size_t gains_bytes = n_features * sizeof(double);

  g_tw.ensure(col_bytes, mask_bytes, gains_bytes);
  GpuWord* d_col   = g_tw.d_col;
  GpuWord* d_smask = g_tw.d_smask;
  GpuWord* d_spos  = g_tw.d_spos;
  double*  d_gains = g_tw.d_gains;

  gtree_check(cudaMemcpy(d_col,   col_data_h,        col_bytes,  cudaMemcpyHostToDevice), "cp col");
  gtree_check(cudaMemcpy(d_smask, sample_mask_h,     mask_bytes, cudaMemcpyHostToDevice), "cp smask");
  gtree_check(cudaMemcpy(d_spos,  sample_pos_mask_h, mask_bytes, cudaMemcpyHostToDevice), "cp spos");

  const int threads = 256;
  const int blocks  = (static_cast<int>(n_features) + threads - 1) / threads;
  kernel_find_split<<<blocks, threads>>>(
      d_col, d_smask, d_spos,
      static_cast<int>(packed_words),
      static_cast<int>(n_features),
      static_cast<int>(total_samples),
      static_cast<int>(pos_count),
      static_cast<int>(neg_count),
      parent_impurity,
      d_gains);
  gtree_check(cudaDeviceSynchronize(), "split sync");

  std::vector<double> h_gains(n_features);
  gtree_check(cudaMemcpy(h_gains.data(), d_gains, gains_bytes,
                          cudaMemcpyDeviceToHost), "cp gains");

  GpuSplitResult res{};
  res.found     = false;
  res.best_gain = -std::numeric_limits<double>::infinity();
  for (std::size_t fi = 0; fi < n_features; ++fi) {
    if (h_gains[fi] > -DBL_MAX && (!res.found || h_gains[fi] > res.best_gain)) {
      res.best_gain = h_gains[fi];
      res.best_fi   = fi;
      res.found     = true;
    }
  }
  return res;
}
