#include "miner.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <numeric>
#include <random>
#include <sys/sysinfo.h>

#ifdef __BMI2__
#include <immintrin.h>
#endif

#include "../core/packed_circuit.hpp"
#include "rule_patch.hpp"
#include "virtual_node.hpp"

#ifdef USE_CUDA
#include <cuda_runtime.h>
#include "../core/gpu_circuit.cuh"

namespace {
// Upload a flat array of circuit node indices to device memory.
inline int* gpu_upload_ints(const std::vector<int>& v) {
  if (v.empty()) return nullptr;
  int* d = nullptr;
  cudaMalloc(&d, v.size() * sizeof(int));
  cudaMemcpy(d, v.data(), v.size() * sizeof(int), cudaMemcpyHostToDevice);
  return d;
}
}  // namespace

#endif  // USE_CUDA

namespace {

struct TrainingData {
  PackedFeatureMatrix features;
  std::vector<int> labels;
  std::size_t pos_count = 0;
  std::size_t neg_count = 0;
};

struct EvalResult {
  std::size_t checked = 0;
  std::size_t false_pos = 0;
  std::size_t added = 0;
};

std::vector<int> build_feature_nodes(const circuit& trojan,
                                     const std::vector<int>& candidate_gate_indices,
                                     bool with_pi) {
  std::vector<int> nodes = candidate_gate_indices;
  if (with_pi) {
    const auto& pi_indices = trojan.pi_indices();
    nodes.insert(nodes.end(), pi_indices.begin(), pi_indices.end());
  }
  return nodes;
}

using FeatureWord = PackedFeatureMatrix::word_t;
using PackedWord = packed_circuit::word_t;

std::size_t count_rule_literals(const std::vector<DecisionTreeRule>& rules) {
  std::size_t total = 0;
  for (const auto& rule : rules) {
    total += rule.terms.size();
  }
  return total;
}

// Evaluate a single rule against sample i in column-major matrix.
bool rule_matches_sample(const DecisionTreeRule& rule,
                         const PackedFeatureMatrix& features,
                         std::size_t sample_idx) {
  for (const auto& term : rule.terms) {
    if (features.feature_value(sample_idx, term.first) != term.second) {
      return false;
    }
  }
  return true;
}

// Evaluate all rules against sample i in column-major matrix.
bool eval_rules_colmajor(const std::vector<DecisionTreeRule>& rules,
                         const PackedFeatureMatrix& features,
                         std::size_t sample_idx) {
  for (const auto& rule : rules) {
    if (rule_matches_sample(rule, features, sample_idx)) {
      return true;
    }
  }
  return false;
}

bool rule_has_no_false_pos(const DecisionTreeRule& rule,
                           const PackedFeatureMatrix& features,
                           const std::vector<int>& labels,
                           bool* has_positive_match) {
  if (has_positive_match) {
    *has_positive_match = false;
  }
  if (features.row_count == 0) {
    return false;
  }
  bool positive_seen = false;
  for (std::size_t i = 0; i < features.row_count; ++i) {
    if (!rule_matches_sample(rule, features, i)) {
      continue;
    }
    if (labels[i] == 0) {
      return false;
    }
    positive_seen = true;
  }
  if (has_positive_match) {
    *has_positive_match = positive_seen;
  }
  return positive_seen;
}

bool try_merge_opposite_literal(const DecisionTreeRule& a,
                                const DecisionTreeRule& b,
                                DecisionTreeRule* merged) {
  if (!merged) {
    return false;
  }
  if (a.terms.size() != b.terms.size() || a.terms.empty()) {
    return false;
  }
  std::size_t i = 0;
  std::size_t j = 0;
  std::size_t diff = 0;
  merged->terms.clear();
  while (i < a.terms.size() && j < b.terms.size()) {
    const auto& ta = a.terms[i];
    const auto& tb = b.terms[j];
    if (ta.first != tb.first) {
      return false;
    }
    if (ta.second == tb.second) {
      merged->terms.push_back(ta);
    } else {
      diff += 1;
      if (diff > 1) {
        return false;
      }
    }
    ++i;
    ++j;
  }
  if (diff != 1) {
    return false;
  }
  return true;
}

void minimize_rules_with_data(std::vector<DecisionTreeRule>* rules,
                              const PackedFeatureMatrix& features,
                              const std::vector<int>& labels) {
  if (!rules || rules->empty()) {
    return;
  }
  if (features.row_count == 0 || features.row_count != labels.size()) {
    return;
  }

  for (auto& rule : *rules) {
    std::sort(rule.terms.begin(), rule.terms.end());
  }

  bool changed = true;
  while (changed) {
    changed = false;
    for (auto& rule : *rules) {
      bool rule_changed = true;
      while (rule_changed && !rule.terms.empty()) {
        rule_changed = false;
        for (std::size_t t = 0; t < rule.terms.size(); ++t) {
          DecisionTreeRule candidate = rule;
          candidate.terms.erase(candidate.terms.begin() + static_cast<long>(t));
          bool has_pos = false;
          if (rule_has_no_false_pos(candidate, features, labels, &has_pos) &&
              has_pos) {
            rule = std::move(candidate);
            rule_changed = true;
            changed = true;
            break;
          }
        }
      }
    }

    for (std::size_t i = 0; i < rules->size(); ++i) {
      for (std::size_t j = i + 1; j < rules->size(); ++j) {
        DecisionTreeRule merged;
        if (!try_merge_opposite_literal((*rules)[i], (*rules)[j], &merged)) {
          continue;
        }
        bool has_pos = false;
        if (rule_has_no_false_pos(merged, features, labels, &has_pos) &&
            has_pos) {
          (*rules)[i] = std::move(merged);
          rules->erase(rules->begin() + static_cast<long>(j));
          changed = true;
          break;
        }
      }
      if (changed) {
        break;
      }
    }
  }
}

std::size_t popcount_word(PackedWord value) {
  return static_cast<std::size_t>(__builtin_popcountll(value));
}

std::size_t ctz_word(PackedWord value) {
  return static_cast<std::size_t>(__builtin_ctzll(value));
}

std::vector<PackedWord> gather_feature_bits(const packed_circuit& packed,
                                            const std::vector<int>& feature_nodes) {
  std::vector<PackedWord> bits;
  bits.reserve(feature_nodes.size());
  for (int node_idx : feature_nodes) {
    bits.push_back(packed.node_bits(node_idx));
  }
  return bits;
}

// ── Column-major write helpers ──────────────────────────────────────────────

// Write a full word block (all patterns) to column-major matrix.
// row_count must be 64-aligned.  block_size ≤ 64 actual samples.
void write_word_block(const PackedWord* feature_bits,
                      std::size_t num_features,
                      std::size_t block_size,
                      PackedFeatureMatrix* matrix,
                      std::vector<int>* labels,
                      int label) {
  const std::size_t wb = matrix->row_count / PackedFeatureMatrix::kWordBits;
  const std::size_t pr = matrix->packed_rows();
  auto* data = matrix->data.data();
  for (std::size_t f = 0; f < num_features; ++f) {
    data[f * pr + wb] = static_cast<FeatureWord>(feature_bits[f]);
  }
  matrix->row_count += block_size;
  labels->insert(labels->end(), block_size, label);
}

// Write multiple contiguous word blocks from GPU download buffer to matrix.
// h_feat[f * chunk_wb + w] is the GPU layout.  row_count must be 64-aligned.
void write_gpu_chunk(const FeatureWord* h_feat,
                     std::size_t num_features,
                     std::size_t chunk_wb,
                     std::size_t chunk_samples,
                     PackedFeatureMatrix* matrix,
                     std::vector<int>* labels,
                     int label) {
  const std::size_t dst_wb = matrix->row_count / PackedFeatureMatrix::kWordBits;
  const std::size_t pr = matrix->packed_rows();
  auto* data = matrix->data.data();
  for (std::size_t f = 0; f < num_features; ++f) {
    const auto* src = h_feat + f * chunk_wb;
    auto* dst = data + f * pr + dst_wb;
    for (std::size_t w = 0; w < chunk_wb; ++w) {
      dst[w] = src[w];
    }
  }
  matrix->row_count += chunk_samples;
  labels->insert(labels->end(), chunk_samples, label);
}

// Append a single sample extracted from a word block.
void append_single_sample(const PackedWord* feature_bits,
                          std::size_t num_features,
                          std::size_t src_bit,
                          PackedFeatureMatrix* matrix,
                          std::vector<int>* labels,
                          int label) {
  const PackedWord src_mask = PackedWord(1) << src_bit;
  const std::size_t dst = matrix->row_count;
  const std::size_t dst_w = dst / PackedFeatureMatrix::kWordBits;
  const FeatureWord dst_bit = FeatureWord(1) << (dst % PackedFeatureMatrix::kWordBits);
  const std::size_t pr = matrix->packed_rows();
  auto* data = matrix->data.data();
  for (std::size_t f = 0; f < num_features; ++f) {
    if (feature_bits[f] & src_mask) {
      data[f * pr + dst_w] |= dst_bit;
    }
  }
  matrix->row_count += 1;
  labels->push_back(label);
}

// Portable parallel bit extract: compact bits at mask positions into contiguous low bits.
PackedWord portable_pext(PackedWord val, PackedWord mask) {
#ifdef __BMI2__
  return _pext_u64(val, mask);
#else
  PackedWord result = 0;
  PackedWord out_bit = 1;
  PackedWord m = mask;
  while (m) {
    PackedWord lowest = m & (-m);
    if (val & lowest) result |= out_bit;
    out_bit <<= 1;
    m &= m - 1;
  }
  return result;
#endif
}

// Keep only the first n set bits in mask, clear the rest.
PackedWord keep_n_set_bits(PackedWord mask, std::size_t n) {
  PackedWord result = 0;
  for (std::size_t i = 0; i < n && mask; ++i) {
    PackedWord lowest = mask & (-mask);
    result |= lowest;
    mask &= mask - 1;
  }
  return result;
}

// Batch-append all patterns selected by select_mask from a single word block.
// Uses pext to compact selected bits into contiguous positions in the matrix.
// Returns the number of samples added (= popcount of select_mask).
std::size_t append_word_block_selective(const PackedWord* feature_bits,
                                        std::size_t num_features,
                                        PackedWord select_mask,
                                        PackedFeatureMatrix* matrix,
                                        std::vector<int>* labels,
                                        int label) {
  if (select_mask == 0) return 0;
  const std::size_t count = popcount_word(select_mask);
  const std::size_t dst_start = matrix->row_count;
  const std::size_t dst_w0 = dst_start / PackedFeatureMatrix::kWordBits;
  const std::size_t dst_bit0 = dst_start % PackedFeatureMatrix::kWordBits;
  const std::size_t pr = matrix->packed_rows();
  auto* data = matrix->data.data();

  if (dst_bit0 + count <= PackedFeatureMatrix::kWordBits) {
    // All extracted bits fit in one word per feature.
    for (std::size_t f = 0; f < num_features; ++f) {
      FeatureWord extracted = static_cast<FeatureWord>(
          portable_pext(feature_bits[f], select_mask));
      data[f * pr + dst_w0] |= (extracted << dst_bit0);
    }
  } else {
    // Extracted bits span two words per feature.
    const std::size_t shift_r = PackedFeatureMatrix::kWordBits - dst_bit0;
    for (std::size_t f = 0; f < num_features; ++f) {
      FeatureWord extracted = static_cast<FeatureWord>(
          portable_pext(feature_bits[f], select_mask));
      data[f * pr + dst_w0]     |= (extracted << dst_bit0);
      data[f * pr + dst_w0 + 1] |= (extracted >> shift_r);
    }
  }
  matrix->row_count += count;
  labels->insert(labels->end(), count, label);
  return count;
}

// Pad row_count up to 64-aligned boundary (zero-feature neg samples).
void pad_to_word_aligned(PackedFeatureMatrix* matrix,
                         std::vector<int>* labels,
                         std::size_t* neg_count) {
  const std::size_t r = matrix->row_count % PackedFeatureMatrix::kWordBits;
  if (r == 0) return;
  const std::size_t pad = PackedFeatureMatrix::kWordBits - r;
  labels->insert(labels->end(), pad, 0);
  matrix->row_count += pad;
  if (neg_count) *neg_count += pad;
}

// ── Dynamic memory cap ────────────────────────────────────────────────────────
// Computes the maximum number of negative training samples that can safely fit
// in memory, considering both CPU RAM and GPU VRAM.
//
// CPU constraint: 40 % of current free RAM, minus the cost of positive samples.
// GPU constraint: 25 % of free VRAM must accommodate the col_data upload used
//   by gpu_find_best_split:  n_features * ceil(total_samples/64) * 8 bytes.
//
// Returns a value >= 1000 so that there are always enough negatives to train.
std::size_t compute_max_neg_samples(std::size_t n_features,
                                    std::size_t est_pos_count,
                                    std::size_t cpu_alloc_overhead = 0) {
  constexpr std::size_t kHardMin = 1000;
  constexpr std::size_t kHardMax = 20'000'000;

  const std::size_t bytes_per_sample =
      ((n_features + 63) / 64) * sizeof(FeatureWord);
  if (bytes_per_sample == 0) return kHardMax;

  // ── CPU RAM ───────────────────────────────────────────────────────────────
  // cpu_alloc_overhead accounts for pre-allocation padding that only exists
  // in the CPU feature matrix (not on GPU).
  std::size_t free_ram = 4ULL * 1024 * 1024 * 1024;  // 4 GB fallback
  {
    struct sysinfo si{};
    if (sysinfo(&si) == 0)
      free_ram = si.freeram * static_cast<std::size_t>(si.mem_unit);
  }
  const std::size_t cpu_budget    = free_ram * 30 / 100;
  const std::size_t fixed_cost    = (est_pos_count + cpu_alloc_overhead) * bytes_per_sample;
  const std::size_t cpu_avail     = cpu_budget > fixed_cost ? cpu_budget - fixed_cost : 0;
  const std::size_t cpu_max       = cpu_avail / bytes_per_sample;

  // ── GPU VRAM ──────────────────────────────────────────────────────────────
  // col_data size = n_features * packed_words * 8
  // packed_words  = ceil(total_samples / 64)
  // Budget: 25 % of free VRAM
  // Note: GPU does not store the pre-alloc padding, so only est_pos_count
  // is subtracted here.
  std::size_t gpu_max = kHardMax;
#ifdef USE_CUDA
  {
    std::size_t free_vram = 0, total_vram = 0;
    if (cudaMemGetInfo(&free_vram, &total_vram) == cudaSuccess &&
        n_features > 0 && free_vram > 0) {
      const std::size_t vram_budget  = free_vram * 25 / 100;
      const std::size_t pw_max       = vram_budget / (n_features * sizeof(FeatureWord));
      const std::size_t total_max    = pw_max * 64;
      gpu_max = total_max > est_pos_count ? total_max - est_pos_count : 0;
    }
  }
#endif

  const std::size_t result = std::min({cpu_max, gpu_max, kHardMax});
  return std::max(result, kHardMin);
}

bool build_training_data(const circuit& golden,
                         const circuit& trojan,
                         const std::vector<std::vector<int>>& trigger_patterns,
                         const std::vector<int>& feature_nodes,
                         const std::vector<std::vector<int>>* extra_neg_patterns,
                         std::size_t neg_ratio,
                         TrainingData* data,
                         NegSampleTrace* neg_trace,
                         const std::vector<VirtualNodeDef>* virtual_defs = nullptr) {
  const std::size_t vn_count = virtual_defs ? virtual_defs->size() : 0;
  const std::size_t total_features = feature_nodes.size() + vn_count;
  data->labels.clear();
  data->pos_count = 0;
  data->neg_count = 0;

  const bool use_trace =
      neg_trace && !neg_trace->masks.empty() &&
      neg_trace->masks.size() == neg_trace->sizes.size();
  if (neg_trace && !use_trace) {
    neg_trace->masks.clear();
    neg_trace->sizes.clear();
    neg_trace->seed = 1337;
  }

  circuit golden_train = golden;
  circuit trojan_train = trojan;
  packed_circuit trojan_packed(trojan_train);

  // ── Memory-aware positive sample cap ─────────────────────────────────────
  const std::size_t bytes_per_sample =
      ((total_features + 63) / 64) * sizeof(FeatureWord);
  std::size_t max_pos_samples = trigger_patterns.size();
  if (bytes_per_sample > 0) {
    constexpr std::size_t kTrainingBudget = 2ULL * 1024 * 1024 * 1024;
    const std::size_t max_total = kTrainingBudget / bytes_per_sample;
    // Give positives at most half the budget (leave room for negatives).
    max_pos_samples = std::max<std::size_t>(1000, max_total / 2);
  }

  // Subsample trigger patterns if they exceed the budget.
  std::vector<std::vector<int>> subsampled_triggers;
  const std::vector<std::vector<int>>* trigger_ptr = &trigger_patterns;
  if (trigger_patterns.size() > max_pos_samples) {
    std::vector<std::size_t> indices(trigger_patterns.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::mt19937_64 pos_rng(42);
    std::shuffle(indices.begin(), indices.end(), pos_rng);
    indices.resize(max_pos_samples);
    std::sort(indices.begin(), indices.end());
    subsampled_triggers.reserve(max_pos_samples);
    for (std::size_t idx : indices) {
      subsampled_triggers.push_back(trigger_patterns[idx]);
    }
    trigger_ptr = &subsampled_triggers;
    std::cerr << "[mem-cap] pos samples " << trigger_patterns.size()
              << " subsampled to " << max_pos_samples
              << " (" << bytes_per_sample << " bytes/sample"
              << ", n_features=" << total_features << ")\n";
  }
  const auto& actual_triggers = *trigger_ptr;

  const std::size_t estimated_pos = actual_triggers.size();
  const std::size_t estimated_extra_neg =
      extra_neg_patterns ? extra_neg_patterns->size() : 0;
  const std::size_t estimated_target_neg =
      estimated_pos * std::max<std::size_t>(1, neg_ratio);
  // Pre-alloc padding for hard negatives and alignment.  Scaled to avoid
  // over-allocating on large circuits (the old fixed 20000 wasted ~1.25 GB
  // on 500K-feature AES).
  const std::size_t pre_alloc_padding =
      std::min<std::size_t>(5000, estimated_pos) + 256;
  // Pass padding as CPU-only overhead (GPU doesn't store the padding).
  const std::size_t max_neg_cap =
      compute_max_neg_samples(total_features, estimated_pos, pre_alloc_padding);
  const std::size_t capped_target_neg = std::min(estimated_target_neg, max_neg_cap);
  if (estimated_target_neg > max_neg_cap) {
    std::cerr << "[mem-cap] neg target " << estimated_target_neg
              << " capped to " << max_neg_cap
              << " (" << bytes_per_sample << " bytes/sample"
              << ", n_features=" << total_features << ")\n";
  }
  // Pre-allocate column-major matrix.
  const std::size_t estimated_total =
      estimated_pos + estimated_extra_neg + capped_target_neg + pre_alloc_padding;
  data->features.allocate(total_features, estimated_total);
  data->labels.reserve(estimated_total);

#ifdef USE_CUDA
  // ── GPU-accelerated training pipeline (pos + neg) ─────────────────────────
  // Build GPU circuits once, reuse for both positive sample simulation and
  // random negative sample generation.  Falls back to CPU on any failure.
  try {
    const std::size_t num_pis = golden_train.pi_count();
    const std::size_t num_feat = total_features;
    circuit golden_g = golden_train;
    const std::size_t max_wb = gpu_compute_max_word_blocks(
        golden_g.node_count(), trojan_train.node_count(), num_pis, num_feat);
    GpuCircuit gpu_golden(golden_g, max_wb);
    GpuCircuit gpu_trojan(trojan_train, max_wb);

    // Device buffers (persistent across pos + neg phases)
    GpuCircuit::word_t* d_pi_bits   = nullptr;
    GpuCircuit::word_t* d_diff_mask = nullptr;
    GpuCircuit::word_t* d_feat_bits = nullptr;
    cudaMalloc(&d_pi_bits,   num_pis  * max_wb * sizeof(GpuCircuit::word_t));
    cudaMalloc(&d_diff_mask, max_wb   * sizeof(GpuCircuit::word_t));
    cudaMalloc(&d_feat_bits, num_feat * max_wb * sizeof(GpuCircuit::word_t));
    int* d_feat_indices = gpu_upload_ints(feature_nodes);

    // VN CSR on GPU (if any)
    int* d_vn_inp_nodes = nullptr;
    int* d_vn_inp_inv   = nullptr;
    int* d_vn_offsets   = nullptr;
    int* d_vn_counts    = nullptr;
    int* d_vn_gtypes    = nullptr;
    const std::size_t vn_count = virtual_defs ? virtual_defs->size() : 0;
    if (virtual_defs && vn_count > 0) {
      std::vector<int> vn_inp_nodes_h, vn_inp_inv_h, vn_offsets_h,
                       vn_counts_h, vn_gtypes_h;
      int off = 0;
      for (const auto& vd : *virtual_defs) {
        vn_offsets_h.push_back(off);
        vn_counts_h.push_back(static_cast<int>(vd.inputs.size()));
        vn_gtypes_h.push_back(static_cast<int>(vd.op));
        for (const auto& inp : vd.inputs) {
          vn_inp_nodes_h.push_back(inp.first);
          vn_inp_inv_h.push_back(inp.second ? 1 : 0);
        }
        off += static_cast<int>(vd.inputs.size());
      }
      d_vn_inp_nodes = gpu_upload_ints(vn_inp_nodes_h);
      d_vn_inp_inv   = gpu_upload_ints(vn_inp_inv_h);
      d_vn_offsets   = gpu_upload_ints(vn_offsets_h);
      d_vn_counts    = gpu_upload_ints(vn_counts_h);
      d_vn_gtypes    = gpu_upload_ints(vn_gtypes_h);
    }

    // Host download buffer
    std::vector<GpuCircuit::word_t> h_feat_bits(num_feat * max_wb);

    // Reusable per-word-block buffer for selected-sample writes.
    std::vector<PackedWord> wb_feat(num_feat);

    // ── Phase 1: GPU positive sample simulation ─────────────────────────────
    // Pack trigger patterns into word-block PI format and simulate on GPU.
    {
      const std::size_t pos_total = actual_triggers.size();
      std::size_t pos_offset = 0;
      while (pos_offset < pos_total) {
        const std::size_t chunk = std::min(
            max_wb * packed_circuit::kWordBits, pos_total - pos_offset);
        const std::size_t chunk_wb = (chunk + packed_circuit::kWordBits - 1) /
                                     packed_circuit::kWordBits;

        // Pack trigger patterns into PI bit layout [pi * chunk_wb + wb].
        std::vector<GpuCircuit::word_t> h_pi_pos(num_pis * chunk_wb, 0);
        for (std::size_t i = 0; i < chunk; ++i) {
          const std::size_t wb = i / packed_circuit::kWordBits;
          const std::size_t bit = i % packed_circuit::kWordBits;
          const auto& pat = actual_triggers[pos_offset + i];
          for (std::size_t p = 0; p < num_pis && p < pat.size(); ++p) {
            if (pat[p])
              h_pi_pos[p * chunk_wb + wb] |=
                  (GpuCircuit::word_t(1) << bit);
          }
        }

        // Upload PI, simulate trojan, gather features
        cudaMemcpy(d_pi_bits, h_pi_pos.data(),
                   num_pis * chunk_wb * sizeof(GpuCircuit::word_t),
                   cudaMemcpyHostToDevice);
        gpu_trojan.simulate(d_pi_bits, chunk_wb);
        gpu_gather_nodes(gpu_trojan.d_values(), d_feat_indices,
                         feature_nodes.size(), chunk_wb, d_feat_bits);
        if (vn_count > 0) {
          const GpuCircuit::word_t pmask =
              (chunk % packed_circuit::kWordBits == 0)
                  ? ~GpuCircuit::word_t(0)
                  : ((GpuCircuit::word_t(1)
                      << (chunk % packed_circuit::kWordBits)) - 1);
          gpu_compute_virtual_features(
              gpu_trojan.d_values(),
              d_vn_inp_nodes, d_vn_inp_inv,
              d_vn_offsets, d_vn_counts, d_vn_gtypes,
              vn_count, chunk_wb, pmask,
              d_feat_bits + feature_nodes.size() * chunk_wb);
        }

        // Download feature bits and write directly to column-major matrix.
        cudaMemcpy(h_feat_bits.data(), d_feat_bits,
                   num_feat * chunk_wb * sizeof(GpuCircuit::word_t),
                   cudaMemcpyDeviceToHost);

        // O(F * chunk_wb) — 64x faster than old per-sample row build.
        write_gpu_chunk(h_feat_bits.data(), num_feat, chunk_wb, chunk,
                        &data->features, &data->labels, 1);
        data->pos_count += chunk;
        pos_offset += chunk;
      }
    }

    if (data->pos_count == 0) {
      // Free and fall through to CPU path
      cudaFree(d_pi_bits); cudaFree(d_diff_mask); cudaFree(d_feat_bits);
      cudaFree(d_feat_indices);
      if (d_vn_inp_nodes) cudaFree(d_vn_inp_nodes);
      if (d_vn_inp_inv)   cudaFree(d_vn_inp_inv);
      if (d_vn_offsets)   cudaFree(d_vn_offsets);
      if (d_vn_counts)    cudaFree(d_vn_counts);
      if (d_vn_gtypes)    cudaFree(d_vn_gtypes);
      return false;
    }

    // ── Phase 1b: extra neg patterns (explicit, not random) ─────────────────
    if (extra_neg_patterns && !extra_neg_patterns->empty()) {
      pad_to_word_aligned(&data->features, &data->labels, &data->neg_count);
      const std::size_t extra_total = extra_neg_patterns->size();
      std::size_t extra_offset = 0;
      while (extra_offset < extra_total) {
        const std::size_t chunk = std::min(
            max_wb * packed_circuit::kWordBits, extra_total - extra_offset);
        const std::size_t chunk_wb = (chunk + packed_circuit::kWordBits - 1) /
                                     packed_circuit::kWordBits;

        std::vector<GpuCircuit::word_t> h_pi_neg(num_pis * chunk_wb, 0);
        for (std::size_t i = 0; i < chunk; ++i) {
          const std::size_t wb = i / packed_circuit::kWordBits;
          const std::size_t bit = i % packed_circuit::kWordBits;
          const auto& pat = (*extra_neg_patterns)[extra_offset + i];
          for (std::size_t p = 0; p < num_pis && p < pat.size(); ++p) {
            if (pat[p])
              h_pi_neg[p * chunk_wb + wb] |=
                  (GpuCircuit::word_t(1) << bit);
          }
        }
        cudaMemcpy(d_pi_bits, h_pi_neg.data(),
                   num_pis * chunk_wb * sizeof(GpuCircuit::word_t),
                   cudaMemcpyHostToDevice);
        gpu_trojan.simulate(d_pi_bits, chunk_wb);
        gpu_gather_nodes(gpu_trojan.d_values(), d_feat_indices,
                         feature_nodes.size(), chunk_wb, d_feat_bits);
        if (vn_count > 0) {
          const GpuCircuit::word_t pmask =
              (chunk % packed_circuit::kWordBits == 0)
                  ? ~GpuCircuit::word_t(0)
                  : ((GpuCircuit::word_t(1)
                      << (chunk % packed_circuit::kWordBits)) - 1);
          gpu_compute_virtual_features(
              gpu_trojan.d_values(),
              d_vn_inp_nodes, d_vn_inp_inv,
              d_vn_offsets, d_vn_counts, d_vn_gtypes,
              vn_count, chunk_wb, pmask,
              d_feat_bits + feature_nodes.size() * chunk_wb);
        }
        cudaMemcpy(h_feat_bits.data(), d_feat_bits,
                   num_feat * chunk_wb * sizeof(GpuCircuit::word_t),
                   cudaMemcpyDeviceToHost);
        write_gpu_chunk(h_feat_bits.data(), num_feat, chunk_wb, chunk,
                        &data->features, &data->labels, 0);
        data->neg_count += chunk;
        extra_offset += chunk;
      }
    }

    // ── Phase 1c: neg trace replay (if any) ─────────────────────────────────
    if (use_trace) {
      std::mt19937_64 rng(neg_trace->seed);
      const std::size_t trace_pi_count = golden_train.pi_count();
      std::vector<PackedWord> trace_pi_bits(trace_pi_count);
      for (std::size_t block = 0; block < neg_trace->masks.size(); ++block) {
        const std::size_t block_size =
            std::min<std::size_t>(packed_circuit::kWordBits,
                                  static_cast<std::size_t>(neg_trace->sizes[block]));
        if (block_size == 0) continue;
        for (std::size_t i = 0; i < trace_pi_count; ++i) trace_pi_bits[i] = rng();

        const PackedWord mask = packed_circuit::mask_for_count(block_size);
        PackedWord sel_mask = neg_trace->masks[block] & mask;
        if (sel_mask == 0) continue;

        cudaMemcpy(d_pi_bits, trace_pi_bits.data(),
                   trace_pi_count * sizeof(PackedWord), cudaMemcpyHostToDevice);
        gpu_trojan.simulate(d_pi_bits, 1);
        gpu_gather_nodes(gpu_trojan.d_values(), d_feat_indices,
                         feature_nodes.size(), 1, d_feat_bits);
        if (vn_count > 0) {
          gpu_compute_virtual_features(
              gpu_trojan.d_values(),
              d_vn_inp_nodes, d_vn_inp_inv,
              d_vn_offsets, d_vn_counts, d_vn_gtypes,
              vn_count, 1, mask,
              d_feat_bits + feature_nodes.size());
        }
        cudaMemcpy(h_feat_bits.data(), d_feat_bits,
                   num_feat * sizeof(GpuCircuit::word_t), cudaMemcpyDeviceToHost);

        for (std::size_t f = 0; f < num_feat; ++f)
          wb_feat[f] = h_feat_bits[f];
        data->neg_count += append_word_block_selective(
            wb_feat.data(), num_feat, sel_mask,
            &data->features, &data->labels, 0);
      }

      // Free GPU resources and return
      cudaFree(d_pi_bits); cudaFree(d_diff_mask); cudaFree(d_feat_bits);
      cudaFree(d_feat_indices);
      if (d_vn_inp_nodes) cudaFree(d_vn_inp_nodes);
      if (d_vn_inp_inv)   cudaFree(d_vn_inp_inv);
      if (d_vn_offsets)   cudaFree(d_vn_offsets);
      if (d_vn_counts)    cudaFree(d_vn_counts);
      if (d_vn_gtypes)    cudaFree(d_vn_gtypes);
      return true;
    }

    // ── Phase 2: GPU random negative sample generation ──────────────────────
    // Cap total training set to avoid multi-GB data.
    constexpr std::size_t kMaxTrainingNeg = 2'000'000;
    const std::size_t remaining_budget =
        (max_pos_samples > data->pos_count)
            ? (max_pos_samples * 2 - data->pos_count)
            : data->pos_count;
    const std::size_t raw_neg =
        data->pos_count * std::max<std::size_t>(1, neg_ratio);
    const std::size_t target_negatives =
        std::min({raw_neg, max_neg_cap, kMaxTrainingNeg, remaining_budget});
    const std::size_t max_attempts = target_negatives * 20 + 1000;
    std::cerr << "[DBG] target_neg=" << target_negatives
              << " max_neg_cap=" << max_neg_cap
              << " pos=" << data->pos_count
              << " neg_ratio=" << neg_ratio << "\n";

    std::vector<GpuCircuit::word_t> h_diff_mask(max_wb);
    unsigned long long gpu_seed = 42ULL;
    std::size_t attempts = 0;

    while (data->neg_count < target_negatives && attempts < max_attempts) {
      const std::size_t remaining_needed = target_negatives - data->neg_count;
      const std::size_t remaining_wb = (max_attempts - attempts +
                                         packed_circuit::kWordBits - 1) /
                                        packed_circuit::kWordBits;
      const std::size_t need_wb = remaining_needed / packed_circuit::kWordBits
                                  + 20;
      const std::size_t num_wb = std::min(max_wb,
          std::min(remaining_wb, need_wb));
      if (num_wb == 0) break;

      gpu_generate_random_pi(d_pi_bits, num_pis, num_wb, gpu_seed);
      gpu_seed += num_pis * num_wb + 1;
      gpu_golden.simulate(d_pi_bits, num_wb);
      gpu_trojan.simulate(d_pi_bits, num_wb);
      gpu_compare_po(gpu_golden, gpu_trojan, d_diff_mask, num_wb,
                     ~GpuCircuit::word_t(0));
      gpu_gather_nodes(gpu_trojan.d_values(), d_feat_indices,
                       feature_nodes.size(), num_wb, d_feat_bits);
      if (vn_count > 0) {
        gpu_compute_virtual_features(
            gpu_trojan.d_values(),
            d_vn_inp_nodes, d_vn_inp_inv,
            d_vn_offsets, d_vn_counts, d_vn_gtypes,
            vn_count, num_wb, ~GpuCircuit::word_t(0),
            d_feat_bits + feature_nodes.size() * num_wb);
      }

      cudaMemcpy(h_diff_mask.data(), d_diff_mask,
                 num_wb * sizeof(GpuCircuit::word_t), cudaMemcpyDeviceToHost);
      cudaMemcpy(h_feat_bits.data(), d_feat_bits,
                 num_feat * num_wb * sizeof(GpuCircuit::word_t),
                 cudaMemcpyDeviceToHost);

      if (attempts == 0) {
        std::cerr << "[DBG2] num_wb=" << num_wb
                  << " h_diff_mask[0]=" << std::hex << h_diff_mask[0]
                  << " h_diff_mask[1]=" << h_diff_mask[1] << std::dec << "\n";
      }
      for (std::size_t wb = 0;
           wb < num_wb && data->neg_count < target_negatives; ++wb) {
        PackedWord notrigger = ~h_diff_mask[wb];
        PackedWord selected_mask_wb = 0;
        if (notrigger) {
          for (std::size_t f = 0; f < num_feat; ++f)
            wb_feat[f] = h_feat_bits[f * num_wb + wb];
          const std::size_t cap = target_negatives - data->neg_count;
          const std::size_t available = popcount_word(notrigger);
          selected_mask_wb = (available <= cap)
              ? notrigger : keep_n_set_bits(notrigger, cap);
          std::size_t added = append_word_block_selective(
              wb_feat.data(), num_feat, selected_mask_wb,
              &data->features, &data->labels, 0);
          data->neg_count += added;
        }
        if (neg_trace) {
          neg_trace->masks.push_back(selected_mask_wb);
          neg_trace->sizes.push_back(static_cast<std::uint8_t>(64));
        }
      }
      attempts += num_wb * packed_circuit::kWordBits;
    }

    // Free GPU resources
    cudaFree(d_pi_bits); cudaFree(d_diff_mask); cudaFree(d_feat_bits);
    cudaFree(d_feat_indices);
    if (d_vn_inp_nodes) cudaFree(d_vn_inp_nodes);
    if (d_vn_inp_inv)   cudaFree(d_vn_inp_inv);
    if (d_vn_offsets)   cudaFree(d_vn_offsets);
    if (d_vn_counts)    cudaFree(d_vn_counts);
    if (d_vn_gtypes)    cudaFree(d_vn_gtypes);
    return true;
  } catch (const std::exception& e) {
    std::cerr << "[GPU training pipeline failed, falling back to CPU] "
              << e.what() << "\n";
  }
  // ── fallback to CPU path ──────────────────────────────────────────────────
#endif  // USE_CUDA

  // ── CPU: positive samples ────────────────────────────────────────────────
  std::size_t trigger_offset = 0;
  while (trigger_offset < actual_triggers.size()) {
    const std::size_t remaining = actual_triggers.size() - trigger_offset;
    const std::size_t block_size =
        std::min(packed_circuit::kWordBits, remaining);
    std::vector<std::vector<int>> patterns;
    patterns.reserve(block_size);
    for (std::size_t p = 0; p < block_size; ++p) {
      patterns.push_back(actual_triggers[trigger_offset + p]);
    }

    bool packed_ok = false;
    try {
      trojan_packed.simulate(patterns);
      packed_ok = true;
    } catch (const std::exception& e) {
      std::cerr << "Training trigger simulation error: " << e.what() << "\n";
    }

    if (packed_ok) {
      std::vector<PackedWord> feature_bits =
          gather_feature_bits(trojan_packed, feature_nodes);
      if (virtual_defs && !virtual_defs->empty()) {
        const auto vn_bits = compute_virtual_feature_bits(
            trojan_packed, *virtual_defs, trojan_packed.pattern_mask());
        feature_bits.insert(feature_bits.end(), vn_bits.begin(), vn_bits.end());
      }
      write_word_block(feature_bits.data(), total_features, block_size,
                       &data->features, &data->labels, 1);
      data->pos_count += block_size;
    } else {
      for (const auto& pattern : patterns) {
        try {
          trojan_train.simulate(pattern);
        } catch (const std::exception& e) {
          std::cerr << "Training trigger simulation error: " << e.what() << "\n";
          continue;
        }
        // Write directly into column-major matrix per feature.
        const std::size_t dst = data->features.row_count;
        const std::size_t dst_w = dst / PackedFeatureMatrix::kWordBits;
        const FeatureWord dst_bit =
            FeatureWord(1) << (dst % PackedFeatureMatrix::kWordBits);
        const std::size_t pr = data->features.packed_rows();
        auto* mdata = data->features.data.data();
        for (std::size_t fi = 0; fi < feature_nodes.size(); ++fi) {
          if (trojan_train.get_cell(feature_nodes[fi]).val) {
            mdata[fi * pr + dst_w] |= dst_bit;
          }
        }
        if (virtual_defs) {
          for (std::size_t vi = 0; vi < virtual_defs->size(); ++vi) {
            if (compute_virtual_feature_value(trojan_train, (*virtual_defs)[vi])) {
              mdata[(feature_nodes.size() + vi) * pr + dst_w] |= dst_bit;
            }
          }
        }
        data->features.row_count += 1;
        data->labels.push_back(1);
        data->pos_count += 1;
      }
    }

    trigger_offset += block_size;
  }

  if (data->pos_count == 0) {
    return false;
  }

  // CPU: extra neg patterns
  if (extra_neg_patterns && !extra_neg_patterns->empty()) {
    std::size_t extra_offset = 0;
    while (extra_offset < extra_neg_patterns->size()) {
      const std::size_t remaining = extra_neg_patterns->size() - extra_offset;
      const std::size_t block_size =
          std::min(packed_circuit::kWordBits, remaining);
      std::vector<std::vector<int>> patterns;
      patterns.reserve(block_size);
      for (std::size_t p = 0; p < block_size; ++p) {
        patterns.push_back((*extra_neg_patterns)[extra_offset + p]);
      }
      bool packed_ok = false;
      try {
        trojan_packed.simulate(patterns);
        packed_ok = true;
      } catch (const std::exception&) {}
      if (packed_ok) {
        std::vector<PackedWord> feature_bits =
            gather_feature_bits(trojan_packed, feature_nodes);
        if (virtual_defs && !virtual_defs->empty()) {
          const auto vn_bits = compute_virtual_feature_bits(
              trojan_packed, *virtual_defs, trojan_packed.pattern_mask());
          feature_bits.insert(feature_bits.end(), vn_bits.begin(), vn_bits.end());
        }
        write_word_block(feature_bits.data(), total_features, block_size,
                         &data->features, &data->labels, 0);
        data->neg_count += block_size;
      }
      extra_offset += block_size;
    }
  }

  // CPU: neg trace replay
  if (use_trace) {
    std::mt19937_64 rng(neg_trace->seed);
    const std::size_t trace_pi_count = golden_train.pi_count();
    std::vector<PackedWord> trace_pi_bits(trace_pi_count);
    for (std::size_t block = 0; block < neg_trace->masks.size(); ++block) {
      const std::size_t block_size =
          std::min<std::size_t>(packed_circuit::kWordBits,
                                static_cast<std::size_t>(neg_trace->sizes[block]));
      if (block_size == 0) continue;
      for (std::size_t i = 0; i < trace_pi_count; ++i) trace_pi_bits[i] = rng();
      const PackedWord mask = packed_circuit::mask_for_count(block_size);
      PackedWord sel_mask = neg_trace->masks[block] & mask;
      if (sel_mask == 0) continue;
      try {
        trojan_packed.simulate_bits(trace_pi_bits, block_size);
      } catch (const std::exception&) { continue; }
      std::vector<PackedWord> feature_bits =
          gather_feature_bits(trojan_packed, feature_nodes);
      if (virtual_defs && !virtual_defs->empty()) {
        const auto vn_bits = compute_virtual_feature_bits(
            trojan_packed, *virtual_defs, trojan_packed.pattern_mask());
        feature_bits.insert(feature_bits.end(), vn_bits.begin(), vn_bits.end());
      }
      data->neg_count += append_word_block_selective(
          feature_bits.data(), total_features, sel_mask,
          &data->features, &data->labels, 0);
    }
    return true;
  }

  // CPU: neg cap computation
  constexpr std::size_t kMaxTrainingNeg_cpu = 2'000'000;
  const std::size_t remaining_budget_cpu =
      (max_pos_samples > data->pos_count)
          ? (max_pos_samples * 2 - data->pos_count)
          : data->pos_count;
  const std::size_t raw_neg_cpu =
      data->pos_count * std::max<std::size_t>(1, neg_ratio);
  const std::size_t target_negatives =
      std::min({raw_neg_cpu, max_neg_cap, kMaxTrainingNeg_cpu, remaining_budget_cpu});
  const std::size_t max_attempts = target_negatives * 20 + 1000;
  std::cerr << "[DBG] target_neg=" << target_negatives
            << " max_neg_cap=" << max_neg_cap
            << " pos=" << data->pos_count
            << " neg_ratio=" << neg_ratio << "\n";

  {
    std::size_t attempts = 0;
    std::mt19937_64 rng(1337);
    packed_circuit golden_packed(golden_train);
    golden_packed.prepare_batch();
    trojan_packed.prepare_batch();
    const std::size_t neg_pi_count = golden_train.pi_count();
    std::vector<PackedWord> neg_pi_bits(neg_pi_count);

    while (data->neg_count < target_negatives && attempts < max_attempts) {
      const std::size_t remaining_attempts = max_attempts - attempts;
      const std::size_t block_size =
          std::min(packed_circuit::kWordBits, remaining_attempts);
      if (block_size == 0) {
        break;
      }
      for (std::size_t i = 0; i < neg_pi_count; ++i) {
        neg_pi_bits[i] = rng();
      }

      bool packed_ok = false;
      try {
        golden_packed.simulate_bits_fast(neg_pi_bits.data(), block_size);
        trojan_packed.simulate_bits_fast(neg_pi_bits.data(), block_size);
        packed_ok = true;
      } catch (const std::exception&) {
        packed_ok = false;
      }

      PackedWord selected_mask = 0;
      if (packed_ok) {
        const PackedWord mask = packed_circuit::mask_for_count(block_size);
        PackedWord diff_mask = 0;
        for (std::size_t o = 0; o < golden_train.po_count(); ++o) {
          diff_mask |= (golden_packed.po_bits(o) ^ trojan_packed.po_bits(o));
        }
        diff_mask &= mask;
        PackedWord notrigger_mask = mask & ~diff_mask;
        if (notrigger_mask != 0) {
          const std::size_t remaining_needed = target_negatives - data->neg_count;
          std::vector<PackedWord> feature_bits =
              gather_feature_bits(trojan_packed, feature_nodes);
          if (virtual_defs && !virtual_defs->empty()) {
            const auto vn_bits = compute_virtual_feature_bits(
                trojan_packed, *virtual_defs, trojan_packed.pattern_mask());
            feature_bits.insert(feature_bits.end(), vn_bits.begin(), vn_bits.end());
          }
          const std::size_t available = popcount_word(notrigger_mask);
          selected_mask = (available <= remaining_needed)
              ? notrigger_mask : keep_n_set_bits(notrigger_mask, remaining_needed);
          data->neg_count += append_word_block_selective(
              feature_bits.data(), total_features, selected_mask,
              &data->features, &data->labels, 0);
        }
      }
      if (neg_trace) {
        neg_trace->masks.push_back(selected_mask);
        const std::size_t size = std::min(block_size, packed_circuit::kWordBits);
        neg_trace->sizes.push_back(static_cast<std::uint8_t>(size));
      }
      attempts += block_size;
    }
  }  // end CPU path

  return true;
}

bool train_model(const TrainingData& data,
                 const DecisionTreeOptions& options,
                 DecisionTreeModel* model,
                 std::size_t* train_pos,
                 std::size_t* train_neg,
                 std::size_t* train_false_pos,
                 std::size_t* train_false_neg,
                 std::string* error) {
  if (error) {
    error->clear();
  }
  *model = build_decision_tree(data.features, data.labels, options, error);
  if (error && !error->empty()) {
    std::cerr << "Decision tree error: " << *error << "\n";
    return false;
  }

  *train_pos = 0;
  *train_neg = 0;
  *train_false_pos = 0;
  *train_false_neg = 0;
  for (std::size_t i = 0; i < data.features.row_count; ++i) {
    const bool pred = eval_rules_colmajor(model->rules, data.features, i);
    if (data.labels[i] == 1) {
      *train_pos += 1;
      if (!pred) {
        *train_false_neg += 1;
      }
    } else {
      *train_neg += 1;
      if (pred) {
        *train_false_pos += 1;
      }
    }
  }
  return true;
}

EvalResult eval_and_mine(const circuit& golden,
                         const circuit& trojan,
                         const std::vector<int>& feature_nodes,
                         const DecisionTreeModel& model,
                         std::size_t eval_limit,
                         std::size_t max_add,
                         TrainingData* data,
                         std::uint32_t seed,
                         const std::vector<VirtualNodeDef>* virtual_defs = nullptr) {
  const std::size_t total_features = feature_nodes.size() +
      (virtual_defs ? virtual_defs->size() : 0);
  EvalResult result;
  const std::size_t max_attempts = eval_limit * 20 + 1000;

#ifdef USE_CUDA
  try {
    const std::size_t num_pis = golden.pi_count();
    circuit golden_e = golden;
    circuit trojan_e = trojan;
    const std::size_t max_wb = gpu_compute_max_word_blocks(
        golden_e.node_count(), trojan_e.node_count(), num_pis, total_features);
    GpuCircuit gpu_golden(golden_e, max_wb);
    GpuCircuit gpu_trojan(trojan_e, max_wb);

    GpuCircuit::word_t* d_pi_bits   = nullptr;
    GpuCircuit::word_t* d_diff_mask = nullptr;
    GpuCircuit::word_t* d_feat_bits = nullptr;
    cudaMalloc(&d_pi_bits,   num_pis       * max_wb * sizeof(GpuCircuit::word_t));
    cudaMalloc(&d_diff_mask, max_wb         * sizeof(GpuCircuit::word_t));
    cudaMalloc(&d_feat_bits, total_features * max_wb * sizeof(GpuCircuit::word_t));

    int* d_feat_indices = gpu_upload_ints(feature_nodes);

    int* d_vn_inp_nodes = nullptr;
    int* d_vn_inp_inv   = nullptr;
    int* d_vn_offsets   = nullptr;
    int* d_vn_counts    = nullptr;
    int* d_vn_gtypes    = nullptr;
    const std::size_t vn_count = virtual_defs ? virtual_defs->size() : 0;
    if (virtual_defs && vn_count > 0) {
      std::vector<int> vn_inp_nodes_h, vn_inp_inv_h, vn_offsets_h,
                       vn_counts_h, vn_gtypes_h;
      int off = 0;
      for (const auto& vd : *virtual_defs) {
        vn_offsets_h.push_back(off);
        vn_counts_h.push_back(static_cast<int>(vd.inputs.size()));
        vn_gtypes_h.push_back(static_cast<int>(vd.op));
        for (const auto& inp : vd.inputs) {
          vn_inp_nodes_h.push_back(inp.first);
          vn_inp_inv_h.push_back(inp.second ? 1 : 0);
        }
        off += static_cast<int>(vd.inputs.size());
      }
      d_vn_inp_nodes = gpu_upload_ints(vn_inp_nodes_h);
      d_vn_inp_inv   = gpu_upload_ints(vn_inp_inv_h);
      d_vn_offsets   = gpu_upload_ints(vn_offsets_h);
      d_vn_counts    = gpu_upload_ints(vn_counts_h);
      d_vn_gtypes    = gpu_upload_ints(vn_gtypes_h);
    }

    std::vector<GpuCircuit::word_t> h_diff_mask(max_wb);
    std::vector<GpuCircuit::word_t> h_feat_bits(total_features * max_wb);
    std::vector<PackedWord> wb_feat_eval(total_features);

    unsigned long long gpu_seed = static_cast<unsigned long long>(seed) + 9999ULL;
    std::size_t attempts = 0;

    while (result.checked < eval_limit && attempts < max_attempts) {
      const std::size_t remaining_wb = (max_attempts - attempts +
                                         packed_circuit::kWordBits - 1) /
                                        packed_circuit::kWordBits;
      const std::size_t num_wb = std::min(max_wb, remaining_wb);
      if (num_wb == 0) break;

      gpu_generate_random_pi(d_pi_bits, num_pis, num_wb, gpu_seed);
      gpu_seed += num_pis * num_wb + 1;
      gpu_golden.simulate(d_pi_bits, num_wb);
      gpu_trojan.simulate(d_pi_bits, num_wb);
      gpu_compare_po(gpu_golden, gpu_trojan, d_diff_mask, num_wb,
                     ~GpuCircuit::word_t(0));
      gpu_gather_nodes(gpu_trojan.d_values(), d_feat_indices,
                       static_cast<int>(feature_nodes.size()), num_wb,
                       d_feat_bits);
      if (vn_count > 0) {
        gpu_compute_virtual_features(
            gpu_trojan.d_values(),
            d_vn_inp_nodes, d_vn_inp_inv,
            d_vn_offsets, d_vn_counts, d_vn_gtypes,
            vn_count, num_wb, ~GpuCircuit::word_t(0),
            d_feat_bits + feature_nodes.size() * num_wb);
      }
      cudaMemcpy(h_diff_mask.data(), d_diff_mask,
                 num_wb * sizeof(GpuCircuit::word_t), cudaMemcpyDeviceToHost);
      cudaMemcpy(h_feat_bits.data(), d_feat_bits,
                 total_features * num_wb * sizeof(GpuCircuit::word_t),
                 cudaMemcpyDeviceToHost);

      for (std::size_t wb = 0;
           wb < num_wb && result.checked < eval_limit; ++wb) {
        PackedWord notrigger = ~h_diff_mask[wb];
        if (!notrigger) continue;
        for (std::size_t f = 0; f < total_features; ++f)
          wb_feat_eval[f] = h_feat_bits[f * num_wb + wb];
        while (notrigger && result.checked < eval_limit) {
          const std::size_t bit = ctz_word(notrigger);
          const PackedWord pmask_bit = PackedWord(1) << bit;
          // Evaluate rules directly from word-block features — O(K*R) not O(F).
          bool match = false;
          for (const auto& rule : model.rules) {
            bool rm = true;
            for (const auto& term : rule.terms) {
              const int val = (wb_feat_eval[term.first] & pmask_bit) ? 1 : 0;
              if (val != term.second) { rm = false; break; }
            }
            if (rm) { match = true; break; }
          }
          if (match) {
            result.false_pos += 1;
            if (data && result.added < max_add) {
              data->features.ensure_row_capacity(data->features.row_count + 1);
              append_single_sample(wb_feat_eval.data(), total_features, bit,
                                   &data->features, &data->labels, 0);
              data->neg_count += 1;
              result.added += 1;
            }
          }
          result.checked += 1;
          notrigger &= (notrigger - 1);
        }
      }
      attempts += num_wb * packed_circuit::kWordBits;
    }

    cudaFree(d_pi_bits);
    cudaFree(d_diff_mask);
    cudaFree(d_feat_bits);
    cudaFree(d_feat_indices);
    if (d_vn_inp_nodes) cudaFree(d_vn_inp_nodes);
    if (d_vn_inp_inv)   cudaFree(d_vn_inp_inv);
    if (d_vn_offsets)   cudaFree(d_vn_offsets);
    if (d_vn_counts)    cudaFree(d_vn_counts);
    if (d_vn_gtypes)    cudaFree(d_vn_gtypes);
    return result;
  } catch (const std::exception& e) {
    std::cerr << "[GPU eval_and_mine failed, falling back to CPU] " << e.what() << "\n";
    result = EvalResult{};
  }
#endif  // USE_CUDA

  // ── CPU fallback ──────────────────────────────────────────────────────────
  {
    std::size_t attempts = 0;
    std::mt19937_64 rng(seed);
    circuit golden_eval = golden;
    circuit trojan_eval = trojan;
    packed_circuit golden_packed(golden_eval);
    packed_circuit trojan_packed_eval(trojan_eval);
    golden_packed.prepare_batch();
    trojan_packed_eval.prepare_batch();
    const std::size_t eval_pi_count = golden_eval.pi_count();
    std::vector<PackedWord> eval_pi_bits(eval_pi_count);

    while (result.checked < eval_limit && attempts < max_attempts) {
      const std::size_t remaining_attempts = max_attempts - attempts;
      const std::size_t block_size =
          std::min(packed_circuit::kWordBits, remaining_attempts);
      if (block_size == 0) break;
      for (std::size_t i = 0; i < eval_pi_count; ++i) eval_pi_bits[i] = rng();

      try {
        golden_packed.simulate_bits_fast(eval_pi_bits.data(), block_size);
        trojan_packed_eval.simulate_bits_fast(eval_pi_bits.data(), block_size);
      } catch (const std::exception&) {
        attempts += block_size;
        continue;
      }

      const PackedWord mask = packed_circuit::mask_for_count(block_size);
      PackedWord diff_mask = 0;
      for (std::size_t o = 0; o < golden_eval.po_count(); ++o)
        diff_mask |= (golden_packed.po_bits(o) ^ trojan_packed_eval.po_bits(o));
      diff_mask &= mask;
      PackedWord notrigger_mask = mask & ~diff_mask;
      if (notrigger_mask != 0) {
        std::vector<PackedWord> feature_bits =
            gather_feature_bits(trojan_packed_eval, feature_nodes);
        if (virtual_defs && !virtual_defs->empty()) {
          const auto vn_bits = compute_virtual_feature_bits(
              trojan_packed_eval, *virtual_defs, trojan_packed_eval.pattern_mask());
          feature_bits.insert(feature_bits.end(), vn_bits.begin(), vn_bits.end());
        }
        while (notrigger_mask && result.checked < eval_limit) {
          const std::size_t bit = ctz_word(notrigger_mask);
          const PackedWord pmask_bit = PackedWord(1) << bit;
          bool match = false;
          for (const auto& rule : model.rules) {
            bool rm = true;
            for (const auto& term : rule.terms) {
              const int val = (feature_bits[term.first] & pmask_bit) ? 1 : 0;
              if (val != term.second) { rm = false; break; }
            }
            if (rm) { match = true; break; }
          }
          if (match) {
            result.false_pos += 1;
            if (data && result.added < max_add) {
              data->features.ensure_row_capacity(data->features.row_count + 1);
              append_single_sample(feature_bits.data(), total_features, bit,
                                   &data->features, &data->labels, 0);
              data->neg_count += 1;
              result.added += 1;
            }
          }
          result.checked += 1;
          notrigger_mask &= (notrigger_mask - 1);
        }
      }
      attempts += block_size;
    }
  }
  return result;
}

void print_rules(const circuit& trojan,
                 const std::vector<int>& feature_nodes,
                 const DecisionTreeModel& model,
                 const std::vector<VirtualNodeDef>* virtual_defs = nullptr) {
  std::cout << "decision_tree_rules " << model.rules.size()
            << " depth_used " << model.max_depth_used
            << " leaf_count " << model.leaf_count << '\n';
  for (std::size_t i = 0; i < model.rules.size(); ++i) {
    const auto& rule = model.rules[i];
    std::cout << "rule " << (i + 1) << ": ";
    if (rule.terms.empty()) {
      std::cout << "TRUE\n";
      continue;
    }
    for (std::size_t t = 0; t < rule.terms.size(); ++t) {
      if (t > 0) {
        std::cout << " & ";
      }
      const std::size_t feature_idx = rule.terms[t].first;
      const int value = rule.terms[t].second;
      if (feature_idx < feature_nodes.size()) {
        std::cout << trojan.node_name(feature_nodes[feature_idx]) << '=' << value;
      } else if (virtual_defs &&
                 (feature_idx - feature_nodes.size()) < virtual_defs->size()) {
        std::cout << "vf_" << (feature_idx - feature_nodes.size()) << '=' << value;
      } else {
        std::cout << "f" << feature_idx << '=' << value;
      }
    }
    std::cout << '\n';
  }
}

bool run_mining_loop(const circuit& golden,
                     const circuit& trojan,
                     const std::vector<int>& feature_nodes,
                     const DecisionTreeOptions& options,
                     TrainingData* data,
                     std::size_t rounds,
                     std::size_t max_add,
                     std::size_t eval_count,
                     double target_rate,
                     MiningResult* result,
                     std::string* error,
                     const std::vector<VirtualNodeDef>* virtual_defs = nullptr,
                     bool strict_phase = false) {
  const std::size_t total_rounds = std::max<std::size_t>(1, rounds);
  result->feature_nodes = feature_nodes;
  result->hard_added = 0;
  result->rounds_used = 0;

  for (std::size_t round = 0; round < total_rounds; ++round) {
    if (!train_model(*data,
                     options,
                     &result->model,
                     &result->train_pos,
                     &result->train_neg,
                     &result->train_false_pos,
                     &result->train_false_neg,
                     error)) {
      return false;
    }
    result->dt_builds += 1;
    if (strict_phase) {
      result->strict_dt_builds += 1;
    }

    const std::size_t rules_before = result->model.rules.size();
    const std::size_t lits_before = count_rule_literals(result->model.rules);
    simplify_rules(&result->model.rules);
    minimize_rules_with_data(&result->model.rules, data->features, data->labels);
    simplify_rules(&result->model.rules);
    result->model.leaf_count = result->model.rules.size();
    const std::size_t rules_after = result->model.rules.size();
    const std::size_t lits_after = count_rule_literals(result->model.rules);
    if (rules_before != rules_after || lits_before != lits_after) {
      std::cout << "rule_minimize " << rules_before
                << " -> " << rules_after
                << " literals " << lits_before
                << " -> " << lits_after << "\n";
    }

    const std::size_t add_cap = (round + 1 < total_rounds) ? max_add : 0;
    EvalResult eval = eval_and_mine(golden,
                                    trojan,
                                    feature_nodes,
                                    result->model,
                                    eval_count,
                                    add_cap,
                                    data,
                                    static_cast<std::uint32_t>(2027 + round),
                                    virtual_defs);
    result->eval_checked = eval.checked;
    result->eval_false_pos = eval.false_pos;
    result->hard_added += eval.added;
    result->rounds_used = round + 1;
    result->data_pos = data->pos_count;
    result->data_neg = data->neg_count;

    double eval_rate = 0.0;
    if (eval.checked > 0) {
      eval_rate = static_cast<double>(eval.false_pos) /
                  static_cast<double>(eval.checked);
    }
    if (total_rounds > 1) {
      std::cout << "round " << (round + 1) << '\n';
      std::cout << "mine_round " << (round + 1)
                << " hard_added " << eval.added
                << " eval_rate " << eval_rate << '\n';
    }
    std::cout << "train_pos " << result->train_pos
              << " train_neg " << result->train_neg << '\n';
    std::cout << "eval_normal " << eval.checked
              << " eval_false_pos " << eval.false_pos;
    if (eval.checked > 0) {
      std::cout << " rate " << eval_rate;
    }
    std::cout << '\n';
    print_rules(trojan, feature_nodes, result->model, virtual_defs);

    if (result->train_false_pos == 0 && eval.checked > 0 &&
        (eval_rate <= target_rate || target_rate == 0.0)) {
      break;
    }
    if (eval.added == 0) {
      break;
    }
  }

  return true;
}

}  // namespace

bool run_mining(const circuit& golden,
                const circuit& trojan,
                const std::vector<std::vector<int>>& trigger_patterns,
                const std::vector<int>& candidate_gate_indices,
                const MiningOptions& options,
                double target_rate,
                const std::vector<std::vector<int>>* extra_neg_patterns,
                NegSampleTrace* neg_trace,
                MiningResult* result,
                std::string* error,
                const std::vector<VirtualNodeDef>* virtual_defs) {
  if (error) {
    error->clear();
  }
  if (!result) {
    if (error) {
      *error = "Mining result pointer is null";
    }
    return false;
  }
  result->dt_builds = 0;
  result->strict_dt_builds = 0;
  result->training_data_builds = 0;
  if (candidate_gate_indices.empty()) {
    if (error) {
      *error = "No candidate nets available for mining";
    }
    return false;
  }
  if (trigger_patterns.empty()) {
    if (error) {
      *error = "No mismatch patterns collected";
    }
    return false;
  }

  const std::size_t max_trigger_patterns = 50000000;
  std::vector<std::vector<int>> limited_triggers;
  const std::vector<std::vector<int>>* training_triggers = &trigger_patterns;
  if (trigger_patterns.size() > max_trigger_patterns) {
    std::vector<std::size_t> indices(trigger_patterns.size());
    std::iota(indices.begin(), indices.end(), 0U);
    std::mt19937 rng(1337);
    std::shuffle(indices.begin(), indices.end(), rng);
    limited_triggers.reserve(max_trigger_patterns);
    for (std::size_t i = 0; i < max_trigger_patterns; ++i) {
      limited_triggers.push_back(trigger_patterns[indices[i]]);
    }
    training_triggers = &limited_triggers;
  }

  DecisionTreeOptions tree_options;
  tree_options.max_depth = options.max_depth;
  tree_options.force_split = options.force_split;

  auto t_mine = std::chrono::steady_clock::now();
  auto mine_ms = [](auto start) {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();
  };

  std::vector<int> feature_nodes = build_feature_nodes(trojan, candidate_gate_indices, options.include_pi);
  if (feature_nodes.empty()) {
    if (error) {
      *error = "No feature nodes available for training";
    }
    return false;
  }

  TrainingData data;
  if (!build_training_data(golden,
                           trojan,
                           *training_triggers,
                           feature_nodes,
                           extra_neg_patterns,
                           options.neg_ratio,
                           &data,
                           neg_trace,
                           virtual_defs)) {
    if (error) {
      *error = "Failed to build training data";
    }
    return false;
  }
  result->training_data_builds += 1;
  std::cerr << "[TIMING]     build_training_data: " << mine_ms(t_mine) << " ms\n";
  t_mine = std::chrono::steady_clock::now();

  if (!run_mining_loop(golden,
                       trojan,
                       feature_nodes,
                       tree_options,
                       &data,
                       options.mine_rounds,
                       options.mine_max,
                       options.eval_count,
                       target_rate,
                       result,
                       error,
                       virtual_defs)) {
    if (error && error->empty()) {
      *error = "Failed to run mining loop";
    }
    return false;
  }
  std::cerr << "[TIMING]     run_mining_loop: " << mine_ms(t_mine) << " ms\n";

  if (options.strict_retry && result->train_false_pos > 0) {
    std::cout << "strict_mode 1\n";
    DecisionTreeOptions strict_options;
    strict_options.force_split = true;
    std::vector<int> strict_features = build_feature_nodes(trojan, candidate_gate_indices, true);
    strict_options.max_depth = std::max(options.max_depth, strict_features.size());
    TrainingData strict_data;
    const bool strict_data_ok = build_training_data(golden,
                                                    trojan,
                                                    *training_triggers,
                                                    strict_features,
                                                    extra_neg_patterns,
                                                    options.neg_ratio,
                                                    &strict_data,
                                                    neg_trace,
                                                    virtual_defs);
    if (strict_data_ok) {
      result->training_data_builds += 1;
    }
    if (strict_data_ok &&
        run_mining_loop(golden,
                        trojan,
                        strict_features,
                        strict_options,
                        &strict_data,
                        options.mine_rounds,
                        options.mine_max,
                        options.eval_count,
                        target_rate,
                        result,
                        error,
                        virtual_defs,
                        true)) {
      std::cout << "strict_features " << strict_features.size()
                << " strict_depth " << strict_options.max_depth << "\n";
    } else {
      std::cout << "strict_mode failed\n";
    }
  }

  return true;
}
