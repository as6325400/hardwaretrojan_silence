#include "decision_tree.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>

#include <omp.h>

#ifdef USE_CUDA
#include "gpu_tree.cuh"
// Use GPU when there are enough features to amortise launch overhead.
static constexpr std::size_t kGpuSplitThreshold = 64;
#endif

namespace {

using PackedWord = PackedFeatureMatrix::word_t;
constexpr std::size_t kPackedWordBits = PackedFeatureMatrix::kWordBits;

struct Node {
  bool is_leaf = true;
  bool label = false;
  std::size_t feature = 0;
  std::unique_ptr<Node> left;
  std::unique_ptr<Node> right;
};

struct BuildStats {
  std::size_t max_depth_used = 0;
  std::size_t leaf_count = 0;
};

void update_max_depth(BuildStats& stats, std::size_t depth) {
  #pragma omp critical(stats_max_depth)
  {
    if (depth > stats.max_depth_used) {
      stats.max_depth_used = depth;
    }
  }
}

void increment_leaf_count(BuildStats& stats) {
  #pragma omp atomic
  stats.leaf_count += 1;
}

double gini_impurity(std::size_t pos, std::size_t neg) {
  const double total = static_cast<double>(pos + neg);
  if (total <= 0.0) {
    return 0.0;
  }
  const double p = static_cast<double>(pos) / total;
  const double q = static_cast<double>(neg) / total;
  return 1.0 - (p * p + q * q);
}

std::unique_ptr<Node> make_leaf(bool label, std::size_t depth, BuildStats& stats) {
  auto node = std::make_unique<Node>();
  node->is_leaf = true;
  node->label = label;
  update_max_depth(stats, depth);
  increment_leaf_count(stats);
  return node;
}

std::unique_ptr<Node> build_node(const PackedFeatureMatrix& features,
                                 const std::vector<int>& labels,
                                 const std::vector<std::size_t>& samples,
                                 const std::vector<std::size_t>& feature_indices,
                                 std::size_t depth,
                                 const DecisionTreeOptions& options,
                                 BuildStats& stats) {
  if (samples.empty()) {
    return make_leaf(false, depth, stats);
  }

  std::size_t pos = 0;
  std::size_t neg = 0;
  #pragma omp parallel for reduction(+:pos,neg) schedule(static)
  for (std::size_t i = 0; i < samples.size(); ++i) {
    const std::size_t idx = samples[i];
    if (labels[idx] == 1) {
      pos += 1;
    } else {
      neg += 1;
    }
  }

  if (pos == 0) {
    return make_leaf(false, depth, stats);
  }
  if (neg == 0) {
    return make_leaf(true, depth, stats);
  }
  if (depth >= options.max_depth || feature_indices.empty()) {
    return make_leaf(true, depth, stats);
  }

  const double parent_impurity = gini_impurity(pos, neg);

  double global_best_gain = -std::numeric_limits<double>::infinity();
  std::size_t global_best_feature = 0;
  bool global_found = false;

  // Build packed sample/label masks for popcount-based split counting.
  const std::size_t total_rows = features.row_count;
  const std::size_t packed_words =
      (total_rows + kPackedWordBits - 1) / kPackedWordBits;
  std::vector<PackedWord> sample_mask(packed_words, 0);
  std::vector<PackedWord> sample_pos_mask(packed_words, 0);
  for (std::size_t idx : samples) {
    const std::size_t w = idx / kPackedWordBits;
    const PackedWord bit = PackedWord(1) << (idx % kPackedWordBits);
    sample_mask[w] |= bit;
    if (labels[idx] == 1) {
      sample_pos_mask[w] |= bit;
    }
  }

  // Column data is already in column-major format in features.data.
  // features.col_ptr(f) points to packed_rows() words for feature f.
  // packed_rows() may be >= packed_words (if capacity > row_count),
  // so we use the stride from features but only scan packed_words words.
  const std::size_t n_features = feature_indices.size();
  const std::size_t col_stride = features.packed_rows();

  // Build a contiguous col_data array with stride = packed_words for
  // the GPU path and CPU split finding. Only needed when col_stride
  // differs from packed_words (capacity > row_count).
  const PackedWord* col_base = features.data.data();
  std::vector<PackedWord> col_data_compact;
  if (col_stride != packed_words) {
    col_data_compact.resize(n_features * packed_words);
    #pragma omp parallel for schedule(static)
    for (std::size_t fi = 0; fi < n_features; ++fi) {
      const PackedWord* src = col_base + feature_indices[fi] * col_stride;
      PackedWord* dst = col_data_compact.data() + fi * packed_words;
      for (std::size_t w = 0; w < packed_words; ++w) {
        dst[w] = src[w];
      }
    }
    col_base = nullptr;  // signal to use compact
  }

  // Helper: pointer to the column for feature index fi.
  auto col_for_fi = [&](std::size_t fi) -> const PackedWord* {
    if (!col_data_compact.empty()) {
      return col_data_compact.data() + fi * packed_words;
    }
    return features.data.data() + feature_indices[fi] * col_stride;
  };

#ifdef USE_CUDA
  if (n_features >= kGpuSplitThreshold) {
    // GPU path needs contiguous col_data with stride=packed_words.
    const PackedWord* gpu_col_data;
    if (!col_data_compact.empty()) {
      gpu_col_data = col_data_compact.data();
    } else {
      // col_stride == packed_words, but features may not be contiguous
      // by feature_indices order. Build compact for GPU.
      col_data_compact.resize(n_features * packed_words);
      #pragma omp parallel for schedule(static)
      for (std::size_t fi = 0; fi < n_features; ++fi) {
        const PackedWord* src = features.data.data() +
                                feature_indices[fi] * col_stride;
        PackedWord* dst = col_data_compact.data() + fi * packed_words;
        for (std::size_t w = 0; w < packed_words; ++w) {
          dst[w] = src[w];
        }
      }
      gpu_col_data = col_data_compact.data();
    }
    const GpuSplitResult gr = gpu_find_best_split(
        gpu_col_data, sample_mask.data(), sample_pos_mask.data(),
        packed_words, n_features,
        samples.size(), pos, neg, parent_impurity);
    if (gr.found) {
      global_best_gain    = gr.best_gain;
      global_best_feature = feature_indices[gr.best_fi];
      global_found        = true;
    }
  } else {
#endif

  #pragma omp parallel
  {
    double local_best_gain = -std::numeric_limits<double>::infinity();
    std::size_t local_best_feature = 0;
    bool local_found = false;

    #pragma omp for schedule(static)
    for (std::size_t fi = 0; fi < n_features; ++fi) {
      const std::size_t f = feature_indices[fi];
      const PackedWord* col = col_for_fi(fi);

      // Count using popcount: pos1 = popcount(col & sample_mask & sample_pos_mask)
      std::size_t total1 = 0;
      std::size_t pos1 = 0;
      for (std::size_t w = 0; w < packed_words; ++w) {
        const PackedWord feat_in_sample = col[w] & sample_mask[w];
        total1 += static_cast<std::size_t>(__builtin_popcountll(feat_in_sample));
        pos1 += static_cast<std::size_t>(
            __builtin_popcountll(feat_in_sample & sample_pos_mask[w]));
      }

      const std::size_t neg1 = total1 - pos1;
      const std::size_t pos0 = pos - pos1;
      const std::size_t neg0 = neg - neg1;
      const std::size_t total0 = pos0 + neg0;

      if (total0 == 0 || total1 == 0) {
        continue;
      }

      const double weighted_impurity =
          (static_cast<double>(total0) / static_cast<double>(samples.size())) *
              gini_impurity(pos0, neg0) +
          (static_cast<double>(total1) /
           static_cast<double>(samples.size())) *
              gini_impurity(pos1, neg1);
      const double gain = parent_impurity - weighted_impurity;

      if (!local_found || gain > local_best_gain) {
        local_best_gain = gain;
        local_best_feature = f;
        local_found = true;
      }
    }

    #pragma omp critical(best_feature_update)
    {
      if (local_found && (!global_found || local_best_gain > global_best_gain)) {
        global_best_gain = local_best_gain;
        global_best_feature = local_best_feature;
        global_found = true;
      }
    }
  }

#ifdef USE_CUDA
  }  // end if (n_features < kGpuSplitThreshold)
#endif

  if (!global_found || (!options.force_split && global_best_gain <= 0.0)) {
    return make_leaf(true, depth, stats);
  }

  // Split samples by best_feature value using column-major lookup.
  const int max_threads = omp_get_max_threads();
  const std::size_t thread_count = static_cast<std::size_t>(max_threads);
  const std::size_t sample_chunk =
      thread_count == 0 ? 0 : (samples.size() + thread_count - 1) / thread_count;
  std::vector<std::vector<std::size_t>> left_bins(thread_count);
  std::vector<std::vector<std::size_t>> right_bins(thread_count);

  #pragma omp parallel
  {
    const std::size_t tid = static_cast<std::size_t>(omp_get_thread_num());
    auto& left_local = left_bins[tid];
    auto& right_local = right_bins[tid];
    left_local.reserve(sample_chunk);
    right_local.reserve(sample_chunk);

    #pragma omp for schedule(static)
    for (std::size_t i = 0; i < samples.size(); ++i) {
      const std::size_t idx = samples[i];
      const int value = features.feature_value(idx, global_best_feature);
      if (value == 1) {
        right_local.push_back(idx);
      } else {
        left_local.push_back(idx);
      }
    }
  }

  std::vector<std::size_t> left_samples;
  std::vector<std::size_t> right_samples;
  left_samples.reserve(samples.size());
  right_samples.reserve(samples.size());
  for (int t = 0; t < max_threads; ++t) {
    const std::size_t tid = static_cast<std::size_t>(t);
    left_samples.insert(left_samples.end(), left_bins[tid].begin(), left_bins[tid].end());
    right_samples.insert(right_samples.end(), right_bins[tid].begin(), right_bins[tid].end());
  }

  const std::size_t feature_chunk =
      thread_count == 0 ? 0
                        : (feature_indices.size() + thread_count - 1) / thread_count;
  std::vector<std::vector<std::size_t>> feature_bins(thread_count);

  #pragma omp parallel
  {
    const std::size_t tid = static_cast<std::size_t>(omp_get_thread_num());
    auto& local = feature_bins[tid];
    local.reserve(feature_chunk);

    #pragma omp for schedule(static)
    for (std::size_t i = 0; i < feature_indices.size(); ++i) {
      const std::size_t f = feature_indices[i];
      if (f != global_best_feature) {
        local.push_back(f);
      }
    }
  }

  std::vector<std::size_t> next_features;
  next_features.reserve(feature_indices.size() - 1);
  for (int t = 0; t < max_threads; ++t) {
    const std::size_t tid = static_cast<std::size_t>(t);
    next_features.insert(next_features.end(), feature_bins[tid].begin(), feature_bins[tid].end());
  }

  auto node = std::make_unique<Node>();
  node->is_leaf = false;
  node->feature = global_best_feature;

  node->left = build_node(features, labels, left_samples, next_features, depth + 1, options, stats);
  node->right = build_node(features, labels, right_samples, next_features, depth + 1, options, stats);
  update_max_depth(stats, depth);
  return node;
}

void collect_rules(const Node& node,
                   std::vector<std::pair<std::size_t, int>>& path,
                   std::vector<DecisionTreeRule>& rules) {
  if (node.is_leaf) {
    if (node.label) {
      rules.push_back(DecisionTreeRule{path});
    }
    return;
  }

  if (node.left) {
    path.push_back({node.feature, 0});
    collect_rules(*node.left, path, rules);
    path.pop_back();
  }
  if (node.right) {
    path.push_back({node.feature, 1});
    collect_rules(*node.right, path, rules);
    path.pop_back();
  }
}

}  // namespace

DecisionTreeModel build_decision_tree(const PackedFeatureMatrix& features,
                                      const std::vector<int>& labels,
                                      const DecisionTreeOptions& options,
                                      std::string* error) {
  DecisionTreeModel model;
  if (error) {
    error->clear();
  }
  if (features.row_count == 0 || labels.empty()) {
    if (error) {
      *error = "empty training data";
    }
    return model;
  }
  if (features.row_count != labels.size()) {
    if (error) {
      *error = "feature/label size mismatch";
    }
    return model;
  }

  const std::size_t feature_count = features.feature_count;
  if (feature_count == 0) {
    if (error) {
      *error = "empty feature set";
    }
    return model;
  }
  // Validate column-major data size.
  const std::size_t expected_size = feature_count * features.packed_rows();
  if (features.data.size() != expected_size) {
    if (error) {
      *error = "packed feature size mismatch";
    }
    return model;
  }

  std::vector<std::size_t> samples(features.row_count);
  for (std::size_t i = 0; i < samples.size(); ++i) {
    samples[i] = i;
  }

  std::vector<std::size_t> feature_indices(feature_count);
  for (std::size_t i = 0; i < feature_count; ++i) {
    feature_indices[i] = i;
  }

  BuildStats stats;
  auto root = build_node(features, labels, samples, feature_indices, 0, options, stats);
  model.max_depth_used = stats.max_depth_used;
  model.leaf_count = stats.leaf_count;

  std::vector<std::pair<std::size_t, int>> path;
  collect_rules(*root, path, model.rules);

  if (model.rules.empty()) {
    if (error) {
      *error = "no positive rules found";
    }
  }
  return model;
}

bool eval_rules(const std::vector<DecisionTreeRule>& rules,
                const std::vector<int>& features) {
  for (const auto& rule : rules) {
    bool match = true;
    for (const auto& term : rule.terms) {
      const std::size_t idx = term.first;
      const int expected = term.second;
      if (idx >= features.size()) {
        match = false;
        break;
      }
      const int value = features[idx] ? 1 : 0;
      if (value != expected) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}

bool eval_rules_packed(const std::vector<DecisionTreeRule>& rules,
                       const PackedFeatureMatrix::word_t* features,
                       std::size_t feature_count) {
  if (!features) {
    return false;
  }
  for (const auto& rule : rules) {
    bool match = true;
    for (const auto& term : rule.terms) {
      const std::size_t idx = term.first;
      const int expected = term.second;
      if (idx >= feature_count) {
        match = false;
        break;
      }
      const std::size_t word_idx = idx / kPackedWordBits;
      const std::size_t bit_idx = idx % kPackedWordBits;
      const int value =
          static_cast<int>((features[word_idx] >> bit_idx) & PackedWord(1));
      if (value != expected) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}
