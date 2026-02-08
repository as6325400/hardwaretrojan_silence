#include "miner.hpp"

#include <algorithm>
#include <iostream>
#include <numeric>
#include <random>

#include "../core/packed_circuit.hpp"
#include "rule_patch.hpp"

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

struct PackedRule {
  std::vector<FeatureWord> must_one;
  std::vector<FeatureWord> must_zero;
};

struct FeatureIndexMap {
  std::vector<std::size_t> word_indices;
  std::vector<FeatureWord> word_masks;
};

FeatureIndexMap build_feature_index_map(std::size_t feature_count) {
  FeatureIndexMap map;
  map.word_indices.resize(feature_count);
  map.word_masks.resize(feature_count);
  for (std::size_t f = 0; f < feature_count; ++f) {
    map.word_indices[f] = f / PackedFeatureMatrix::kWordBits;
    map.word_masks[f] = FeatureWord(1) << (f % PackedFeatureMatrix::kWordBits);
  }
  return map;
}

std::size_t count_rule_literals(const std::vector<DecisionTreeRule>& rules) {
  std::size_t total = 0;
  for (const auto& rule : rules) {
    total += rule.terms.size();
  }
  return total;
}

PackedRule build_packed_rule(const DecisionTreeRule& rule,
                             std::size_t words_per_row) {
  PackedRule packed;
  packed.must_one.assign(words_per_row, 0);
  packed.must_zero.assign(words_per_row, 0);
  for (const auto& term : rule.terms) {
    const std::size_t feature = term.first;
    const int value = term.second;
    const std::size_t word = feature / PackedFeatureMatrix::kWordBits;
    const std::size_t bit = feature % PackedFeatureMatrix::kWordBits;
    if (word >= words_per_row) {
      continue;
    }
    const FeatureWord mask = FeatureWord(1) << bit;
    if (value == 0) {
      packed.must_zero[word] |= mask;
    } else {
      packed.must_one[word] |= mask;
    }
  }
  return packed;
}

bool packed_rule_matches_row(const PackedRule& rule,
                             const FeatureWord* row,
                             std::size_t words_per_row) {
  for (std::size_t w = 0; w < words_per_row; ++w) {
    if ((row[w] & rule.must_one[w]) != rule.must_one[w]) {
      return false;
    }
    if (((~row[w]) & rule.must_zero[w]) != rule.must_zero[w]) {
      return false;
    }
  }
  return true;
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
  const std::size_t words_per_row = features.words_per_row();
  const PackedRule packed = build_packed_rule(rule, words_per_row);
  bool positive_seen = false;
  for (std::size_t i = 0; i < features.row_count; ++i) {
    const FeatureWord* row = features.row_ptr(i);
    if (!packed_rule_matches_row(packed, row, words_per_row)) {
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

void fill_feature_row_from_bits(const std::vector<PackedWord>& feature_bits,
                                const FeatureIndexMap& feature_map,
                                std::size_t pattern_idx,
                                FeatureWord* row_ptr) {
  if (!row_ptr) {
    return;
  }
  const PackedWord mask = PackedWord(1) << pattern_idx;
  for (std::size_t f = 0; f < feature_bits.size(); ++f) {
    if (feature_bits[f] & mask) {
      row_ptr[feature_map.word_indices[f]] |= feature_map.word_masks[f];
    }
  }
}

void append_feature_rows_from_bits_range(const std::vector<PackedWord>& feature_bits,
                                         const FeatureIndexMap& feature_map,
                                         std::size_t pattern_count,
                                         std::size_t words_per_row,
                                         PackedFeatureMatrix* matrix,
                                         std::vector<int>* labels,
                                         int label) {
  if (!matrix || !labels || pattern_count == 0) {
    return;
  }
  std::vector<FeatureWord> rows(pattern_count * words_per_row, 0);
  #pragma omp parallel for schedule(static)
  for (std::size_t p = 0; p < pattern_count; ++p) {
    FeatureWord* row_ptr = rows.data() + p * words_per_row;
    fill_feature_row_from_bits(feature_bits, feature_map, p, row_ptr);
  }
  matrix->data.insert(matrix->data.end(), rows.begin(), rows.end());
  matrix->row_count += pattern_count;
  labels->insert(labels->end(), pattern_count, label);
}

void append_feature_rows_from_bits_indices(const std::vector<PackedWord>& feature_bits,
                                           const FeatureIndexMap& feature_map,
                                           const std::vector<std::size_t>& pattern_indices,
                                           std::size_t words_per_row,
                                           PackedFeatureMatrix* matrix,
                                           std::vector<int>* labels,
                                           int label) {
  if (!matrix || !labels || pattern_indices.empty()) {
    return;
  }
  std::vector<FeatureWord> rows(pattern_indices.size() * words_per_row, 0);
  #pragma omp parallel for schedule(static)
  for (std::size_t i = 0; i < pattern_indices.size(); ++i) {
    FeatureWord* row_ptr = rows.data() + i * words_per_row;
    fill_feature_row_from_bits(feature_bits, feature_map, pattern_indices[i], row_ptr);
  }
  matrix->data.insert(matrix->data.end(), rows.begin(), rows.end());
  matrix->row_count += pattern_indices.size();
  labels->insert(labels->end(), pattern_indices.size(), label);
}

void pack_feature_row(circuit& c,
                      const std::vector<int>& feature_nodes,
                      std::size_t words_per_row,
                      std::vector<FeatureWord>* row) {
  if (!row) {
    return;
  }
  row->assign(words_per_row, 0);
  for (std::size_t i = 0; i < feature_nodes.size(); ++i) {
    if (c.get_cell(feature_nodes[i]).val) {
      const std::size_t word_idx = i / PackedFeatureMatrix::kWordBits;
      const std::size_t bit_idx = i % PackedFeatureMatrix::kWordBits;
      (*row)[word_idx] |= (FeatureWord(1) << bit_idx);
    }
  }
}

bool append_feature_row(const std::vector<FeatureWord>& row,
                        PackedFeatureMatrix* matrix) {
  if (!matrix) {
    return false;
  }
  const std::size_t words_per_row = matrix->words_per_row();
  if (row.size() != words_per_row) {
    return false;
  }
  matrix->data.insert(matrix->data.end(), row.begin(), row.end());
  matrix->row_count += 1;
  return true;
}

bool build_training_data(const circuit& golden,
                         const circuit& trojan,
                         const std::vector<std::vector<int>>& trigger_patterns,
                         const std::vector<int>& feature_nodes,
                         const std::vector<std::vector<int>>* extra_neg_patterns,
                         std::size_t neg_ratio,
                         TrainingData* data) {
  data->features.data.clear();
  data->features.row_count = 0;
  data->features.feature_count = feature_nodes.size();
  data->labels.clear();
  data->pos_count = 0;
  data->neg_count = 0;

  circuit golden_train = golden;
  circuit trojan_train = trojan;
  packed_circuit trojan_packed(trojan_train);

  const std::size_t words_per_row = data->features.words_per_row();
  std::vector<FeatureWord> row_bits;
  row_bits.reserve(words_per_row);
  const std::size_t estimated_pos = trigger_patterns.size();
  const std::size_t estimated_extra_neg =
      extra_neg_patterns ? extra_neg_patterns->size() : 0;
  const std::size_t estimated_target_neg =
      estimated_pos * std::max<std::size_t>(1, neg_ratio);
  data->features.data.reserve(
      (estimated_pos + estimated_extra_neg + estimated_target_neg) *
      words_per_row);
  data->labels.reserve(estimated_pos + estimated_extra_neg + estimated_target_neg);
  const FeatureIndexMap feature_map =
      build_feature_index_map(feature_nodes.size());

  std::size_t trigger_offset = 0;
  while (trigger_offset < trigger_patterns.size()) {
    const std::size_t remaining = trigger_patterns.size() - trigger_offset;
    const std::size_t block_size =
        std::min(packed_circuit::kWordBits, remaining);
    std::vector<std::vector<int>> patterns;
    patterns.reserve(block_size);
    for (std::size_t p = 0; p < block_size; ++p) {
      patterns.push_back(trigger_patterns[trigger_offset + p]);
    }

    bool packed_ok = false;
    try {
      trojan_packed.simulate(patterns);
      packed_ok = true;
    } catch (const std::exception& e) {
      std::cerr << "Training trigger simulation error: " << e.what() << "\n";
    }

    if (packed_ok) {
      const std::vector<PackedWord> feature_bits =
          gather_feature_bits(trojan_packed, feature_nodes);
      append_feature_rows_from_bits_range(feature_bits,
                                          feature_map,
                                          block_size,
                                          words_per_row,
                                          &data->features,
                                          &data->labels,
                                          1);
      data->pos_count += block_size;
    } else {
      for (const auto& pattern : patterns) {
        try {
          trojan_train.simulate(pattern);
        } catch (const std::exception& e) {
          std::cerr << "Training trigger simulation error: " << e.what() << "\n";
          continue;
        }
        pack_feature_row(trojan_train, feature_nodes, words_per_row, &row_bits);
        append_feature_row(row_bits, &data->features);
        data->labels.push_back(1);
        data->pos_count += 1;
      }
    }

    trigger_offset += block_size;
  }

  if (data->pos_count == 0) {
    return false;
  }

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
      } catch (const std::exception& e) {
        std::cerr << "Training negative simulation error: " << e.what() << "\n";
      }

      if (packed_ok) {
        const std::vector<PackedWord> feature_bits =
            gather_feature_bits(trojan_packed, feature_nodes);
        append_feature_rows_from_bits_range(feature_bits,
                                            feature_map,
                                            block_size,
                                            words_per_row,
                                            &data->features,
                                            &data->labels,
                                            0);
        data->neg_count += block_size;
      } else {
        for (const auto& pattern : patterns) {
          try {
            trojan_train.simulate(pattern);
          } catch (const std::exception&) {
            continue;
          }
          pack_feature_row(trojan_train, feature_nodes, words_per_row, &row_bits);
          append_feature_row(row_bits, &data->features);
          data->labels.push_back(0);
          data->neg_count += 1;
        }
      }

      extra_offset += block_size;
    }
  }

  const std::size_t target_negatives = data->pos_count * std::max<std::size_t>(1, neg_ratio);

  std::size_t attempts = 0;
  const std::size_t max_attempts = target_negatives * 20 + 1000;
  std::mt19937 rng(1337);
  std::uniform_int_distribution<int> dist(0, 1);
  packed_circuit golden_packed(golden_train);

  while (data->neg_count < target_negatives && attempts < max_attempts) {
    const std::size_t remaining_attempts = max_attempts - attempts;
    const std::size_t block_size =
        std::min(packed_circuit::kWordBits, remaining_attempts);
    if (block_size == 0) {
      break;
    }
    std::vector<std::vector<int>> patterns;
    patterns.reserve(block_size);
    for (std::size_t p = 0; p < block_size; ++p) {
      std::vector<int> pi_values;
      pi_values.reserve(golden_train.pi_count());
      for (std::size_t i = 0; i < golden_train.pi_count(); ++i) {
        pi_values.push_back(dist(rng));
      }
      patterns.push_back(std::move(pi_values));
    }

    try {
      golden_packed.simulate(patterns);
      trojan_packed.simulate(patterns);
    } catch (const std::exception&) {
      attempts += block_size;
      continue;
    }

    const PackedWord mask = packed_circuit::mask_for_count(block_size);
    PackedWord diff_mask = 0;
    for (std::size_t o = 0; o < golden_train.po_count(); ++o) {
      diff_mask |= (golden_packed.po_bits(o) ^ trojan_packed.po_bits(o));
    }
    diff_mask &= mask;
    PackedWord notrigger_mask = mask & ~diff_mask;
    if (notrigger_mask != 0) {
      const std::size_t remaining_needed = target_negatives - data->neg_count;
      std::vector<std::size_t> selected;
      selected.reserve(std::min(remaining_needed, popcount_word(notrigger_mask)));
      while (notrigger_mask && selected.size() < remaining_needed) {
        const std::size_t bit = ctz_word(notrigger_mask);
        selected.push_back(bit);
        notrigger_mask &= (notrigger_mask - 1);
      }
      if (!selected.empty()) {
        const std::vector<PackedWord> feature_bits =
            gather_feature_bits(trojan_packed, feature_nodes);
        append_feature_rows_from_bits_indices(feature_bits,
                                              feature_map,
                                              selected,
                                              words_per_row,
                                              &data->features,
                                              &data->labels,
                                              0);
        data->neg_count += selected.size();
      }
    }
    attempts += block_size;
  }

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
    const bool pred = eval_rules_packed(model->rules,
                                        data.features.row_ptr(i),
                                        data.features.feature_count);
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
                         std::uint32_t seed) {
  EvalResult result;
  std::size_t attempts = 0;
  const std::size_t max_attempts = eval_limit * 20 + 1000;
  std::mt19937 rng(seed);
  std::uniform_int_distribution<int> dist(0, 1);
  circuit golden_eval = golden;
  circuit trojan_eval = trojan;
  packed_circuit golden_packed(golden_eval);
  packed_circuit trojan_packed(trojan_eval);
  const FeatureIndexMap feature_map =
      build_feature_index_map(feature_nodes.size());
  const std::size_t words_per_row =
      (feature_nodes.size() + PackedFeatureMatrix::kWordBits - 1) /
      PackedFeatureMatrix::kWordBits;
  std::vector<FeatureWord> row_bits(words_per_row, 0);

  while (result.checked < eval_limit && attempts < max_attempts) {
    const std::size_t remaining_attempts = max_attempts - attempts;
    const std::size_t block_size =
        std::min(packed_circuit::kWordBits, remaining_attempts);
    if (block_size == 0) {
      break;
    }
    std::vector<std::vector<int>> patterns;
    patterns.reserve(block_size);
    for (std::size_t p = 0; p < block_size; ++p) {
      std::vector<int> pi_values;
      pi_values.reserve(golden_eval.pi_count());
      for (std::size_t i = 0; i < golden_eval.pi_count(); ++i) {
        pi_values.push_back(dist(rng));
      }
      patterns.push_back(std::move(pi_values));
    }

    try {
      golden_packed.simulate(patterns);
      trojan_packed.simulate(patterns);
    } catch (const std::exception&) {
      attempts += block_size;
      continue;
    }

    const PackedWord mask = packed_circuit::mask_for_count(block_size);
    PackedWord diff_mask = 0;
    for (std::size_t o = 0; o < golden_eval.po_count(); ++o) {
      diff_mask |= (golden_packed.po_bits(o) ^ trojan_packed.po_bits(o));
    }
    diff_mask &= mask;
    PackedWord notrigger_mask = mask & ~diff_mask;
    if (notrigger_mask != 0) {
      const std::vector<PackedWord> feature_bits =
          gather_feature_bits(trojan_packed, feature_nodes);
      while (notrigger_mask && result.checked < eval_limit) {
        const std::size_t bit = ctz_word(notrigger_mask);
        std::fill(row_bits.begin(), row_bits.end(), 0);
        fill_feature_row_from_bits(feature_bits, feature_map, bit, row_bits.data());
        if (eval_rules_packed(model.rules, row_bits.data(), feature_nodes.size())) {
          result.false_pos += 1;
          if (data && result.added < max_add) {
            append_feature_row(row_bits, &data->features);
            data->labels.push_back(0);
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
  return result;
}

void print_rules(const circuit& trojan,
                 const std::vector<int>& feature_nodes,
                 const DecisionTreeModel& model) {
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
                     std::string* error) {
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
                                    static_cast<std::uint32_t>(2027 + round));
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
    print_rules(trojan, feature_nodes, result->model);

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
                MiningResult* result,
                std::string* error) {
  if (error) {
    error->clear();
  }
  if (!result) {
    if (error) {
      *error = "Mining result pointer is null";
    }
    return false;
  }
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
                           &data)) {
    if (error) {
      *error = "Failed to build training data";
    }
    return false;
  }

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
                       error)) {
    if (error && error->empty()) {
      *error = "Failed to run mining loop";
    }
    return false;
  }

  if (options.strict_retry && result->train_false_pos > 0) {
    std::cout << "strict_mode 1\n";
    DecisionTreeOptions strict_options;
    strict_options.force_split = true;
    std::vector<int> strict_features = build_feature_nodes(trojan, candidate_gate_indices, true);
    strict_options.max_depth = std::max(options.max_depth, strict_features.size());
    TrainingData strict_data;
    if (build_training_data(golden,
                            trojan,
                            *training_triggers,
                            strict_features,
                            extra_neg_patterns,
                            options.neg_ratio,
                            &strict_data) &&
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
                        error)) {
      std::cout << "strict_features " << strict_features.size()
                << " strict_depth " << strict_options.max_depth << "\n";
    } else {
      std::cout << "strict_mode failed\n";
    }
  }

  return true;
}
