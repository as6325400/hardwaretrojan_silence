#include "set_cover_optimizer.hpp"

#ifdef USE_HIGHS
#include <Highs.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using Word = PackedFeatureMatrix::word_t;
using TermKey = std::vector<std::pair<std::size_t, int>>;

std::atomic<bool> force_phase3_timeout_after_verified_mip2{false};

double elapsed_ms(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start)
      .count();
}

std::size_t count_literals(const DecisionTreeModel& model) {
  std::size_t result = 0;
  for (const auto& rule : model.rules) result += rule.terms.size();
  return result;
}

std::size_t count_unique_inverters(const DecisionTreeModel& model) {
  std::set<std::size_t> features;
  for (const auto& rule : model.rules) {
    for (const auto& literal : rule.terms) {
      if (literal.second == 0) features.insert(literal.first);
    }
  }
  return features.size();
}

void finish_stats(RuleOptimizationResult* result,
                  Clock::time_point total_start) {
  if (result) result->stats.total_ms = elapsed_ms(total_start);
}

#ifdef USE_HIGHS

bool validate_input(const PackedFeatureMatrix& features,
                    const std::vector<int>& labels,
                    const std::vector<std::size_t>& candidates,
                    const DecisionTreeModel& baseline,
                    std::string* reason) {
  if (features.row_count == 0) {
    *reason = "empty feature matrix";
    return false;
  }
  if (features.row_count != labels.size()) {
    *reason = "feature row count does not match labels";
    return false;
  }
  if (features.feature_count == 0) {
    *reason = "empty feature set";
    return false;
  }
  if (features.capacity_rows != 0 &&
      features.capacity_rows < features.row_count) {
    *reason = "packed feature capacity is smaller than row count";
    return false;
  }
  const std::size_t storage_rows = features.capacity_rows != 0
                                       ? features.capacity_rows
                                       : features.row_count;
  if (storage_rows > std::numeric_limits<std::size_t>::max() -
                         (PackedFeatureMatrix::kWordBits - 1U)) {
    *reason = "packed feature row capacity overflows word rounding";
    return false;
  }
  const std::size_t packed_words =
      storage_rows / PackedFeatureMatrix::kWordBits +
      (storage_rows % PackedFeatureMatrix::kWordBits != 0 ? 1U : 0U);
  if (packed_words == 0 ||
      features.feature_count >
          std::numeric_limits<std::size_t>::max() / packed_words) {
    *reason = "packed feature dimensions overflow storage size";
    return false;
  }
  if (features.data.size() != features.feature_count * packed_words) {
    *reason = "packed feature matrix has an invalid data size";
    return false;
  }
  if (candidates.empty()) {
    *reason = "raw decision-tree candidate union is empty";
    return false;
  }
  for (std::size_t feature : candidates) {
    if (feature >= features.feature_count) {
      *reason = "candidate feature index is out of range";
      return false;
    }
  }
  for (int label : labels) {
    if (label != 0 && label != 1) {
      *reason = "labels must be binary";
      return false;
    }
  }
  if (baseline.rules.empty()) {
    *reason = "baseline model has no positive clauses";
    return false;
  }
  for (const auto& rule : baseline.rules) {
    for (const auto& term : rule.terms) {
      if (term.first >= features.feature_count ||
          (term.second != 0 && term.second != 1)) {
        *reason = "baseline rule contains an invalid term";
        return false;
      }
    }
  }
  return true;
}

std::vector<Word> active_feature_signature(
    const PackedFeatureMatrix& features, std::size_t feature) {
  const std::size_t words =
      features.row_count / PackedFeatureMatrix::kWordBits +
      (features.row_count % PackedFeatureMatrix::kWordBits != 0 ? 1U : 0U);
  std::vector<Word> signature(words, Word{0});
  const Word* column = features.col_ptr(feature);
  for (std::size_t word = 0; word < words; ++word) {
    signature[word] = column[word];
  }
  const std::size_t tail =
      features.row_count % PackedFeatureMatrix::kWordBits;
  if (tail != 0 && !signature.empty()) {
    signature.back() &= (Word{1} << tail) - Word{1};
  }
  return signature;
}

std::vector<std::size_t> deduplicate_candidate_features(
    const PackedFeatureMatrix& features,
    const std::vector<std::size_t>& raw_candidates) {
  std::vector<std::size_t> sorted = raw_candidates;
  std::sort(sorted.begin(), sorted.end());
  sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

  // Iterating sorted feature indices and using emplace selects the smallest
  // deterministic representative for each finite-table truth signature.
  std::map<std::vector<Word>, std::size_t> by_signature;
  for (std::size_t feature : sorted) {
    by_signature.emplace(active_feature_signature(features, feature), feature);
  }

  std::vector<std::size_t> unique;
  unique.reserve(by_signature.size());
  for (const auto& entry : by_signature) unique.push_back(entry.second);
  std::sort(unique.begin(), unique.end());
  return unique;
}

struct PatternSignature {
  std::vector<Word> bits;
  int label = 0;
  std::size_t representative_row = 0;
  std::size_t multiplicity = 0;
};

struct SignatureBuildResult {
  std::vector<PatternSignature> patterns;
  std::size_t total_unique = 0;
  std::size_t conflicts = 0;
};

struct WordVectorHash {
  std::size_t operator()(const std::vector<Word>& words) const noexcept {
    std::size_t hash = static_cast<std::size_t>(1469598103934665603ULL);
    for (Word word : words) {
      hash ^= static_cast<std::size_t>(word);
      hash *= static_cast<std::size_t>(1099511628211ULL);
      if (sizeof(std::size_t) < sizeof(Word)) {
        hash ^= static_cast<std::size_t>(word >> 32U);
        hash *= static_cast<std::size_t>(1099511628211ULL);
      }
    }
    return hash;
  }
};

std::vector<Word> project_row(const PackedFeatureMatrix& features,
                              const std::vector<std::size_t>& candidates,
                              std::size_t row) {
  const std::size_t words =
      candidates.size() / PackedFeatureMatrix::kWordBits +
      (candidates.size() % PackedFeatureMatrix::kWordBits != 0 ? 1U : 0U);
  std::vector<Word> bits(words, Word{0});
  for (std::size_t position = 0; position < candidates.size(); ++position) {
    if (features.feature_value(row, candidates[position]) != 0) {
      bits[position / PackedFeatureMatrix::kWordBits] |=
          Word{1} << (position % PackedFeatureMatrix::kWordBits);
    }
  }
  return bits;
}

SignatureBuildResult build_pattern_signatures(
    const PackedFeatureMatrix& features,
    const std::vector<int>& labels,
    const std::vector<std::size_t>& candidates) {
  struct Aggregate {
    int label = 0;
    std::size_t representative_row = 0;
    std::size_t multiplicity = 0;
    bool conflict = false;
  };

  std::unordered_map<std::vector<Word>, Aggregate, WordVectorHash> table;
  table.reserve(std::min<std::size_t>(features.row_count, 1U << 20U));
  for (std::size_t row = 0; row < features.row_count; ++row) {
    std::vector<Word> signature = project_row(features, candidates, row);
    auto inserted = table.emplace(
        signature, Aggregate{labels[row], row, 1, false});
    if (!inserted.second) {
      Aggregate& aggregate = inserted.first->second;
      aggregate.multiplicity += 1;
      if (aggregate.label != labels[row]) aggregate.conflict = true;
    }
  }

  SignatureBuildResult result;
  result.total_unique = table.size();
  result.patterns.reserve(table.size());
  for (auto& entry : table) {
    const Aggregate& aggregate = entry.second;
    if (aggregate.conflict) {
      result.conflicts += 1;
      continue;
    }
    result.patterns.push_back(PatternSignature{
        std::move(entry.first), aggregate.label,
        aggregate.representative_row, aggregate.multiplicity});
  }
  std::sort(result.patterns.begin(), result.patterns.end(),
            [](const PatternSignature& lhs, const PatternSignature& rhs) {
              return lhs.bits < rhs.bits;
            });
  return result;
}

int signature_value(const PatternSignature& signature,
                    std::size_t position) {
  return static_cast<int>(
      (signature.bits[position / PackedFeatureMatrix::kWordBits] >>
       (position % PackedFeatureMatrix::kWordBits)) &
      Word{1});
}

bool rule_matches_signature(
    const DecisionTreeRule& rule,
    const PatternSignature& signature,
    const std::map<std::size_t, std::size_t>& candidate_position) {
  for (const auto& literal : rule.terms) {
    const auto it = candidate_position.find(literal.first);
    if (it == candidate_position.end() ||
        signature_value(signature, it->second) != literal.second) {
      return false;
    }
  }
  return true;
}

bool model_matches_signature(
    const DecisionTreeModel& model,
    const PatternSignature& signature,
    const std::map<std::size_t, std::size_t>& candidate_position) {
  for (const auto& rule : model.rules) {
    if (rule_matches_signature(rule, signature, candidate_position)) {
      return true;
    }
  }
  return false;
}

bool model_matches_row(const DecisionTreeModel& model,
                       const PackedFeatureMatrix& features,
                       std::size_t row) {
  for (const auto& rule : model.rules) {
    bool matches = true;
    for (const auto& literal : rule.terms) {
      if (literal.first >= features.feature_count ||
          features.feature_value(row, literal.first) != literal.second) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

enum class VerificationStatus {
  verified,
  timeout,
  failed
};

VerificationStatus verify_candidate_model(
    const DecisionTreeModel& model,
    const std::vector<PatternSignature>& patterns,
    const std::map<std::size_t, std::size_t>& candidate_position,
    const PackedFeatureMatrix& features,
    const std::vector<int>& labels,
    Clock::time_point deadline,
    RuleOptimizerStats* stats,
    std::string* reason) {
  std::size_t signature_fp = 0;
  std::size_t signature_fn = 0;
  for (const auto& pattern : patterns) {
    if (Clock::now() >= deadline) {
      *reason = "optimizer deadline expired during signature verification";
      stats->verified = false;
      return VerificationStatus::timeout;
    }
    const bool prediction =
        model_matches_signature(model, pattern, candidate_position);
    if (prediction && pattern.label == 0) signature_fp += 1;
    if (!prediction && pattern.label == 1) signature_fn += 1;
  }
  if (signature_fp != 0 || signature_fn != 0) {
    stats->verification_false_positive = signature_fp;
    stats->verification_false_negative = signature_fn;
    stats->verified = false;
    *reason = "optimized model failed projected-signature verification";
    return VerificationStatus::failed;
  }

  std::size_t full_fp = 0;
  std::size_t full_fn = 0;
  for (std::size_t row = 0; row < features.row_count; ++row) {
    if ((row & 1023U) == 0U && Clock::now() >= deadline) {
      *reason = "optimizer deadline expired during full-row verification";
      stats->verified = false;
      return VerificationStatus::timeout;
    }
    const bool prediction = model_matches_row(model, features, row);
    if (prediction && labels[row] == 0) full_fp += 1;
    if (!prediction && labels[row] == 1) full_fn += 1;
  }
  stats->verification_false_positive = full_fp;
  stats->verification_false_negative = full_fn;
  stats->verified = full_fp == 0 && full_fn == 0;
  if (!stats->verified) {
    *reason = "optimized model failed full packed-matrix verification";
    return VerificationStatus::failed;
  }
  if (Clock::now() >= deadline) {
    *reason = "optimizer deadline expired after full-row verification";
    stats->verified = false;
    return VerificationStatus::timeout;
  }
  reason->clear();
  return VerificationStatus::verified;
}

bool vector_subset(const std::vector<std::size_t>& subset,
                   const std::vector<std::size_t>& superset) {
  return std::includes(superset.begin(), superset.end(),
                       subset.begin(), subset.end());
}

std::vector<std::vector<std::size_t>> build_minimal_difference_edges(
    const PatternSignature& positive,
    const std::vector<const PatternSignature*>& negatives,
    std::size_t feature_count,
    RuleOptimizerStats* stats) {
  std::vector<std::vector<std::size_t>> edges;
  edges.reserve(negatives.size());
  for (const PatternSignature* negative : negatives) {
    std::vector<std::size_t> difference;
    for (std::size_t feature = 0; feature < feature_count; ++feature) {
      if (signature_value(positive, feature) !=
          signature_value(*negative, feature)) {
        difference.push_back(feature);
      }
    }
    edges.push_back(std::move(difference));
  }
  std::sort(edges.begin(), edges.end(),
            [](const std::vector<std::size_t>& lhs,
               const std::vector<std::size_t>& rhs) {
              if (lhs.size() != rhs.size()) return lhs.size() < rhs.size();
              return lhs < rhs;
            });
  edges.erase(std::unique(edges.begin(), edges.end()), edges.end());
  if (stats) stats->pool_hyperedges += edges.size();

  // If A is a subset of B, hitting A necessarily hits B.  Retaining only
  // inclusion-minimal difference edges shrinks enumeration without changing
  // its minimal transversals.
  std::vector<std::vector<std::size_t>> minimal;
  minimal.reserve(edges.size());
  for (const auto& edge : edges) {
    bool redundant = false;
    for (const auto& kept : minimal) {
      if (kept.size() > edge.size()) break;
      if (vector_subset(kept, edge)) {
        redundant = true;
        break;
      }
    }
    if (redundant) {
      if (stats) stats->pool_redundant_hyperedges += 1;
    } else {
      minimal.push_back(edge);
    }
  }
  return minimal;
}

bool is_minimal_hitting_set(
    const std::vector<std::vector<std::size_t>>& edges,
    const std::vector<char>& selected,
    const std::vector<std::size_t>& selected_features) {
  // Every member of a minimal hitting set has a private edge: an edge whose
  // intersection with the hitting set consists of that member alone.
  for (std::size_t feature : selected_features) {
    bool has_private_edge = false;
    for (const auto& edge : edges) {
      std::size_t intersection_count = 0;
      std::size_t intersection_feature = 0;
      for (std::size_t member : edge) {
        if (!selected[member]) continue;
        intersection_count += 1;
        intersection_feature = member;
        if (intersection_count > 1) break;
      }
      if (intersection_count == 1 && intersection_feature == feature) {
        has_private_edge = true;
        break;
      }
    }
    if (!has_private_edge) return false;
  }
  return true;
}

struct EnumerationState {
  Clock::time_point deadline;
  std::size_t literal_limit = 0;
  std::size_t max_terms = 0;
  std::size_t max_states = 0;
  std::size_t recursion_calls = 0;
  std::size_t states_explored = 0;
  bool timed_out = false;
  bool term_limit_hit = false;
  bool state_limit_hit = false;
  bool depth_limit_hit = false;
  RuleOptimizerStats* stats = nullptr;
  std::map<TermKey, char>* unique_terms = nullptr;
};

bool enumeration_should_stop(EnumerationState* state, bool force_clock_check) {
  if (state->timed_out || state->term_limit_hit || state->state_limit_hit ||
      state->depth_limit_hit) {
    return true;
  }
  state->recursion_calls += 1;
  if (force_clock_check || (state->recursion_calls & 1023U) == 0U) {
    if (Clock::now() >= state->deadline) {
      state->timed_out = true;
      return true;
    }
  }
  return false;
}

void enumerate_minimal_hitting_sets(
    const PatternSignature& positive,
    const std::vector<std::size_t>& candidates,
    const std::vector<std::vector<std::size_t>>& edges,
    std::vector<char>* selected,
    std::vector<std::size_t>* selected_features,
    std::set<std::vector<std::size_t>>* visited,
    EnumerationState* state) {
  if (enumeration_should_stop(state, false)) return;
  state->states_explored += 1;
  if (state->stats) {
    state->stats->pool_states_explored = state->states_explored;
  }
  if (state->max_states != 0 &&
      state->states_explored > state->max_states) {
    state->state_limit_hit = true;
    if (state->stats) state->stats->pool_state_limit_hit = true;
    return;
  }
  if (!visited->insert(*selected_features).second) return;

  const std::vector<std::size_t>* uncovered = nullptr;
  for (const auto& edge : edges) {
    bool hit = false;
    for (std::size_t feature : edge) {
      if ((*selected)[feature]) {
        hit = true;
        break;
      }
    }
    if (!hit) {
      uncovered = &edge;
      break;
    }
  }

  if (!uncovered) {
    if (selected_features->empty() ||
        !is_minimal_hitting_set(edges, *selected, *selected_features)) {
      return;
    }
    TermKey term;
    term.reserve(selected_features->size());
    for (std::size_t position : *selected_features) {
      term.push_back({candidates[position],
                      signature_value(positive, position)});
    }
    std::sort(term.begin(), term.end());
    if (state->stats) state->stats->pool_terms_generated += 1;
    const auto inserted = state->unique_terms->emplace(std::move(term), 0);
    if (inserted.second && state->max_terms != 0 &&
        state->unique_terms->size() > state->max_terms) {
      state->unique_terms->erase(inserted.first);
      state->term_limit_hit = true;
    }
    return;
  }

  if (selected_features->size() >= state->literal_limit) return;
  // This implementation intentionally uses recursive DFS because ordinary
  // trigger rules are shallow (the default literal cap is ten).  Keep an
  // explicit hard guard so adversarial, user-supplied caps cannot overflow
  // the native stack before timeout/resource fallback is reached.
  constexpr std::size_t kMaxSafeEnumerationDepth = 256;
  if (selected_features->size() >= kMaxSafeEnumerationDepth) {
    state->depth_limit_hit = true;
    if (state->stats) state->stats->pool_depth_limit_hit = true;
    return;
  }
  for (std::size_t feature : *uncovered) {
    if (enumeration_should_stop(state, false)) return;
    (*selected)[feature] = 1;
    const auto position = std::lower_bound(selected_features->begin(),
                                           selected_features->end(), feature);
    const std::size_t insertion_offset = static_cast<std::size_t>(
        position - selected_features->begin());
    selected_features->insert(position, feature);
    enumerate_minimal_hitting_sets(positive, candidates, edges, selected,
                                   selected_features, visited, state);
    selected_features->erase(selected_features->begin() +
                             static_cast<long>(insertion_offset));
    (*selected)[feature] = 0;
  }
}

struct CoverTerm {
  DecisionTreeRule rule;
  std::vector<Word> positive_cover;
};

bool extract_term_model(const std::vector<CoverTerm>& terms,
                        const std::vector<double>& values,
                        std::size_t expected_rules,
                        std::size_t expected_literals,
                        DecisionTreeModel* model,
                        std::string* reason,
                        std::set<std::size_t>* selected_inverters = nullptr) {
  if (!model || values.size() < terms.size()) {
    *reason = "solver solution is missing term variables";
    return false;
  }
  *model = DecisionTreeModel{};
  if (selected_inverters) selected_inverters->clear();
  for (std::size_t term = 0; term < terms.size(); ++term) {
    const double value = values[term];
    if (!std::isfinite(value) ||
        std::fabs(value - std::round(value)) > 1.0e-6 ||
        value < -1.0e-6 || value > 1.0 + 1.0e-6) {
      *reason = "solver returned a non-integral term variable";
      return false;
    }
    if (value <= 0.5) continue;
    model->rules.push_back(terms[term].rule);
    if (selected_inverters) {
      for (const auto& literal : terms[term].rule.terms) {
        if (literal.second == 0) {
          selected_inverters->insert(literal.first);
        }
      }
    }
    model->max_depth_used = std::max(
        model->max_depth_used, terms[term].rule.terms.size());
  }
  std::sort(model->rules.begin(), model->rules.end(),
            [](const DecisionTreeRule& lhs, const DecisionTreeRule& rhs) {
              return lhs.terms < rhs.terms;
            });
  model->leaf_count = model->rules.size();
  if (model->rules.size() != expected_rules ||
      count_literals(*model) != expected_literals) {
    *reason = "extracted model disagrees with fixed MILP objectives";
    return false;
  }
  return true;
}

std::vector<std::size_t> negative_feature_set(
    const DecisionTreeRule& rule) {
  std::vector<std::size_t> features;
  for (const auto& literal : rule.terms) {
    if (literal.second == 0) features.push_back(literal.first);
  }
  // Rule terms are canonical, but keep this helper independently robust.
  std::sort(features.begin(), features.end());
  features.erase(std::unique(features.begin(), features.end()),
                 features.end());
  return features;
}

std::size_t cover_popcount(const std::vector<Word>& cover) {
  std::size_t result = 0;
  for (Word word : cover) {
    result += static_cast<std::size_t>(__builtin_popcountll(word));
  }
  return result;
}

bool make_cover_term(
    const TermKey& key,
    const std::vector<const PatternSignature*>& positives,
    const std::vector<const PatternSignature*>& negatives,
    const std::map<std::size_t, std::size_t>& candidate_position,
    CoverTerm* out) {
  out->rule.terms = key;
  for (const PatternSignature* negative : negatives) {
    if (rule_matches_signature(out->rule, *negative, candidate_position)) {
      return false;
    }
  }
  const std::size_t words =
      positives.size() / PackedFeatureMatrix::kWordBits +
      (positives.size() % PackedFeatureMatrix::kWordBits != 0 ? 1U : 0U);
  out->positive_cover.assign(words, Word{0});
  for (std::size_t positive = 0; positive < positives.size(); ++positive) {
    if (rule_matches_signature(out->rule, *positives[positive],
                               candidate_position)) {
      out->positive_cover[positive / PackedFeatureMatrix::kWordBits] |=
          Word{1} << (positive % PackedFeatureMatrix::kWordBits);
    }
  }
  return cover_popcount(out->positive_cover) != 0;
}

bool rule_key_less(const CoverTerm& lhs, const CoverTerm& rhs) {
  return lhs.rule.terms < rhs.rule.terms;
}

#ifdef USE_HIGHS

struct MasterPhaseResult {
  bool invoked = false;
  bool optimal = false;
  std::string status;
  std::string error;
  double objective = 0.0;
  double dual_bound = 0.0;
  double gap = 0.0;
  std::size_t simplex_iterations = 0;
  std::size_t mip_nodes = 0;
  std::vector<double> column_values;
  std::size_t dual_nonzero = 0;
  double dual_min = 0.0;
  double dual_max = 0.0;
  double dual_sum_abs = 0.0;
  double elapsed = 0.0;
};

bool highs_status_ok(HighsStatus status) {
  return status != HighsStatus::kError;
}

bool checked_highs_option(Highs* highs,
                          const std::string& name,
                          const std::string& value,
                          std::string* error) {
  if (highs_status_ok(highs->setOptionValue(name, value))) return true;
  *error = "HiGHS rejected option " + name;
  return false;
}

template <typename T>
bool checked_highs_option(Highs* highs,
                          const std::string& name,
                          T value,
                          std::string* error) {
  if (highs_status_ok(highs->setOptionValue(name, value))) return true;
  *error = "HiGHS rejected option " + name;
  return false;
}

MasterPhaseResult solve_master_phase(
    const std::vector<CoverTerm>& terms,
    const std::vector<std::vector<HighsInt>>& coverage_rows,
    std::size_t clause_limit,
    const std::vector<double>& costs,
    bool integer,
    bool fix_rule_count,
    std::size_t fixed_rule_count,
    Clock::time_point deadline,
    std::size_t* master_constraints,
    std::size_t* master_nonzeros) {
  const Clock::time_point phase_start = Clock::now();
  MasterPhaseResult result;
  if (phase_start >= deadline) {
    result.status = "Time limit";
    result.error = "shared optimizer deadline expired before HiGHS phase";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }
  if (terms.size() >
          static_cast<std::size_t>(std::numeric_limits<HighsInt>::max()) ||
      coverage_rows.size() >
          static_cast<std::size_t>(std::numeric_limits<HighsInt>::max())) {
    result.status = "Model error";
    result.error = "set-cover master exceeds HiGHS index range";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }

  Highs highs;
  std::string option_error;
  if (!checked_highs_option(&highs, "output_flag", false, &option_error) ||
      !checked_highs_option(&highs, "threads", 1, &option_error) ||
      !checked_highs_option(&highs, "parallel", std::string("off"),
                            &option_error) ||
      !checked_highs_option(&highs, "random_seed", 0, &option_error) ||
      !checked_highs_option(&highs, "mip_rel_gap", 0.0, &option_error) ||
      !checked_highs_option(&highs, "mip_abs_gap", 0.0, &option_error)) {
    result.status = "Option error";
    result.error = option_error;
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }

  const HighsInt variable_count = static_cast<HighsInt>(terms.size());
  std::vector<double> lower(terms.size(), 0.0);
  std::vector<double> upper(terms.size(), 1.0);
  if (!highs_status_ok(highs.addCols(variable_count, costs.data(),
                                     lower.data(), upper.data(), 0,
                                     nullptr, nullptr, nullptr))) {
    result.status = "Model error";
    result.error = "HiGHS failed to add set-cover variables";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }
  if (integer) {
    std::vector<HighsVarType> integrality(
        terms.size(), HighsVarType::kInteger);
    if (!highs_status_ok(highs.changeColsIntegrality(
            0, variable_count - 1, integrality.data()))) {
      result.status = "Model error";
      result.error = "HiGHS failed to mark set-cover variables binary";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
  }

  std::size_t row_count = 0;
  std::size_t nonzeros = 0;
  std::vector<HighsInt> indices;
  std::vector<double> values;
  for (std::size_t positive = 0; positive < coverage_rows.size(); ++positive) {
    if ((positive & 127U) == 0U && Clock::now() >= deadline) {
      result.status = "Time limit";
      result.error = "shared optimizer deadline expired building HiGHS rows";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
    indices = coverage_rows[positive];
    if (indices.empty()) {
      result.status = "Infeasible";
      result.error = "a positive signature has no covering term";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
    values.assign(indices.size(), 1.0);
    if (!highs_status_ok(highs.addRow(
            1.0, kHighsInf, static_cast<HighsInt>(indices.size()),
            indices.data(), values.data()))) {
      result.status = "Model error";
      result.error = "HiGHS failed to add a positive coverage row";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
    row_count += 1;
    nonzeros += indices.size();
  }

  indices.resize(terms.size());
  values.assign(terms.size(), 1.0);
  for (std::size_t term = 0; term < terms.size(); ++term) {
    indices[term] = static_cast<HighsInt>(term);
  }
  if (!highs_status_ok(highs.addRow(
          -kHighsInf, static_cast<double>(clause_limit), variable_count,
          indices.data(), values.data()))) {
    result.status = "Model error";
    result.error = "HiGHS failed to add the clause-limit row";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }
  row_count += 1;
  nonzeros += terms.size();
  if (fix_rule_count) {
    const double count = static_cast<double>(fixed_rule_count);
    if (!highs_status_ok(highs.addRow(count, count, variable_count,
                                      indices.data(), values.data()))) {
      result.status = "Model error";
      result.error = "HiGHS failed to fix the optimal rule count";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
    row_count += 1;
    nonzeros += terms.size();
  }
  if (master_constraints) *master_constraints = row_count;
  if (master_nonzeros) *master_nonzeros = nonzeros;

  if (Clock::now() >= deadline) {
    result.status = "Time limit";
    result.error = "shared optimizer deadline expired before HiGHS run";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }
  const double seconds = std::max(
      0.001,
      std::chrono::duration<double>(deadline - Clock::now()).count());
  if (!checked_highs_option(&highs, "time_limit", seconds, &option_error)) {
    result.status = "Option error";
    result.error = option_error;
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }

  result.invoked = true;
  const HighsStatus run_status = highs.run();
  result.status = highs.modelStatusToString(highs.getModelStatus());
  if (!highs_status_ok(run_status)) {
    result.error = "HiGHS run returned an error";
  }
  result.optimal = highs.getModelStatus() == HighsModelStatus::kOptimal;
  const HighsInfo& info = highs.getInfo();
  if (info.valid) {
    result.objective = info.objective_function_value;
    result.dual_bound = info.mip_dual_bound;
    result.gap = info.mip_gap;
    if (info.simplex_iteration_count > 0) {
      result.simplex_iterations =
          static_cast<std::size_t>(info.simplex_iteration_count);
    }
    if (info.mip_node_count > 0) {
      result.mip_nodes = static_cast<std::size_t>(info.mip_node_count);
    }
  }

  const HighsSolution& solution = highs.getSolution();
  if (solution.value_valid) result.column_values = solution.col_value;
  if (!integer && solution.dual_valid &&
      solution.row_dual.size() >= coverage_rows.size() &&
      !coverage_rows.empty()) {
    result.dual_min = solution.row_dual[0];
    result.dual_max = solution.row_dual[0];
    for (std::size_t row = 0; row < coverage_rows.size(); ++row) {
      const double dual = solution.row_dual[row];
      result.dual_min = std::min(result.dual_min, dual);
      result.dual_max = std::max(result.dual_max, dual);
      result.dual_sum_abs += std::fabs(dual);
      if (std::fabs(dual) > 1.0e-9) result.dual_nonzero += 1;
    }
  }
  result.elapsed = elapsed_ms(phase_start);
  return result;
}

struct InverterMasterData {
  std::vector<std::size_t> features;
  std::vector<std::vector<HighsInt>> terms_by_feature;
  std::size_t incidences = 0;
};

bool build_inverter_master_data(
    const std::vector<CoverTerm>& terms,
    Clock::time_point deadline,
    InverterMasterData* result) {
  if (!result) return false;
  std::map<std::size_t, std::vector<HighsInt>> by_feature;
  for (std::size_t term = 0; term < terms.size(); ++term) {
    if ((term & 1023U) == 0U && Clock::now() >= deadline) return false;
    for (const auto& literal : terms[term].rule.terms) {
      if (literal.second == 0) {
        by_feature[literal.first].push_back(static_cast<HighsInt>(term));
      }
    }
  }
  result->features.clear();
  result->terms_by_feature.clear();
  result->incidences = 0;
  result->features.reserve(by_feature.size());
  result->terms_by_feature.reserve(by_feature.size());
  for (auto& entry : by_feature) {
    if (Clock::now() >= deadline) return false;
    if (entry.second.size() >
        std::numeric_limits<std::size_t>::max() - result->incidences) {
      return false;
    }
    result->features.push_back(entry.first);
    result->incidences += entry.second.size();
    result->terms_by_feature.push_back(std::move(entry.second));
  }
  return Clock::now() < deadline;
}

MasterPhaseResult solve_inverter_phase(
    const std::vector<CoverTerm>& terms,
    const std::vector<std::vector<HighsInt>>& coverage_rows,
    const InverterMasterData& inverter_data,
    std::size_t clause_limit,
    std::size_t fixed_rule_count,
    std::size_t fixed_literal_count,
    bool integer,
    Clock::time_point deadline,
    std::size_t* master_variables,
    std::size_t* master_constraints,
    std::size_t* master_nonzeros,
    std::size_t* inverter_link_constraints) {
  const Clock::time_point phase_start = Clock::now();
  MasterPhaseResult result;
  if (phase_start >= deadline) {
    result.status = "Time limit";
    result.error = "shared optimizer deadline expired before inverter phase";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }
  if (terms.size() >
          static_cast<std::size_t>(std::numeric_limits<HighsInt>::max()) ||
      coverage_rows.size() >
          static_cast<std::size_t>(std::numeric_limits<HighsInt>::max()) ||
      inverter_data.features.size() >
          static_cast<std::size_t>(std::numeric_limits<HighsInt>::max()) ||
      inverter_data.features.size() !=
          inverter_data.terms_by_feature.size() ||
      terms.size() > std::numeric_limits<std::size_t>::max() -
                         inverter_data.features.size()) {
    result.status = "Model error";
    result.error = "inverter master exceeds HiGHS index range";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }
  const std::size_t variable_size =
      terms.size() + inverter_data.features.size();
  if (variable_size >
      static_cast<std::size_t>(std::numeric_limits<HighsInt>::max())) {
    result.status = "Model error";
    result.error = "inverter master variable count exceeds HiGHS index range";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }

  auto checked_add = [](std::size_t addend, std::size_t* value) {
    if (addend > std::numeric_limits<std::size_t>::max() - *value) {
      return false;
    }
    *value += addend;
    return true;
  };
  auto checked_multiply = [](std::size_t lhs, std::size_t rhs,
                             std::size_t* product) {
    if (lhs != 0 &&
        rhs > std::numeric_limits<std::size_t>::max() / lhs) {
      return false;
    }
    *product = lhs * rhs;
    return true;
  };
  std::size_t coverage_nonzeros = 0;
  for (std::size_t row = 0; row < coverage_rows.size(); ++row) {
    if ((row & 1023U) == 0U && Clock::now() >= deadline) {
      result.status = "Time limit";
      result.error = "shared deadline expired sizing inverter master";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
    if (coverage_rows[row].size() >
            static_cast<std::size_t>(
                std::numeric_limits<HighsInt>::max()) ||
        !checked_add(coverage_rows[row].size(), &coverage_nonzeros)) {
      result.status = "Model error";
      result.error = "inverter-master coverage incidence exceeds index range";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
  }
  std::size_t required_rows = coverage_rows.size();
  std::size_t required_nonzeros = coverage_nonzeros;
  std::size_t term_nonzeros = 0;
  std::size_t link_nonzeros = 0;
  if (!checked_add(3, &required_rows) ||
      !checked_add(inverter_data.incidences, &required_rows) ||
      !checked_add(inverter_data.features.size(), &required_rows) ||
      !checked_multiply(terms.size(), 3, &term_nonzeros) ||
      !checked_add(term_nonzeros, &required_nonzeros) ||
      !checked_multiply(inverter_data.incidences, 3,
                        &link_nonzeros) ||
      !checked_add(link_nonzeros, &required_nonzeros) ||
      !checked_add(inverter_data.features.size(), &required_nonzeros) ||
      required_rows >
          static_cast<std::size_t>(
              std::numeric_limits<HighsInt>::max()) ||
      required_nonzeros >
          static_cast<std::size_t>(
              std::numeric_limits<HighsInt>::max())) {
    result.status = "Model error";
    result.error = "inverter master exceeds HiGHS row/nonzero index range";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }

  Highs highs;
  std::string option_error;
  if (!checked_highs_option(&highs, "output_flag", false, &option_error) ||
      !checked_highs_option(&highs, "threads", 1, &option_error) ||
      !checked_highs_option(&highs, "parallel", std::string("off"),
                            &option_error) ||
      !checked_highs_option(&highs, "random_seed", 0, &option_error) ||
      !checked_highs_option(&highs, "mip_rel_gap", 0.0, &option_error) ||
      !checked_highs_option(&highs, "mip_abs_gap", 0.0, &option_error)) {
    result.status = "Option error";
    result.error = option_error;
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }

  const HighsInt variable_count = static_cast<HighsInt>(variable_size);
  std::vector<double> costs(variable_size, 0.0);
  for (std::size_t inverter = 0;
       inverter < inverter_data.features.size(); ++inverter) {
    costs[terms.size() + inverter] = 1.0;
  }
  std::vector<double> lower(variable_size, 0.0);
  std::vector<double> upper(variable_size, 1.0);
  if (!highs_status_ok(highs.addCols(variable_count, costs.data(),
                                     lower.data(), upper.data(), 0,
                                     nullptr, nullptr, nullptr))) {
    result.status = "Model error";
    result.error = "HiGHS failed to add inverter-master variables";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }
  if (integer) {
    std::vector<HighsVarType> integrality(
        variable_size, HighsVarType::kInteger);
    if (!highs_status_ok(highs.changeColsIntegrality(
            0, variable_count - 1, integrality.data()))) {
      result.status = "Model error";
      result.error = "HiGHS failed to mark inverter-master variables binary";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
  }

  std::size_t row_count = 0;
  std::size_t nonzeros = 0;
  std::vector<HighsInt> indices;
  std::vector<double> values;
  for (std::size_t positive = 0; positive < coverage_rows.size(); ++positive) {
    if ((positive & 127U) == 0U && Clock::now() >= deadline) {
      result.status = "Time limit";
      result.error = "shared deadline expired building inverter cover rows";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
    indices = coverage_rows[positive];
    if (indices.empty()) {
      result.status = "Infeasible";
      result.error = "a positive signature has no inverter-master term";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
    values.assign(indices.size(), 1.0);
    if (!highs_status_ok(highs.addRow(
            1.0, kHighsInf, static_cast<HighsInt>(indices.size()),
            indices.data(), values.data()))) {
      result.status = "Model error";
      result.error = "HiGHS failed to add inverter-master coverage row";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
    row_count += 1;
    nonzeros += indices.size();
  }

  indices.resize(terms.size());
  values.assign(terms.size(), 1.0);
  for (std::size_t term = 0; term < terms.size(); ++term) {
    indices[term] = static_cast<HighsInt>(term);
  }
  const HighsInt term_count = static_cast<HighsInt>(terms.size());
  if (!highs_status_ok(highs.addRow(
          -kHighsInf, static_cast<double>(clause_limit), term_count,
          indices.data(), values.data())) ||
      !highs_status_ok(highs.addRow(
          static_cast<double>(fixed_rule_count),
          static_cast<double>(fixed_rule_count), term_count,
          indices.data(), values.data()))) {
    result.status = "Model error";
    result.error = "HiGHS failed to add inverter-master rule rows";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }
  row_count += 2;
  nonzeros += terms.size() * 2;

  for (std::size_t term = 0; term < terms.size(); ++term) {
    values[term] = static_cast<double>(terms[term].rule.terms.size());
  }
  if (!highs_status_ok(highs.addRow(
          static_cast<double>(fixed_literal_count),
          static_cast<double>(fixed_literal_count), term_count,
          indices.data(), values.data()))) {
    result.status = "Model error";
    result.error = "HiGHS failed to fix the optimal literal count";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }
  row_count += 1;
  nonzeros += terms.size();

  std::size_t link_rows = 0;
  std::size_t processed_incidences = 0;
  for (std::size_t inverter = 0;
       inverter < inverter_data.features.size(); ++inverter) {
    if ((inverter & 127U) == 0U && Clock::now() >= deadline) {
      result.status = "Time limit";
      result.error = "shared deadline expired building inverter OR rows";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
    const HighsInt inverter_col =
        static_cast<HighsInt>(terms.size() + inverter);
    const std::vector<HighsInt>& using_terms =
        inverter_data.terms_by_feature[inverter];
    for (HighsInt term_col : using_terms) {
      if ((processed_incidences++ & 1023U) == 0U &&
          Clock::now() >= deadline) {
        result.status = "Time limit";
        result.error = "shared deadline expired building inverter links";
        result.elapsed = elapsed_ms(phase_start);
        return result;
      }
      const HighsInt link_indices[2] = {term_col, inverter_col};
      const double link_values[2] = {-1.0, 1.0};
      // z_f >= y_t for every term t using the negative literal f=0.
      if (!highs_status_ok(highs.addRow(
              0.0, kHighsInf, 2, link_indices, link_values))) {
        result.status = "Model error";
        result.error = "HiGHS failed to add inverter lower-link row";
        result.elapsed = elapsed_ms(phase_start);
        return result;
      }
      row_count += 1;
      link_rows += 1;
      nonzeros += 2;
    }

    // z_f <= sum_{t uses f=0} y_t closes the OR linearization; without this
    // row an unused inverter could be spuriously set in an LP/MIP solution.
    indices = using_terms;
    values.assign(indices.size(), -1.0);
    indices.push_back(inverter_col);
    values.push_back(1.0);
    if (!highs_status_ok(highs.addRow(
            -kHighsInf, 0.0, static_cast<HighsInt>(indices.size()),
            indices.data(), values.data()))) {
      result.status = "Model error";
      result.error = "HiGHS failed to add inverter upper-link row";
      result.elapsed = elapsed_ms(phase_start);
      return result;
    }
    row_count += 1;
    link_rows += 1;
    nonzeros += indices.size();
  }

  if (master_variables) *master_variables = variable_size;
  if (master_constraints) *master_constraints = row_count;
  if (master_nonzeros) *master_nonzeros = nonzeros;
  if (inverter_link_constraints) *inverter_link_constraints = link_rows;
  if (Clock::now() >= deadline) {
    result.status = "Time limit";
    result.error = "shared optimizer deadline expired before inverter run";
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }
  const double seconds = std::max(
      0.001,
      std::chrono::duration<double>(deadline - Clock::now()).count());
  if (!checked_highs_option(&highs, "time_limit", seconds, &option_error)) {
    result.status = "Option error";
    result.error = option_error;
    result.elapsed = elapsed_ms(phase_start);
    return result;
  }

  result.invoked = true;
  const HighsStatus run_status = highs.run();
  result.status = highs.modelStatusToString(highs.getModelStatus());
  if (!highs_status_ok(run_status)) {
    result.error = "HiGHS inverter run returned an error";
  }
  result.optimal = highs.getModelStatus() == HighsModelStatus::kOptimal;
  const HighsInfo& info = highs.getInfo();
  if (info.valid) {
    result.objective = info.objective_function_value;
    result.dual_bound = info.mip_dual_bound;
    result.gap = info.mip_gap;
    if (info.simplex_iteration_count > 0) {
      result.simplex_iterations =
          static_cast<std::size_t>(info.simplex_iteration_count);
    }
    if (info.mip_node_count > 0) {
      result.mip_nodes = static_cast<std::size_t>(info.mip_node_count);
    }
  }
  const HighsSolution& solution = highs.getSolution();
  if (solution.value_valid) result.column_values = solution.col_value;
  if (!integer && solution.dual_valid &&
      solution.row_dual.size() >= coverage_rows.size() &&
      !coverage_rows.empty()) {
    result.dual_min = solution.row_dual[0];
    result.dual_max = solution.row_dual[0];
    for (std::size_t row = 0; row < coverage_rows.size(); ++row) {
      const double dual = solution.row_dual[row];
      result.dual_min = std::min(result.dual_min, dual);
      result.dual_max = std::max(result.dual_max, dual);
      result.dual_sum_abs += std::fabs(dual);
      if (std::fabs(dual) > 1.0e-9) result.dual_nonzero += 1;
    }
  }
  result.elapsed = elapsed_ms(phase_start);
  return result;
}

void assign_lp3_phase(const MasterPhaseResult& phase,
                      RuleOptimizerStats* stats) {
  stats->lp3_status = phase.status;
  stats->lp3_objective = phase.objective;
  stats->lp3_iterations = phase.simplex_iterations;
  stats->lp3_dual_nonzero = phase.dual_nonzero;
  stats->lp3_dual_min = phase.dual_min;
  stats->lp3_dual_max = phase.dual_max;
  stats->lp3_dual_sum_abs = phase.dual_sum_abs;
  stats->lp3_ms = phase.elapsed;
}

void assign_mip3_phase(const MasterPhaseResult& phase,
                       RuleOptimizerStats* stats) {
  stats->mip3_status = phase.status;
  stats->mip3_objective = phase.objective;
  stats->mip3_dual_bound = phase.dual_bound;
  stats->mip3_gap = phase.gap;
  stats->mip3_nodes = phase.mip_nodes;
  stats->mip3_ms = phase.elapsed;
}

void assign_lp_phase(const MasterPhaseResult& phase,
                     bool first,
                     RuleOptimizerStats* stats) {
  if (first) {
    stats->lp1_status = phase.status;
    stats->lp1_objective = phase.objective;
    stats->lp1_iterations = phase.simplex_iterations;
    stats->lp1_dual_nonzero = phase.dual_nonzero;
    stats->lp1_dual_min = phase.dual_min;
    stats->lp1_dual_max = phase.dual_max;
    stats->lp1_dual_sum_abs = phase.dual_sum_abs;
    stats->lp1_ms = phase.elapsed;
  } else {
    stats->lp2_status = phase.status;
    stats->lp2_objective = phase.objective;
    stats->lp2_iterations = phase.simplex_iterations;
    stats->lp2_dual_nonzero = phase.dual_nonzero;
    stats->lp2_dual_min = phase.dual_min;
    stats->lp2_dual_max = phase.dual_max;
    stats->lp2_dual_sum_abs = phase.dual_sum_abs;
    stats->lp2_ms = phase.elapsed;
  }
}

void assign_mip_phase(const MasterPhaseResult& phase,
                      bool first,
                      RuleOptimizerStats* stats) {
  if (first) {
    stats->mip1_status = phase.status;
    stats->mip1_objective = phase.objective;
    stats->mip1_dual_bound = phase.dual_bound;
    stats->mip1_gap = phase.gap;
    stats->mip1_nodes = phase.mip_nodes;
    stats->mip1_ms = phase.elapsed;
  } else {
    stats->mip2_status = phase.status;
    stats->mip2_objective = phase.objective;
    stats->mip2_dual_bound = phase.dual_bound;
    stats->mip2_gap = phase.gap;
    stats->mip2_nodes = phase.mip_nodes;
    stats->mip2_ms = phase.elapsed;
  }
}

#endif  // USE_HIGHS

std::string phase_failure_status(const std::string& solver_status) {
  std::string lower = solver_status;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char ch) { return static_cast<char>(
                     std::tolower(ch)); });
  if (lower.find("time") != std::string::npos) return "timeout";
  if (lower.find("infeasible") != std::string::npos) return "infeasible";
  return "unknown";
}

#endif  // USE_HIGHS

}  // namespace

namespace set_cover_optimizer_testing {

void force_phase3_timeout_after_verified_mip2_once() {
  force_phase3_timeout_after_verified_mip2.store(
      true, std::memory_order_relaxed);
}

}  // namespace set_cover_optimizer_testing

bool highs_set_cover_backend_available() {
#ifdef USE_HIGHS
  return true;
#else
  return false;
#endif
}

RuleOptimizationResult optimize_dnf_rules_highs_set_cover(
    const PackedFeatureMatrix& features,
    const std::vector<int>& labels,
    const std::vector<std::size_t>& raw_dt_candidate_features,
    const DecisionTreeModel& baseline_model,
    const RuleOptimizerOptions& options) {
  const Clock::time_point total_start = Clock::now();
  RuleOptimizationResult result;
  result.model = baseline_model;
  RuleOptimizerStats& stats = result.stats;
  stats.solver_backend = "highs-set-cover-milp";
  stats.backend_available = highs_set_cover_backend_available();
  stats.input_rows = features.row_count;
  stats.raw_candidate_features = raw_dt_candidate_features.size();
  stats.rules_before = baseline_model.rules.size();
  stats.literals_before = count_literals(baseline_model);
  stats.rules_after = stats.rules_before;
  stats.literals_after = stats.literals_before;
  try {
    stats.unique_inverters_before = count_unique_inverters(baseline_model);
  } catch (const std::exception& exception) {
    stats.status = "unknown";
    stats.reason = std::string("failed to count baseline inverters: ") +
                   exception.what();
    finish_stats(&result, total_start);
    return result;
  }
  stats.unique_inverters_after = stats.unique_inverters_before;
  stats.third_objective =
      options.cover_third_objective ==
              RuleCoverThirdObjective::unique_inverters
          ? "unique_inverters"
          : "none";

#ifndef USE_HIGHS
  (void)labels;
  stats.status = "backend_unavailable";
  stats.reason = "HiGHS support was not compiled (USE_HIGHS is disabled)";
  finish_stats(&result, total_start);
  return result;
#else
  try {
  Highs version_probe;
  stats.solver_version = version_probe.version();

  if (!validate_input(features, labels, raw_dt_candidate_features,
                      baseline_model, &stats.reason)) {
    stats.status = "invalid";
    finish_stats(&result, total_start);
    return result;
  }
  for (int label : labels) {
    if (label == 1) {
      stats.positive_rows += 1;
    } else {
      stats.negative_rows += 1;
    }
  }
  if (stats.positive_rows == 0 || stats.negative_rows == 0) {
    stats.status = "invalid";
    stats.reason = "both positive and negative samples are required";
    finish_stats(&result, total_start);
    return result;
  }
  if (options.timeout_ms == 0) {
    stats.status = "timeout";
    stats.reason = "optimizer wall-clock budget is zero";
    finish_stats(&result, total_start);
    return result;
  }
  const Clock::time_point deadline =
      total_start + std::chrono::milliseconds(options.timeout_ms);
  const Clock::time_point preprocessing_start = Clock::now();

  const std::vector<std::size_t> candidates =
      deduplicate_candidate_features(features, raw_dt_candidate_features);
  stats.unique_candidate_features = candidates.size();
  stats.duplicate_candidate_features =
      raw_dt_candidate_features.size() - candidates.size();
  stats.candidate_literals = candidates.size() * 2;
  if (candidates.empty()) {
    stats.status = "invalid";
    stats.reason = "candidate signature deduplication removed all features";
    stats.preprocessing_ms = elapsed_ms(preprocessing_start);
    finish_stats(&result, total_start);
    return result;
  }

  SignatureBuildResult signature_result =
      build_pattern_signatures(features, labels, candidates);
  stats.unique_pattern_signatures = signature_result.total_unique;
  stats.duplicate_pattern_rows =
      stats.input_rows - stats.unique_pattern_signatures;
  stats.conflicting_signatures = signature_result.conflicts;
  if (signature_result.conflicts != 0) {
    stats.status = "infeasible";
    stats.reason = "positive and negative rows share a candidate projection";
    stats.preprocessing_ms = elapsed_ms(preprocessing_start);
    finish_stats(&result, total_start);
    return result;
  }

  std::vector<const PatternSignature*> positives;
  std::vector<const PatternSignature*> negatives;
  for (const auto& pattern : signature_result.patterns) {
    if (pattern.label == 1) {
      positives.push_back(&pattern);
    } else {
      negatives.push_back(&pattern);
    }
  }
  stats.positive_signatures = positives.size();
  stats.negative_signatures = negatives.size();

  stats.clause_limit = options.max_clauses == 0
                           ? baseline_model.rules.size()
                           : options.max_clauses;
  std::size_t baseline_max_literals = 0;
  for (const auto& rule : baseline_model.rules) {
    baseline_max_literals =
        std::max(baseline_max_literals, rule.terms.size());
  }
  stats.literal_limit = options.max_literals_per_clause == 0
                            ? std::max<std::size_t>(1, baseline_max_literals)
                            : options.max_literals_per_clause;
  if (stats.clause_limit == 0 || stats.literal_limit == 0) {
    stats.status = "invalid";
    stats.reason = "clause and literal limits must be positive";
    stats.preprocessing_ms = elapsed_ms(preprocessing_start);
    finish_stats(&result, total_start);
    return result;
  }

  std::map<std::size_t, std::size_t> candidate_position;
  for (std::size_t position = 0; position < candidates.size(); ++position) {
    candidate_position[candidates[position]] = position;
  }

  const Clock::time_point generation_start = Clock::now();
  std::map<TermKey, char> unique_term_keys;
  EnumerationState enumeration;
  enumeration.deadline = deadline;
  enumeration.literal_limit = stats.literal_limit;
  enumeration.max_terms = options.max_pool_terms;
  enumeration.max_states = options.max_pool_states;
  enumeration.stats = &stats;
  enumeration.unique_terms = &unique_term_keys;
  for (const PatternSignature* positive : positives) {
    if (enumeration_should_stop(&enumeration, true)) break;
    const std::vector<std::vector<std::size_t>> edges =
        build_minimal_difference_edges(*positive, negatives,
                                       candidates.size(), &stats);
    bool empty_edge = false;
    for (const auto& edge : edges) {
      if (edge.empty()) {
        empty_edge = true;
        break;
      }
    }
    if (empty_edge) {
      stats.status = "infeasible";
      stats.reason = "positive/negative signatures have no separating literal";
      stats.term_generation_ms = elapsed_ms(generation_start);
      stats.preprocessing_ms = elapsed_ms(preprocessing_start);
      finish_stats(&result, total_start);
      return result;
    }
    std::vector<char> selected(candidates.size(), 0);
    std::vector<std::size_t> selected_features;
    std::set<std::vector<std::size_t>> visited;
    enumerate_minimal_hitting_sets(*positive, candidates, edges, &selected,
                                   &selected_features, &visited, &enumeration);
  }
  stats.term_generation_ms = elapsed_ms(generation_start);
  stats.pool_terms_unique = unique_term_keys.size();
  if (enumeration.timed_out) {
    stats.status = "timeout";
    stats.reason = "optimizer deadline expired during term enumeration";
    stats.preprocessing_ms = elapsed_ms(preprocessing_start);
    finish_stats(&result, total_start);
    return result;
  }
  if (enumeration.term_limit_hit) {
    stats.status = "pool_limit";
    stats.reason = "prime-implicant term pool exceeded max_pool_terms";
    stats.preprocessing_ms = elapsed_ms(preprocessing_start);
    finish_stats(&result, total_start);
    return result;
  }
  if (enumeration.state_limit_hit || enumeration.depth_limit_hit) {
    stats.status = "pool_limit";
    stats.reason = enumeration.depth_limit_hit
                       ? "prime-implicant enumeration exceeded safe DFS depth"
                       : "prime-implicant enumeration exceeded max_pool_states";
    stats.preprocessing_ms = elapsed_ms(preprocessing_start);
    finish_stats(&result, total_start);
    return result;
  }
  stats.pool_complete = true;
  if (unique_term_keys.empty()) {
    stats.status = "infeasible";
    stats.reason = "no bounded prime implicant separates the signatures";
    stats.preprocessing_ms = elapsed_ms(preprocessing_start);
    finish_stats(&result, total_start);
    return result;
  }

  // With only the first two objectives, terms with identical positive
  // coverage are interchangeable: keep the shortest, then lexical first.
  // For the optional inverter objective, equally short alternatives must be
  // retained when their expected-zero feature sets are incomparable.  A term
  // whose zero-feature set is a superset is exact-dominated for every possible
  // union with other selected terms and can still be removed.
  std::map<std::vector<Word>, CoverTerm> by_coverage;
  std::map<std::vector<Word>, std::vector<CoverTerm>>
      alternatives_by_coverage;
  const bool optimize_unique_inverters =
      options.cover_third_objective ==
      RuleCoverThirdObjective::unique_inverters;
  std::size_t materialized_terms = 0;
  for (const auto& entry : unique_term_keys) {
    if ((materialized_terms++ & 255U) == 0U && Clock::now() >= deadline) {
      stats.status = "timeout";
      stats.reason =
          "optimizer deadline expired materializing term coverage";
      stats.pool_complete = false;
      stats.preprocessing_ms = elapsed_ms(preprocessing_start);
      finish_stats(&result, total_start);
      return result;
    }
    CoverTerm term;
    if (!make_cover_term(entry.first, positives, negatives,
                         candidate_position, &term)) {
      stats.pool_terms_unsafe += 1;
      continue;
    }
    if (!optimize_unique_inverters) {
      auto inserted = by_coverage.emplace(term.positive_cover, term);
      if (!inserted.second) {
        stats.pool_terms_coverage_deduplicated += 1;
        CoverTerm& kept = inserted.first->second;
        if (term.rule.terms.size() < kept.rule.terms.size() ||
            (term.rule.terms.size() == kept.rule.terms.size() &&
             term.rule.terms < kept.rule.terms)) {
          kept = std::move(term);
        }
      }
      continue;
    }

    std::vector<CoverTerm>& alternatives =
        alternatives_by_coverage[term.positive_cover];
    if (alternatives.empty()) {
      alternatives.push_back(std::move(term));
      continue;
    }
    const std::size_t shortest = alternatives.front().rule.terms.size();
    if (term.rule.terms.size() < shortest) {
      stats.pool_terms_coverage_deduplicated += alternatives.size();
      alternatives.clear();
      alternatives.push_back(std::move(term));
      continue;
    }
    if (term.rule.terms.size() > shortest) {
      stats.pool_terms_coverage_deduplicated += 1;
      continue;
    }

    const std::vector<std::size_t> term_inverters =
        negative_feature_set(term.rule);
    bool dominated = false;
    for (CoverTerm& existing : alternatives) {
      const std::vector<std::size_t> existing_inverters =
          negative_feature_set(existing.rule);
      if (!vector_subset(existing_inverters, term_inverters)) continue;
      dominated = true;
      stats.pool_terms_coverage_deduplicated += 1;
      if (existing_inverters == term_inverters &&
          term.rule.terms < existing.rule.terms) {
        existing = std::move(term);
      }
      break;
    }
    if (dominated) continue;

    for (auto it = alternatives.begin(); it != alternatives.end();) {
      const std::vector<std::size_t> existing_inverters =
          negative_feature_set(it->rule);
      if (vector_subset(term_inverters, existing_inverters)) {
        it = alternatives.erase(it);
        stats.pool_terms_coverage_deduplicated += 1;
      } else {
        ++it;
      }
    }
    alternatives.push_back(std::move(term));
  }
  if (stats.pool_terms_unsafe != 0) {
    stats.status = "verification_failed";
    stats.reason = "generated prime implicant matched a negative signature";
    stats.pool_complete = false;
    stats.preprocessing_ms = elapsed_ms(preprocessing_start);
    finish_stats(&result, total_start);
    return result;
  }

  std::vector<CoverTerm> terms;
  std::size_t retained_terms = 0;
  if (!optimize_unique_inverters) {
    terms.reserve(by_coverage.size());
    for (auto& entry : by_coverage) {
      if ((retained_terms++ & 1023U) == 0U && Clock::now() >= deadline) {
        stats.status = "timeout";
        stats.reason = "optimizer deadline expired finalizing the term pool";
        stats.pool_complete = false;
        stats.preprocessing_ms = elapsed_ms(preprocessing_start);
        finish_stats(&result, total_start);
        return result;
      }
      terms.push_back(std::move(entry.second));
    }
  } else {
    for (auto& entry : alternatives_by_coverage) {
      if (entry.second.size() > 1) {
        stats.pool_terms_coverage_alternatives += entry.second.size() - 1;
      }
      for (CoverTerm& alternative : entry.second) {
        if ((retained_terms++ & 1023U) == 0U &&
            Clock::now() >= deadline) {
          stats.status = "timeout";
          stats.reason =
              "optimizer deadline expired finalizing alternative terms";
          stats.pool_complete = false;
          stats.preprocessing_ms = elapsed_ms(preprocessing_start);
          finish_stats(&result, total_start);
          return result;
        }
        terms.push_back(std::move(alternative));
      }
    }
  }
  std::sort(terms.begin(), terms.end(), rule_key_less);
  stats.pool_terms_final = terms.size();
  stats.master_variables = terms.size();
  stats.preprocessing_ms = elapsed_ms(preprocessing_start);
  if (terms.empty()) {
    stats.status = "infeasible";
    stats.reason = "term filtering left an empty master";
    finish_stats(&result, total_start);
    return result;
  }

  const Clock::time_point solver_start = Clock::now();
  if (terms.size() >
      static_cast<std::size_t>(std::numeric_limits<HighsInt>::max())) {
    stats.status = "invalid";
    stats.reason = "set-cover term pool exceeds HiGHS index range";
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }
  std::vector<std::vector<HighsInt>> coverage_rows(positives.size());
  for (std::size_t term = 0; term < terms.size(); ++term) {
    if ((term & 1023U) == 0U && Clock::now() >= deadline) {
      stats.status = "timeout";
      stats.reason = "optimizer deadline expired building master incidence";
      stats.solver_ms = elapsed_ms(solver_start);
      finish_stats(&result, total_start);
      return result;
    }
    for (std::size_t word = 0;
         word < terms[term].positive_cover.size(); ++word) {
      Word covered = terms[term].positive_cover[word];
      while (covered != 0) {
        const std::size_t bit =
            static_cast<std::size_t>(__builtin_ctzll(covered));
        const std::size_t positive =
            word * PackedFeatureMatrix::kWordBits + bit;
        if (positive < coverage_rows.size()) {
          coverage_rows[positive].push_back(static_cast<HighsInt>(term));
        }
        covered &= covered - Word{1};
      }
    }
  }
  std::vector<double> rule_costs(terms.size(), 1.0);
  MasterPhaseResult lp1 = solve_master_phase(
      terms, coverage_rows, stats.clause_limit, rule_costs,
      false, false, 0, deadline,
      &stats.master_constraints, &stats.master_nonzeros);
  stats.solver_checks += lp1.invoked ? 1 : 0;
  assign_lp_phase(lp1, true, &stats);
  if (!lp1.optimal) {
    stats.status = phase_failure_status(lp1.status);
    stats.reason = lp1.error.empty()
                       ? "HiGHS LP1 did not reach optimality: " + lp1.status
                       : lp1.error;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }

  MasterPhaseResult mip1 = solve_master_phase(
      terms, coverage_rows, stats.clause_limit, rule_costs,
      true, false, 0, deadline, nullptr, nullptr);
  stats.solver_checks += mip1.invoked ? 1 : 0;
  assign_mip_phase(mip1, true, &stats);
  if (!mip1.optimal || mip1.column_values.size() != terms.size()) {
    stats.status = phase_failure_status(mip1.status);
    stats.reason = mip1.error.empty()
                       ? "HiGHS MIP1 did not reach optimality: " + mip1.status
                       : mip1.error;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }
  const double rounded_rules = std::round(mip1.objective);
  if (!std::isfinite(mip1.objective) ||
      std::fabs(mip1.objective - rounded_rules) > 1.0e-6 ||
      rounded_rules < 1.0 ||
      rounded_rules > static_cast<double>(stats.clause_limit) ||
      rounded_rules > static_cast<double>(terms.size())) {
    stats.status = "verification_failed";
    stats.reason = "HiGHS MIP1 returned an invalid integral objective";
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }
  const std::size_t optimal_rule_count =
      static_cast<std::size_t>(rounded_rules);
  stats.rules_optimal = true;

  std::vector<double> literal_costs;
  literal_costs.reserve(terms.size());
  for (const auto& term : terms) {
    literal_costs.push_back(static_cast<double>(term.rule.terms.size()));
  }
  MasterPhaseResult lp2 = solve_master_phase(
      terms, coverage_rows, stats.clause_limit, literal_costs,
      false, true, optimal_rule_count, deadline,
      &stats.master_constraints, &stats.master_nonzeros);
  stats.solver_checks += lp2.invoked ? 1 : 0;
  assign_lp_phase(lp2, false, &stats);
  if (!lp2.optimal) {
    stats.status = phase_failure_status(lp2.status);
    stats.reason = lp2.error.empty()
                       ? "HiGHS LP2 did not reach optimality: " + lp2.status
                       : lp2.error;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }

  MasterPhaseResult mip2 = solve_master_phase(
      terms, coverage_rows, stats.clause_limit, literal_costs,
      true, true, optimal_rule_count, deadline, nullptr, nullptr);
  stats.solver_checks += mip2.invoked ? 1 : 0;
  assign_mip_phase(mip2, false, &stats);
  if (!mip2.optimal || mip2.column_values.size() != terms.size()) {
    stats.status = phase_failure_status(mip2.status);
    stats.reason = mip2.error.empty()
                       ? "HiGHS MIP2 did not reach optimality: " + mip2.status
                       : mip2.error;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }
  const double rounded_literals = std::round(mip2.objective);
  const double maximum_literals =
      static_cast<double>(optimal_rule_count) *
      static_cast<double>(stats.literal_limit);
  if (!std::isfinite(mip2.objective) ||
      std::fabs(mip2.objective - rounded_literals) > 1.0e-6 ||
      rounded_literals < static_cast<double>(optimal_rule_count) ||
      rounded_literals > maximum_literals ||
      static_cast<long double>(rounded_literals) >
          static_cast<long double>(
              std::numeric_limits<std::size_t>::max())) {
    stats.status = "verification_failed";
    stats.reason = "HiGHS MIP2 returned an invalid integral objective";
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }
  const std::size_t optimal_literal_count =
      static_cast<std::size_t>(rounded_literals);
  stats.literals_optimal = true;

  DecisionTreeModel mip2_model;
  std::set<std::size_t> mip2_selected_inverters;
  if (!extract_term_model(terms, mip2.column_values, optimal_rule_count,
                          optimal_literal_count, &mip2_model,
                          &stats.reason, &mip2_selected_inverters)) {
    stats.status = "verification_failed";
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }

  const VerificationStatus mip2_verification = verify_candidate_model(
      mip2_model, signature_result.patterns, candidate_position, features,
      labels, deadline, &stats, &stats.reason);
  if (mip2_verification != VerificationStatus::verified) {
    stats.status = mip2_verification == VerificationStatus::timeout
                       ? "timeout"
                       : "verification_failed";
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }

  if (!optimize_unique_inverters) {
    result.model = std::move(mip2_model);
    stats.accepted = true;
    stats.optimal = stats.pool_complete && stats.rules_optimal &&
                    stats.literals_optimal;
    stats.status = "accepted";
    stats.reason.clear();
    stats.rules_after = result.model.rules.size();
    stats.literals_after = count_literals(result.model);
    stats.unique_inverters_after = mip2_selected_inverters.size();
    stats.rounds_used = 1;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }

  // MIP2 has now been independently checked against both the projected
  // signatures and every packed row.  If the optional hardware phase runs
  // out of the shared budget, this is therefore a safe accepted fallback,
  // but no phase-3 or overall-optimality claim is made.
  auto accept_verified_mip2_after_phase3_timeout =
      [&](const std::string& reason) -> RuleOptimizationResult {
    result.model = mip2_model;
    stats.accepted = true;
    stats.verified = true;
    stats.optimal = false;
    stats.hardware_optimal = false;
    stats.phase3_timeout_fallback = true;
    stats.status = "accepted_phase3_timeout";
    stats.reason = reason;
    stats.verification_false_positive = 0;
    stats.verification_false_negative = 0;
    stats.rules_after = result.model.rules.size();
    stats.literals_after = count_literals(result.model);
    stats.unique_inverters_after = mip2_selected_inverters.size();
    stats.rounds_used = 1;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  };

  if (force_phase3_timeout_after_verified_mip2.exchange(
          false, std::memory_order_relaxed)) {
    return accept_verified_mip2_after_phase3_timeout(
        "test-injected timeout after verified HiGHS MIP2");
  }

  InverterMasterData inverter_data;
  if (!build_inverter_master_data(terms, deadline, &inverter_data)) {
    if (Clock::now() >= deadline) {
      return accept_verified_mip2_after_phase3_timeout(
          "shared optimizer deadline expired building phase-3 data");
    }
    stats.status = "unknown";
    stats.reason = "failed to build the phase-3 inverter incidence";
    stats.verified = false;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }
  stats.inverter_features = inverter_data.features.size();

  MasterPhaseResult lp3 = solve_inverter_phase(
      terms, coverage_rows, inverter_data, stats.clause_limit,
      optimal_rule_count, optimal_literal_count, false, deadline,
      &stats.master_variables, &stats.master_constraints,
      &stats.master_nonzeros, &stats.inverter_link_constraints);
  stats.solver_checks += lp3.invoked ? 1 : 0;
  assign_lp3_phase(lp3, &stats);
  if (!lp3.optimal) {
    if (phase_failure_status(lp3.status) == "timeout") {
      return accept_verified_mip2_after_phase3_timeout(
          lp3.error.empty() ? "HiGHS LP3 reached the shared deadline"
                            : lp3.error);
    }
    stats.status = phase_failure_status(lp3.status);
    stats.reason = lp3.error.empty()
                       ? "HiGHS LP3 did not reach optimality: " + lp3.status
                       : lp3.error;
    stats.verified = false;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }
  if (!std::isfinite(lp3.objective) || lp3.objective < -1.0e-7 ||
      lp3.objective >
          static_cast<double>(inverter_data.features.size()) + 1.0e-7) {
    stats.status = "verification_failed";
    stats.reason = "HiGHS LP3 returned an invalid objective";
    stats.verified = false;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }
  if (Clock::now() >= deadline) {
    return accept_verified_mip2_after_phase3_timeout(
        "shared optimizer deadline expired after HiGHS LP3");
  }

  MasterPhaseResult mip3 = solve_inverter_phase(
      terms, coverage_rows, inverter_data, stats.clause_limit,
      optimal_rule_count, optimal_literal_count, true, deadline,
      &stats.master_variables, &stats.master_constraints,
      &stats.master_nonzeros, &stats.inverter_link_constraints);
  stats.solver_checks += mip3.invoked ? 1 : 0;
  assign_mip3_phase(mip3, &stats);
  if (!mip3.optimal) {
    if (phase_failure_status(mip3.status) == "timeout") {
      return accept_verified_mip2_after_phase3_timeout(
          mip3.error.empty() ? "HiGHS MIP3 reached the shared deadline"
                             : mip3.error);
    }
    stats.status = phase_failure_status(mip3.status);
    stats.reason = mip3.error.empty()
                       ? "HiGHS MIP3 did not reach optimality: " + mip3.status
                       : mip3.error;
    stats.verified = false;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }
  if (Clock::now() >= deadline) {
    return accept_verified_mip2_after_phase3_timeout(
        "shared optimizer deadline expired after HiGHS MIP3");
  }

  const double rounded_inverters = std::round(mip3.objective);
  const std::size_t phase3_variable_count =
      terms.size() + inverter_data.features.size();
  if (!std::isfinite(mip3.objective) ||
      std::fabs(mip3.objective - rounded_inverters) > 1.0e-6 ||
      rounded_inverters < 0.0 ||
      rounded_inverters >
          static_cast<double>(inverter_data.features.size()) ||
      mip3.column_values.size() != phase3_variable_count) {
    stats.status = "verification_failed";
    stats.reason = "HiGHS MIP3 returned an invalid integral solution";
    stats.verified = false;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }

  DecisionTreeModel candidate_model;
  std::set<std::size_t> selected_inverters;
  if (!extract_term_model(terms, mip3.column_values, optimal_rule_count,
                          optimal_literal_count, &candidate_model,
                          &stats.reason, &selected_inverters)) {
    stats.status = "verification_failed";
    stats.verified = false;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }

  if (Clock::now() >= deadline) {
    return accept_verified_mip2_after_phase3_timeout(
        "shared optimizer deadline expired extracting the MIP3 model");
  }
  bool valid_inverter_columns = true;
  for (std::size_t inverter = 0;
       inverter < inverter_data.features.size(); ++inverter) {
    if ((inverter & 1023U) == 0U && Clock::now() >= deadline) {
      return accept_verified_mip2_after_phase3_timeout(
          "shared optimizer deadline expired verifying MIP3 inverter columns");
    }
    const double value = mip3.column_values[terms.size() + inverter];
    if (!std::isfinite(value) ||
        std::fabs(value - std::round(value)) > 1.0e-6 ||
        value < -1.0e-6 || value > 1.0 + 1.0e-6 ||
        (value > 0.5) !=
            (selected_inverters.count(inverter_data.features[inverter]) != 0)) {
      valid_inverter_columns = false;
      break;
    }
  }
  if (Clock::now() >= deadline) {
    return accept_verified_mip2_after_phase3_timeout(
        "shared optimizer deadline expired after MIP3 inverter verification");
  }
  if (!valid_inverter_columns ||
      selected_inverters.size() !=
          static_cast<std::size_t>(rounded_inverters)) {
    stats.status = "verification_failed";
    stats.reason = "MIP3 inverter variables violate the OR objective";
    stats.verified = false;
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }

  const VerificationStatus mip3_verification = verify_candidate_model(
      candidate_model, signature_result.patterns, candidate_position,
      features, labels, deadline, &stats, &stats.reason);
  if (mip3_verification == VerificationStatus::timeout) {
    return accept_verified_mip2_after_phase3_timeout(stats.reason);
  }
  if (mip3_verification != VerificationStatus::verified) {
    stats.status = "verification_failed";
    stats.solver_ms = elapsed_ms(solver_start);
    finish_stats(&result, total_start);
    return result;
  }

  result.model = std::move(candidate_model);
  stats.accepted = true;
  stats.hardware_optimal = true;
  stats.optimal = stats.pool_complete && stats.rules_optimal &&
                  stats.literals_optimal && stats.hardware_optimal;
  stats.status = "accepted";
  stats.reason.clear();
  stats.rules_after = result.model.rules.size();
  stats.literals_after = count_literals(result.model);
  stats.unique_inverters_after = selected_inverters.size();
  stats.rounds_used = 1;
  stats.solver_ms = elapsed_ms(solver_start);
  finish_stats(&result, total_start);
  return result;
  } catch (const std::exception& exception) {
    result.model = baseline_model;
    stats.accepted = false;
    stats.optimal = false;
    stats.verified = false;
    stats.pool_complete = false;
    stats.rules_optimal = false;
    stats.literals_optimal = false;
    stats.hardware_optimal = false;
    stats.phase3_timeout_fallback = false;
    stats.rules_after = stats.rules_before;
    stats.literals_after = stats.literals_before;
    stats.unique_inverters_after = stats.unique_inverters_before;
    stats.status = "unknown";
    stats.reason = std::string("set-cover optimizer exception: ") +
                   exception.what();
    finish_stats(&result, total_start);
    return result;
  }
#endif  // USE_HIGHS
}
