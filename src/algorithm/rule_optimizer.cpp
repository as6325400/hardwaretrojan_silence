#include "rule_optimizer.hpp"

#include <z3++.h>
#include <z3_optimization.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using Word = PackedFeatureMatrix::word_t;

double elapsed_ms(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start)
      .count();
}

std::size_t count_literals(const DecisionTreeModel& model) {
  std::size_t count = 0;
  for (const auto& rule : model.rules) {
    count += rule.terms.size();
  }
  return count;
}

void finish_stats(RuleOptimizationResult* result,
                  Clock::time_point total_start) {
  if (!result) return;
  result->stats.total_ms = elapsed_ms(total_start);
}

bool validate_input(const PackedFeatureMatrix& features,
                    const std::vector<int>& labels,
                    const std::vector<std::size_t>& candidates,
                    const DecisionTreeModel& baseline,
                    const RuleOptimizerOptions& options,
                    std::string* reason) {
  if (features.row_count == 0) {
    *reason = "empty feature matrix";
    return false;
  }
  if (features.row_count != labels.size()) {
    *reason = "feature row count does not match labels";
    return false;
  }
  if (features.feature_count == 0 || features.packed_rows() == 0) {
    *reason = "empty feature set";
    return false;
  }
  if (features.data.size() !=
      features.feature_count * features.packed_rows()) {
    *reason = "packed feature matrix has an invalid data size";
    return false;
  }
  if (candidates.empty()) {
    *reason = "raw decision-tree candidate union is empty";
    return false;
  }
  for (std::size_t f : candidates) {
    if (f >= features.feature_count) {
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
  if (options.max_rounds == 0) {
    *reason = "max_rounds must be positive";
    return false;
  }
  if (options.counterexample_batch_size == 0) {
    *reason = "counterexample_batch_size must be positive";
    return false;
  }
  return true;
}

std::vector<Word> active_feature_signature(
    const PackedFeatureMatrix& features,
    std::size_t feature) {
  const std::size_t words =
      (features.row_count + PackedFeatureMatrix::kWordBits - 1) /
      PackedFeatureMatrix::kWordBits;
  std::vector<Word> signature(words, Word{0});
  const Word* col = features.col_ptr(feature);
  for (std::size_t w = 0; w < words; ++w) {
    signature[w] = col[w];
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

  std::map<std::vector<Word>, std::size_t> by_signature;
  for (std::size_t feature : sorted) {
    std::vector<Word> signature =
        active_feature_signature(features, feature);
    by_signature.emplace(std::move(signature), feature);
  }

  std::vector<std::size_t> unique;
  unique.reserve(by_signature.size());
  for (const auto& entry : by_signature) {
    unique.push_back(entry.second);
  }
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
  const std::size_t word_count =
      (candidates.size() + PackedFeatureMatrix::kWordBits - 1) /
      PackedFeatureMatrix::kWordBits;
  std::vector<Word> bits(word_count, Word{0});
  for (std::size_t pos = 0; pos < candidates.size(); ++pos) {
    if (features.feature_value(row, candidates[pos]) != 0) {
      bits[pos / PackedFeatureMatrix::kWordBits] |=
          Word{1} << (pos % PackedFeatureMatrix::kWordBits);
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
      if (aggregate.label != labels[row]) {
        aggregate.conflict = true;
      }
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

int signature_value(const PatternSignature& pattern, std::size_t feature_pos) {
  return static_cast<int>(
      (pattern.bits[feature_pos / PackedFeatureMatrix::kWordBits] >>
       (feature_pos % PackedFeatureMatrix::kWordBits)) &
      Word{1});
}

bool rule_matches_signature(
    const DecisionTreeRule& rule,
    const PatternSignature& pattern,
    const std::map<std::size_t, std::size_t>& candidate_position) {
  for (const auto& term : rule.terms) {
    auto it = candidate_position.find(term.first);
    if (it == candidate_position.end() ||
        signature_value(pattern, it->second) != term.second) {
      return false;
    }
  }
  return true;
}

bool model_matches_signature(
    const DecisionTreeModel& model,
    const PatternSignature& pattern,
    const std::map<std::size_t, std::size_t>& candidate_position) {
  for (const auto& rule : model.rules) {
    if (rule_matches_signature(rule, pattern, candidate_position)) {
      return true;
    }
  }
  return false;
}

bool model_matches_row(const DecisionTreeModel& model,
                       const PackedFeatureMatrix& features,
                       std::size_t row) {
  for (const auto& rule : model.rules) {
    bool match = true;
    for (const auto& term : rule.terms) {
      if (term.first >= features.feature_count ||
          features.feature_value(row, term.first) != term.second) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

struct LiteralVars {
  z3::expr zero;
  z3::expr one;

  LiteralVars(z3::expr zero_var, z3::expr one_var)
      : zero(std::move(zero_var)), one(std::move(one_var)) {}
};

z3::expr bool_sum(z3::context& ctx, const std::vector<z3::expr>& vars) {
  if (vars.empty()) return ctx.int_val(0);
  z3::expr_vector terms(ctx);
  for (const auto& var : vars) {
    terms.push_back(z3::ite(var, ctx.int_val(1), ctx.int_val(0)));
  }
  return z3::sum(terms);
}

z3::expr clause_match_expr(
    z3::context& ctx,
    const PatternSignature& pattern,
    std::size_t clause,
    const std::vector<z3::expr>& active,
    const std::vector<std::vector<LiteralVars>>& selected) {
  z3::expr match = active[clause];
  for (std::size_t feature = 0; feature < selected[clause].size(); ++feature) {
    const int value = signature_value(pattern, feature);
    // A clause fails iff it selected the polarity opposite to this sample.
    match = match &&
            !(value == 0 ? selected[clause][feature].one
                         : selected[clause][feature].zero);
  }
  (void)ctx;
  return match;
}

void add_signature_constraint(
    z3::context& ctx,
    z3::optimize& opt,
    const PatternSignature& pattern,
    const std::vector<z3::expr>& active,
    const std::vector<std::vector<LiteralVars>>& selected) {
  z3::expr_vector matches(ctx);
  for (std::size_t clause = 0; clause < active.size(); ++clause) {
    matches.push_back(clause_match_expr(
        ctx, pattern, clause, active, selected));
  }
  if (pattern.label == 1) {
    opt.add(z3::mk_or(matches));
  } else {
    for (unsigned i = 0; i < matches.size(); ++i) {
      opt.add(!matches[i]);
    }
  }
}

DecisionTreeModel extract_model(
    const z3::model& z3_model,
    const std::vector<std::size_t>& candidates,
    const std::vector<z3::expr>& active,
    const std::vector<std::vector<LiteralVars>>& selected) {
  DecisionTreeModel model;
  for (std::size_t clause = 0; clause < active.size(); ++clause) {
    if (!z3_model.eval(active[clause], true).is_true()) continue;
    DecisionTreeRule rule;
    for (std::size_t feature = 0; feature < candidates.size(); ++feature) {
      if (z3_model.eval(selected[clause][feature].zero, true).is_true()) {
        rule.terms.push_back({candidates[feature], 0});
      } else if (z3_model.eval(selected[clause][feature].one, true)
                     .is_true()) {
        rule.terms.push_back({candidates[feature], 1});
      }
    }
    std::sort(rule.terms.begin(), rule.terms.end());
    model.max_depth_used =
        std::max(model.max_depth_used, rule.terms.size());
    model.rules.push_back(std::move(rule));
  }
  std::sort(model.rules.begin(), model.rules.end(),
            [](const DecisionTreeRule& lhs, const DecisionTreeRule& rhs) {
              return lhs.terms < rhs.terms;
            });
  model.leaf_count = model.rules.size();
  return model;
}

std::string optimize_unknown_reason(z3::context& ctx, z3::optimize& opt) {
  const char* reason = Z3_optimize_get_reason_unknown(ctx, opt);
  return reason ? std::string(reason) : std::string("unknown");
}

}  // namespace

RuleOptimizationResult optimize_dnf_rules_z3_pb(
    const PackedFeatureMatrix& features,
    const std::vector<int>& labels,
    const std::vector<std::size_t>& raw_dt_candidate_features,
    const DecisionTreeModel& baseline_model,
    const RuleOptimizerOptions& options) {
  const Clock::time_point total_start = Clock::now();
  RuleOptimizationResult result;
  result.model = baseline_model;
  RuleOptimizerStats& stats = result.stats;
  stats.solver_backend = "z3-pb";
  stats.backend_available = true;
  stats.solver_version = Z3_get_full_version();
  stats.input_rows = features.row_count;
  stats.raw_candidate_features = raw_dt_candidate_features.size();
  stats.rules_before = baseline_model.rules.size();
  stats.literals_before = count_literals(baseline_model);
  stats.rules_after = stats.rules_before;
  stats.literals_after = stats.literals_before;

  if (!validate_input(features, labels, raw_dt_candidate_features,
                      baseline_model, options, &stats.reason)) {
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

  const Clock::time_point preprocessing_start = Clock::now();
  std::vector<std::size_t> candidates = deduplicate_candidate_features(
      features, raw_dt_candidate_features);
  stats.unique_candidate_features = candidates.size();
  stats.duplicate_candidate_features =
      raw_dt_candidate_features.size() - stats.unique_candidate_features;
  stats.candidate_literals = stats.unique_candidate_features * 2;
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

  const std::vector<PatternSignature>& patterns = signature_result.patterns;
  for (const auto& pattern : patterns) {
    if (pattern.label == 1) {
      stats.positive_signatures += 1;
    } else {
      stats.negative_signatures += 1;
    }
  }
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
  stats.preprocessing_ms = elapsed_ms(preprocessing_start);

  if (options.timeout_ms == 0) {
    stats.status = "timeout";
    stats.reason = "solver wall-clock budget is zero";
    finish_stats(&result, total_start);
    return result;
  }

  const Clock::time_point solver_start = Clock::now();
  const Clock::time_point deadline =
      solver_start + std::chrono::milliseconds(options.timeout_ms);

  try {
  z3::context ctx;
  z3::optimize opt(ctx);

  std::vector<z3::expr> active;
  std::vector<std::vector<LiteralVars>> selected;
  active.reserve(stats.clause_limit);
  selected.reserve(stats.clause_limit);
  for (std::size_t clause = 0; clause < stats.clause_limit; ++clause) {
    active.push_back(ctx.bool_const(
        ("rule_pb_active_" + std::to_string(clause)).c_str()));
    selected.emplace_back();
    selected.back().reserve(candidates.size());
    for (std::size_t feature = 0; feature < candidates.size(); ++feature) {
      const std::string prefix = "rule_pb_c" + std::to_string(clause) +
                                 "_f" + std::to_string(feature) + "_";
      selected.back().emplace_back(
          ctx.bool_const((prefix + "v0").c_str()),
          ctx.bool_const((prefix + "v1").c_str()));
    }
  }

  std::vector<z3::expr> all_selected;
  all_selected.reserve(stats.clause_limit * candidates.size() * 2);
  for (std::size_t clause = 0; clause < stats.clause_limit; ++clause) {
    std::vector<z3::expr> clause_selected;
    clause_selected.reserve(candidates.size() * 2);
    for (std::size_t feature = 0; feature < candidates.size(); ++feature) {
      const z3::expr& zero = selected[clause][feature].zero;
      const z3::expr& one = selected[clause][feature].one;
      opt.add(!(zero && one));
      opt.add(z3::implies(zero, active[clause]));
      opt.add(z3::implies(one, active[clause]));
      clause_selected.push_back(zero);
      clause_selected.push_back(one);
      all_selected.push_back(zero);
      all_selected.push_back(one);
    }
    z3::expr clause_sum = bool_sum(ctx, clause_selected);
    opt.add(z3::implies(active[clause], clause_sum >= 1));
    opt.add(clause_sum <=
            static_cast<int>(std::min<std::size_t>(
                stats.literal_limit,
                static_cast<std::size_t>(std::numeric_limits<int>::max()))));
    if (clause > 0) {
      opt.add(z3::implies(active[clause], active[clause - 1]));
    }
  }

  const z3::optimize::handle clause_objective =
      opt.minimize(bool_sum(ctx, active));
  const z3::optimize::handle literal_objective =
      opt.minimize(bool_sum(ctx, all_selected));
  (void)clause_objective;
  (void)literal_objective;

  // Deterministic, stratified seed constraints.  Pattern signatures are
  // stored in lexicographic order, so no RNG or hash iteration affects them.
  std::vector<char> constrained(patterns.size(), 0);
  std::size_t seeded_pos = 0;
  std::size_t seeded_neg = 0;
  for (std::size_t i = 0; i < patterns.size(); ++i) {
    const int label = patterns[i].label;
    std::size_t& seeded = label == 1 ? seeded_pos : seeded_neg;
    if (seeded >= options.counterexample_batch_size) continue;
    add_signature_constraint(ctx, opt, patterns[i], active, selected);
    constrained[i] = 1;
    seeded += 1;
    stats.initial_constraints += 1;
    stats.constraints_added += 1;
  }

  std::map<std::size_t, std::size_t> candidate_position;
  for (std::size_t pos = 0; pos < candidates.size(); ++pos) {
    candidate_position[candidates[pos]] = pos;
  }

  for (std::size_t round = 0; round < options.max_rounds; ++round) {
    const Clock::time_point now = Clock::now();
    if (now >= deadline) {
      stats.status = "timeout";
      stats.reason = "shared solver wall-clock deadline expired";
      break;
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - now).count();
    z3::params params(ctx);
    params.set("priority", "lex");
    params.set("timeout", static_cast<unsigned>(std::max<long long>(1, std::min<long long>(
        remaining, std::numeric_limits<unsigned>::max()))));
    opt.set(params);

    stats.solver_checks += 1;
    stats.rounds_used = round + 1;
    const z3::check_result check = opt.check();
    if (check == z3::unsat) {
      stats.status = "infeasible";
      stats.reason = "bounded DNF constraints are unsatisfiable";
      break;
    }
    if (check == z3::unknown) {
      stats.reason = optimize_unknown_reason(ctx, opt);
      stats.status = stats.reason.find("timeout") != std::string::npos ||
                             Clock::now() >= deadline
                         ? "timeout"
                         : "unknown";
      break;
    }

    const z3::model z3_model = opt.get_model();
    DecisionTreeModel candidate_model =
        extract_model(z3_model, candidates, active, selected);

    std::vector<std::size_t> false_negative;
    std::vector<std::size_t> false_positive;
    bool scan_timed_out = false;
    for (std::size_t i = 0; i < patterns.size(); ++i) {
      if ((i & 1023U) == 0U && Clock::now() >= deadline) {
        scan_timed_out = true;
        break;
      }
      const bool prediction = model_matches_signature(
          candidate_model, patterns[i], candidate_position);
      if (prediction == (patterns[i].label != 0)) continue;
      if (patterns[i].label == 1) {
        false_negative.push_back(i);
      } else {
        false_positive.push_back(i);
      }
    }
    if (scan_timed_out) {
      stats.status = "timeout";
      stats.reason = "solver deadline expired during signature verification";
      break;
    }

    if (false_negative.empty() && false_positive.empty()) {
      std::size_t full_fp = 0;
      std::size_t full_fn = 0;
      for (std::size_t row = 0; row < features.row_count; ++row) {
        if ((row & 1023U) == 0U && Clock::now() >= deadline) {
          scan_timed_out = true;
          break;
        }
        const bool prediction = model_matches_row(
            candidate_model, features, row);
        if (prediction && labels[row] == 0) full_fp += 1;
        if (!prediction && labels[row] == 1) full_fn += 1;
      }
      if (scan_timed_out) {
        stats.status = "timeout";
        stats.reason = "solver deadline expired during full-row verification";
        break;
      }
      stats.verification_false_positive = full_fp;
      stats.verification_false_negative = full_fn;
      stats.verified = full_fp == 0 && full_fn == 0;
      if (!stats.verified) {
        stats.status = "verification_failed";
        stats.reason = "optimized model failed full packed-matrix verification";
        break;
      }

      result.model = std::move(candidate_model);
      stats.accepted = true;
      stats.optimal = true;
      stats.status = "accepted";
      stats.reason.clear();
      stats.rules_after = result.model.rules.size();
      stats.literals_after = count_literals(result.model);
      break;
    }

    // Add at most N genuinely violated signatures, alternating classes so a
    // large false-positive set cannot starve false-negative refinement.
    std::size_t fn_pos = 0;
    std::size_t fp_pos = 0;
    std::size_t added = 0;
    bool take_positive = true;
    while (added < options.counterexample_batch_size &&
           (fn_pos < false_negative.size() || fp_pos < false_positive.size())) {
      std::size_t index = patterns.size();
      if (take_positive && fn_pos < false_negative.size()) {
        index = false_negative[fn_pos++];
      } else if (!take_positive && fp_pos < false_positive.size()) {
        index = false_positive[fp_pos++];
      } else if (fn_pos < false_negative.size()) {
        index = false_negative[fn_pos++];
      } else if (fp_pos < false_positive.size()) {
        index = false_positive[fp_pos++];
      }
      take_positive = !take_positive;
      if (index >= patterns.size() || constrained[index]) continue;
      add_signature_constraint(ctx, opt, patterns[index], active, selected);
      constrained[index] = 1;
      stats.constraints_added += 1;
      stats.counterexamples_added += 1;
      added += 1;
    }
    if (added == 0) {
      stats.status = "verification_failed";
      stats.reason = "misclassified signatures could not be refined";
      break;
    }
  }

  } catch (const z3::exception& exception) {
    result.model = baseline_model;
    stats.accepted = false;
    stats.optimal = false;
    stats.verified = false;
    stats.status = "unknown";
    stats.reason = std::string("Z3 exception: ") + exception.what();
    stats.rules_after = stats.rules_before;
    stats.literals_after = stats.literals_before;
  } catch (const std::exception& exception) {
    result.model = baseline_model;
    stats.accepted = false;
    stats.optimal = false;
    stats.verified = false;
    stats.status = "invalid";
    stats.reason = std::string("rule optimizer exception: ") + exception.what();
    stats.rules_after = stats.rules_before;
    stats.literals_after = stats.literals_before;
  }

  if (!stats.accepted && stats.status == "invalid" && stats.reason.empty()) {
    stats.status = "max_rounds";
    stats.reason = "CEGIS reached max_rounds before full verification";
  }
  stats.solver_ms = elapsed_ms(solver_start);
  finish_stats(&result, total_start);
  return result;
}
