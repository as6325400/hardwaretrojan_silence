#include "candidate_selector.hpp"

bool build_candidates(const PatternStats& stats,
                      double p1_trigger_threshold,
                      double p1_notrigger_threshold,
                      bool no_filter,
                      std::vector<CandidateInfo>* out,
                      std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out) {
    if (error) {
      *error = "Candidate output pointer is null";
    }
    return false;
  }
  out->clear();

  if (stats.trigger_patterns_total == 0 || stats.notrigger_patterns_total == 0) {
    if (error) {
      *error = "Not enough trigger/notrigger patterns to build candidates.";
    }
    return false;
  }

  out->reserve(stats.gate_indices.size());
  for (std::size_t g = 0; g < stats.gate_indices.size(); ++g) {
    const double p1_trigger =
        static_cast<double>(stats.ones_trigger[g]) /
        static_cast<double>(stats.trigger_patterns_total);
    const double p1_notrigger =
        static_cast<double>(stats.ones_notrigger[g]) /
        static_cast<double>(stats.notrigger_patterns_total);
    const bool pass_filter =
        no_filter ||
        (p1_trigger >= p1_trigger_threshold && p1_notrigger <= p1_notrigger_threshold);
    if (pass_filter) {
      out->push_back(CandidateInfo{stats.gate_indices[g], p1_trigger, p1_notrigger});
    }
  }

  if (out->empty()) {
    if (error) {
      *error = "No candidate nets found.";
    }
    return false;
  }

  return true;
}

std::vector<int> candidate_gate_indices(const std::vector<CandidateInfo>& candidates) {
  std::vector<int> indices;
  indices.reserve(candidates.size());
  for (const auto& cand : candidates) {
    indices.push_back(cand.gate_idx);
  }
  return indices;
}
