#include "candidate_selector.hpp"

bool build_candidates(const PatternStats& stats,
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
    out->push_back(CandidateInfo{stats.gate_indices[g]});
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
