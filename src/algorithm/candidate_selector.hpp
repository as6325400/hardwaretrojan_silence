#pragma once

#include <string>
#include <vector>

#include "pattern_sampler.hpp"

struct CandidateInfo {
  int gate_idx = -1;
};

bool build_candidates(const PatternStats& stats,
                      std::vector<CandidateInfo>* out,
                      std::string* error); // Build candidate nets from stats (all gates).
std::vector<int> candidate_gate_indices(const std::vector<CandidateInfo>& candidates); // Extract gate indices from candidates.
