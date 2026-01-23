#pragma once

#include <string>
#include <vector>

#include "pattern_sampler.hpp"

struct CandidateInfo {
  int gate_idx = -1;
  double p1_trigger = 0.0;
  double p1_notrigger = 0.0;
};

bool build_candidates(const PatternStats& stats,
                      double p1_trigger_threshold,
                      double p1_notrigger_threshold,
                      bool no_filter,
                      std::vector<CandidateInfo>* out,
                      std::string* error); // Build candidate nets from stats and thresholds.
std::vector<int> candidate_gate_indices(const std::vector<CandidateInfo>& candidates); // Extract gate indices from candidates.
