#include "pattern_sampler.hpp"

double compute_trojan_rate(const PatternStats& stats) {
  if (stats.total_patterns == 0) {
    return 0.0;
  }
  return static_cast<double>(stats.trigger_patterns_total) /
         static_cast<double>(stats.total_patterns);
}
