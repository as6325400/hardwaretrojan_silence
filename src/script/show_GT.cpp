#include <iostream>
#include <string>

#include "../io/parallel_collect_log.hpp"

int main(int argc, char** argv) {
  std::string path =
      (argc > 1) ? argv[1] : "groundtruth/c880_trojan0_error_patterns.json";

  try {
    ParallelCollectLog log(path);
    Summary summary = log.summary();

    std::cout << "benchmark: "
              << (summary.benchmark ? *summary.benchmark : "unknown") << "\n";
    if (summary.round) {
      std::cout << "round: " << *summary.round << "\n";
    } else {
      std::cout << "round: unknown\n";
    }
    if (summary.time_seconds) {
      std::cout << "time_seconds: " << *summary.time_seconds << "\n";
    } else {
      std::cout << "time_seconds: unknown\n";
    }
    std::cout << "pattern_count: " << summary.pattern_count << "\n";
    std::cout << "unique_patterns: " << summary.unique_patterns << "\n";
    std::cout << "unique_errors: " << summary.unique_errors << "\n";
    std::cout << "pi_count: " << summary.pi_count << "\n";
    std::cout << "outputs: " << summary.output_counts.size() << "\n";

    auto bits = log.get_pattern_bits(0);
    if (bits) {
      std::cout << "first pattern_bits: " << *bits << "\n";
      auto inputs = log.get_pattern_inputs(0);
      std::cout << "first inputs: " << inputs.size() << " signals\n";
    }
  } catch (const std::exception& e) {
    std::cerr << "Error reading log: " << e.what() << "\n";
    std::cerr << "Usage: " << argv[0]
              << " [path/to/error_patterns.json]\n";
    return 1;
  }

  return 0;
}
