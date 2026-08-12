#include <cstdlib>
#include <iostream>
#include <string>

#include "../algorithm/dac25_rectification.hpp"
#include "../io/bench_parser.hpp"

int main(int argc, char** argv) {
  if (argc < 3 || argc > 6) {
    std::cerr << "usage: " << argv[0]
              << " <golden.bench> <trojan.bench> [candidate-limit]"
                 " [max-targets] [timeout-ms]\n";
    return EXIT_FAILURE;
  }
  circuit golden;
  circuit trojan;
  std::string error;
  if (!bench_io::parse_bench_file(argv[1], golden, &error)) {
    std::cerr << "golden parse error: " << error << '\n';
    return EXIT_FAILURE;
  }
  if (!bench_io::parse_bench_file(argv[2], trojan, &error)) {
    std::cerr << "Trojan parse error: " << error << '\n';
    return EXIT_FAILURE;
  }
  Dac25PlanOptions options;
  try {
    if (argc >= 4) options.candidate_limit = std::stoull(argv[3]);
    if (argc >= 5) options.max_targets = std::stoull(argv[4]);
    if (argc >= 6) options.timeout_ms = std::stoull(argv[5]);
  } catch (const std::exception& e) {
    std::cerr << "invalid numeric option: " << e.what() << '\n';
    return EXIT_FAILURE;
  }
  const Dac25PlanResult result =
      plan_dac25_rectification(golden, trojan, options);
  std::cout << "dac25_plan status " << dac25_plan_status_name(result.status)
            << " raw_candidates " << result.raw_candidates
            << " retained_candidates " << result.candidates.size()
            << " sets_checked " << result.sets_checked
            << " feasible_sets " << result.feasible_sets
            << " selected_targets " << result.selected_targets.size()
            << " solver_ms " << result.solver_ms
            << " total_ms " << result.total_ms << '\n';
  std::cout << "reason " << result.reason << '\n';
  for (std::size_t i = 0; i < result.candidates.size(); ++i) {
    const auto& candidate = result.candidates[i];
    std::cout << "candidate " << i << " node " << candidate.node
              << " name " << candidate.name
              << " score " << candidate.score
              << " missing " << candidate.absent_from_golden
              << " structural_diff " << candidate.structurally_different
              << " po " << candidate.primary_output
              << " distance " << candidate.distance_to_observed_mismatch
              << " fanout " << candidate.fanout << '\n';
  }
  for (int target : result.selected_targets) {
    std::cout << "selected node " << target << " name "
              << trojan.node_name(target) << '\n';
  }
  return result.status == Dac25PlanStatus::selected ? EXIT_SUCCESS
                                                    : EXIT_FAILURE;
}
