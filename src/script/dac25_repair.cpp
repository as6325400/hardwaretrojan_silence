#include <cstdlib>
#include <iostream>
#include <string>

#include "../algorithm/dac25_repair.hpp"
#include "../io/bench_parser.hpp"

int main(int argc, char** argv) {
  if (argc < 5 || argc > 8) {
    std::cerr << "usage: " << argv[0]
              << " <golden.bench> <trojan.bench> <abc> <output.bench>"
                 " [candidate-limit] [max-targets] [max-sets]\n";
    return EXIT_FAILURE;
  }
  circuit golden;
  circuit trojan;
  std::string error;
  if (!bench_io::parse_bench_file(argv[1], golden, &error) ||
      !bench_io::parse_bench_file(argv[2], trojan, &error)) {
    std::cerr << "parse error: " << error << '\n';
    return EXIT_FAILURE;
  }
  Dac25RepairOptions options;
  options.abc_executable = argv[3];
  options.plan.timeout_ms = 30000;
  options.runeco_timeout_seconds = 60;
  try {
    if (argc >= 6) options.plan.candidate_limit = std::stoull(argv[5]);
    if (argc >= 7) options.plan.max_targets = std::stoull(argv[6]);
    if (argc >= 8) options.plan.max_feasible_sets = std::stoull(argv[7]);
  } catch (const std::exception& e) {
    std::cerr << "numeric option error: " << e.what() << '\n';
    return EXIT_FAILURE;
  }
  const Dac25RepairResult result = execute_dac25_inspired_repair(
      golden, trojan, options, argv[4]);
  std::cout << "dac25_repair status " << dac25_repair_status_name(result.status)
            << " plan_status " << dac25_plan_status_name(result.plan.status)
            << " candidates " << result.plan.candidates.size()
            << " sets_checked " << result.plan.sets_checked
            << " feasible_sets " << result.plan.feasible_sets
            << " trials " << result.trials.size()
            << " successful_trials " << result.successful_trials
            << " selected_trial " << result.selected_trial
            << " total_ms " << result.total_ms << '\n';
  for (std::size_t i = 0; i < result.trials.size(); ++i) {
    const auto& trial = result.trials[i];
    std::cout << "trial " << i << " status "
              << dac25_runeco_status_name(trial.runeco.status)
              << " targets";
    for (int target : trial.targets) {
      std::cout << " " << trojan.node_name(target);
    }
    std::cout << " patched_area " << trial.runeco.metrics.patched_area
              << " patched_level " << trial.runeco.metrics.patched_level
              << " patch_gates " << trial.runeco.metrics.patch_added_gates
              << " patch_inputs " << trial.runeco.metrics.patch_inputs
              << " runeco_ms " << trial.runeco.metrics.runeco_ms << '\n';
    if (!trial.runeco.ok()) {
      std::cout << "trial_reason " << trial.runeco.reason << '\n';
      std::cout << "trial_stdout " << trial.runeco.stdout_log << '\n';
      std::cout << "trial_stderr " << trial.runeco.stderr_log << '\n';
    }
  }
  std::cout << "reason " << result.reason << '\n';
  return result.ok() ? EXIT_SUCCESS : EXIT_FAILURE;
}
