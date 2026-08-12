#include "dac25_repair.hpp"

#include <chrono>
#include <filesystem>
#include <limits>
#include <tuple>

#include <unistd.h>

namespace {

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

double elapsed_ms(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start)
      .count();
}

struct TempDirectory {
  fs::path path;
  ~TempDirectory() {
    std::error_code ignored;
    if (!path.empty()) fs::remove_all(path, ignored);
  }
};

bool create_temp_directory(TempDirectory* out, std::string* error) {
  if (!out) return false;
  std::string pattern = "/tmp/dac25-repair-XXXXXX";
  std::vector<char> writable(pattern.begin(), pattern.end());
  writable.push_back('\0');
  char* created = mkdtemp(writable.data());
  if (!created) {
    if (error) *error = "could not create DAC25 repair temporary directory";
    return false;
  }
  out->path = fs::path(created);
  return true;
}

bool atomic_copy(const fs::path& source,
                 const fs::path& destination,
                 std::string* error) {
  std::error_code ec;
  if (!destination.parent_path().empty()) {
    fs::create_directories(destination.parent_path(), ec);
    if (ec) {
      if (error) *error = "cannot create output directory: " + ec.message();
      return false;
    }
  }
  const fs::path temporary = destination.string() + ".tmp." +
                             std::to_string(static_cast<long long>(getpid()));
  fs::copy_file(source, temporary, fs::copy_options::overwrite_existing, ec);
  if (ec) {
    if (error) *error = "cannot stage selected BENCH: " + ec.message();
    return false;
  }
  fs::rename(temporary, destination, ec);
  if (ec) {
    std::error_code ignored;
    fs::remove(temporary, ignored);
    if (error) *error = "cannot publish selected BENCH: " + ec.message();
    return false;
  }
  return true;
}

}  // namespace

const char* dac25_repair_status_name(Dac25RepairStatus status) {
  switch (status) {
    case Dac25RepairStatus::success:
      return "success";
    case Dac25RepairStatus::planner_failed:
      return "planner_failed";
    case Dac25RepairStatus::patch_failed:
      return "patch_failed";
    case Dac25RepairStatus::write_failed:
      return "write_failed";
  }
  return "planner_failed";
}

Dac25RepairResult execute_dac25_inspired_repair(
    const circuit& golden,
    const circuit& trojan,
    const Dac25RepairOptions& options,
    const std::string& output_bench_path) {
  Dac25RepairResult result;
  const auto start = Clock::now();
  result.plan = plan_dac25_rectification(golden, trojan, options.plan);
  if (result.plan.status != Dac25PlanStatus::selected ||
      result.plan.feasible_target_sets.empty()) {
    result.status = Dac25RepairStatus::planner_failed;
    result.reason = result.plan.reason;
    result.total_ms = elapsed_ms(start);
    return result;
  }

  TempDirectory temporary;
  if (!create_temp_directory(&temporary, &result.reason)) {
    result.status = Dac25RepairStatus::write_failed;
    result.total_ms = elapsed_ms(start);
    return result;
  }

  std::size_t best = static_cast<std::size_t>(-1);
  std::tuple<std::size_t, std::size_t, std::size_t, std::vector<int>> best_key{
      std::numeric_limits<std::size_t>::max(),
      std::numeric_limits<std::size_t>::max(),
      std::numeric_limits<std::size_t>::max(), {}};
  for (std::size_t i = 0; i < result.plan.feasible_target_sets.size(); ++i) {
    Dac25RepairTrial trial;
    trial.targets = result.plan.feasible_target_sets[i];
    const fs::path trial_path =
        temporary.path / ("trial_" + std::to_string(i) + ".bench");
    trial.runeco = run_dac25_runeco(
        golden, trojan, trial.targets, options.abc_executable,
        options.runeco_timeout_seconds, trial_path.string());
    result.trials.push_back(std::move(trial));
    const Dac25RunecoResult& runeco = result.trials.back().runeco;
    if (!runeco.ok()) continue;
    result.successful_trials += 1;
    const auto key = std::make_tuple(
        runeco.metrics.patched_area, runeco.metrics.patched_level,
        runeco.metrics.patch_added_gates, result.trials.back().targets);
    if (best == static_cast<std::size_t>(-1) || key < best_key) {
      best = i;
      best_key = key;
    }
  }
  if (best == static_cast<std::size_t>(-1)) {
    result.status = Dac25RepairStatus::patch_failed;
    result.reason = "no qualified target set produced a verified runeco patch";
    result.total_ms = elapsed_ms(start);
    return result;
  }

  const fs::path selected_path =
      temporary.path / ("trial_" + std::to_string(best) + ".bench");
  if (!atomic_copy(selected_path, output_bench_path, &result.reason)) {
    result.status = Dac25RepairStatus::write_failed;
    result.total_ms = elapsed_ms(start);
    return result;
  }
  result.selected_trial = best;
  result.status = Dac25RepairStatus::success;
  result.reason = "selected the best verified runeco patch";
  result.total_ms = elapsed_ms(start);
  return result;
}
