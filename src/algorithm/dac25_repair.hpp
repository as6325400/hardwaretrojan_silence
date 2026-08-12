#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dac25_rectification.hpp"
#include "dac25_runeco.hpp"

enum class Dac25RepairStatus {
  success,
  planner_failed,
  patch_failed,
  write_failed
};

const char* dac25_repair_status_name(Dac25RepairStatus status);

struct Dac25RepairOptions {
  Dac25PlanOptions plan;
  std::string abc_executable = "abc";
  std::uint64_t runeco_timeout_seconds = 60;
};

struct Dac25RepairTrial {
  std::vector<int> targets;
  Dac25RunecoResult runeco;
};

struct Dac25RepairResult {
  Dac25RepairStatus status = Dac25RepairStatus::planner_failed;
  std::string reason;
  Dac25PlanResult plan;
  std::vector<Dac25RepairTrial> trials;
  std::size_t successful_trials = 0;
  std::size_t selected_trial = static_cast<std::size_t>(-1);
  double total_ms = 0.0;

  bool ok() const { return status == Dac25RepairStatus::success; }
};

// Plan minimum-cardinality target sets, synthesize every retained set with
// the same runeco backend, and select lexicographically by post-strash area,
// logic level, raw added patch gates, then target indices.
Dac25RepairResult execute_dac25_inspired_repair(
    const circuit& golden,
    const circuit& trojan,
    const Dac25RepairOptions& options,
    const std::string& output_bench_path);
