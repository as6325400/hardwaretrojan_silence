#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "../core/circuit.hpp"

enum class Dac25RunecoStatus {
  success,
  invalid_input,
  serialize_error,
  launch_error,
  timeout,
  runeco_failed,
  output_missing,
  conversion_failed,
  write_failed
};

const char* dac25_runeco_status_name(Dac25RunecoStatus status);

struct Dac25RunecoMetrics {
  std::size_t selected_targets = 0;
  std::size_t trojan_area = 0;
  std::size_t trojan_level = 0;
  std::size_t patched_area = 0;
  std::size_t patched_level = 0;
  std::size_t patch_inputs = 0;
  std::size_t patch_added_gates = 0;
  std::int64_t area_delta = 0;
  std::int64_t level_delta = 0;
  double serialize_ms = 0.0;
  double runeco_ms = 0.0;
  double convert_ms = 0.0;
  double total_ms = 0.0;
};

struct Dac25RunecoResult {
  Dac25RunecoStatus status = Dac25RunecoStatus::invalid_input;
  int exit_code = -1;
  bool timed_out = false;
  bool used_weight_file = false;
  std::string reason;
  std::string stdout_log;
  std::string stderr_log;
  std::vector<std::string> target_names;
  Dac25RunecoMetrics metrics;

  bool ok() const { return status == Dac25RunecoStatus::success; }
};

// Run ABC's DAC'18 runeco implementation as the patch-function backend for a
// DAC25-inspired target set.  Each selected Trojan gate is removed from the
// serialized implementation and replaced by exactly one floating internal
// wire named t_0, t_1, ...; every original fanout and PO connection observes
// that same wire.  The external process runs in a unique temporary directory
// and its own deadline terminates the complete ABC child process group.  The
// benchmark harness separately terminates the full descendant tree when its
// outer deadline fires.
Dac25RunecoResult run_dac25_runeco(
    const circuit& golden,
    const circuit& trojan,
    const std::vector<int>& selected_target_nodes,
    const std::string& abc_executable,
    std::uint64_t hard_timeout_seconds,
    const std::string& output_bench_path);
