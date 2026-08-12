#include "dac25_runeco.hpp"

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../io/bench_parser.hpp"
#include "../io/bench_writer.hpp"

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
  std::string pattern = "/tmp/dac25-runeco-XXXXXX";
  std::vector<char> writable(pattern.begin(), pattern.end());
  writable.push_back('\0');
  char* created = mkdtemp(writable.data());
  if (!created) {
    if (error) *error = std::string("mkdtemp failed: ") + std::strerror(errno);
    return false;
  }
  out->path = fs::path(created);
  return true;
}

std::string read_text_file(const fs::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return {};
  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

struct ProcessResult {
  bool launched = false;
  bool timed_out = false;
  int exit_code = -1;
  std::string error;
  std::string stdout_text;
  std::string stderr_text;
};

ProcessResult run_abc_process(const std::string& executable,
                              const std::string& command,
                              const fs::path& workdir,
                              std::uint64_t timeout_seconds,
                              const std::string& log_stem) {
  ProcessResult result;
  const fs::path stdout_path = workdir / (log_stem + ".stdout");
  const fs::path stderr_path = workdir / (log_stem + ".stderr");
  const int stdout_fd =
      open(stdout_path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
  const int stderr_fd =
      open(stderr_path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
  if (stdout_fd < 0 || stderr_fd < 0) {
    if (stdout_fd >= 0) close(stdout_fd);
    if (stderr_fd >= 0) close(stderr_fd);
    result.error = std::string("cannot open process log: ") +
                   std::strerror(errno);
    return result;
  }

  const pid_t pid = fork();
  if (pid < 0) {
    close(stdout_fd);
    close(stderr_fd);
    result.error = std::string("fork failed: ") + std::strerror(errno);
    return result;
  }
  if (pid == 0) {
    setpgid(0, 0);
    if (chdir(workdir.c_str()) != 0 ||
        dup2(stdout_fd, STDOUT_FILENO) < 0 ||
        dup2(stderr_fd, STDERR_FILENO) < 0) {
      _exit(126);
    }
    close(stdout_fd);
    close(stderr_fd);
    execlp(executable.c_str(), executable.c_str(), "-c", command.c_str(),
           static_cast<char*>(nullptr));
    _exit(127);
  }

  // Close the fork/setpgid race so even an immediate timeout can address the
  // entire ABC process group.  EACCES only means the child already exec'd
  // after establishing the same group itself.
  if (setpgid(pid, pid) != 0 && errno != EACCES && errno != ESRCH) {
    result.error = std::string("setpgid failed: ") + std::strerror(errno);
  }

  close(stdout_fd);
  close(stderr_fd);
  result.launched = true;
  const auto start = Clock::now();
  int wait_status = 0;
  while (true) {
    const pid_t waited = waitpid(pid, &wait_status, WNOHANG);
    if (waited == pid) break;
    if (waited < 0) {
      result.error = std::string("waitpid failed: ") + std::strerror(errno);
      kill(-pid, SIGKILL);
      waitpid(pid, &wait_status, 0);
      break;
    }
    if (timeout_seconds == 0 ||
        elapsed_ms(start) >= static_cast<double>(timeout_seconds) * 1000.0) {
      result.timed_out = true;
      kill(-pid, SIGTERM);
      const auto grace = Clock::now();
      while (elapsed_ms(grace) < 1000.0) {
        const pid_t grace_waited = waitpid(pid, &wait_status, WNOHANG);
        if (grace_waited == pid) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      if (waitpid(pid, &wait_status, WNOHANG) == 0) {
        kill(-pid, SIGKILL);
        waitpid(pid, &wait_status, 0);
      }
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  if (WIFEXITED(wait_status)) {
    result.exit_code = WEXITSTATUS(wait_status);
  } else if (WIFSIGNALED(wait_status)) {
    result.exit_code = 128 + WTERMSIG(wait_status);
  }
  result.stdout_text = read_text_file(stdout_path);
  result.stderr_text = read_text_file(stderr_path);
  return result;
}

const char* primitive_name(GType type) {
  switch (type) {
    case GType::AND:
      return "and";
    case GType::OR:
      return "or";
    case GType::NAND:
      return "nand";
    case GType::NOR:
      return "nor";
    case GType::NOT:
      return "not";
    case GType::BUFF:
      return "buf";
    case GType::XOR:
      return "xor";
    case GType::XNOR:
      return "xnor";
  }
  return "buf";
}

bool build_signal_name_map(
    const circuit& net,
    const std::unordered_map<std::string, std::size_t>& canonical_pis,
    const std::unordered_map<int, std::size_t>& target_position,
    std::vector<std::string>* names,
    std::string* error) {
  if (!names) return false;
  names->assign(net.node_count(), {});
  for (std::size_t idx = 0; idx < net.node_count(); ++idx) {
    const cell& node = net.get_cell(static_cast<int>(idx));
    auto target = target_position.find(static_cast<int>(idx));
    if (target != target_position.end()) {
      (*names)[idx] = "t_" + std::to_string(target->second);
      continue;
    }
    switch (node.ctype) {
      case CType::PI: {
        auto found = canonical_pis.find(net.node_name(static_cast<int>(idx)));
        if (found == canonical_pis.end()) {
          if (error) *error = "PI name sets do not match";
          return false;
        }
        (*names)[idx] = "pi_" + std::to_string(found->second);
        break;
      }
      case CType::CONST:
        (*names)[idx] = node.val != 0 ? "1'b1" : "1'b0";
        break;
      case CType::GATE:
        (*names)[idx] = "n_" + std::to_string(idx);
        break;
      case CType::UNDEF:
        if (error) *error = "undefined node in Verilog serializer";
        return false;
    }
  }
  return true;
}

bool serialize_verilog(
    const circuit& net,
    const std::vector<std::string>& canonical_pi_names,
    const std::vector<std::string>& canonical_po_names,
    const std::unordered_map<int, std::size_t>& target_position,
    const fs::path& path,
    std::string* error) {
  std::unordered_map<std::string, std::size_t> pi_position;
  for (std::size_t i = 0; i < canonical_pi_names.size(); ++i) {
    if (!pi_position.emplace(canonical_pi_names[i], i).second) {
      if (error) *error = "duplicate canonical PI name";
      return false;
    }
  }
  std::unordered_map<std::string, int> po_by_name;
  for (int idx : net.po_indices()) {
    if (!po_by_name.emplace(net.node_name(idx), idx).second) {
      if (error) *error = "duplicate PO name";
      return false;
    }
  }
  if (pi_position.size() != net.pi_count() ||
      po_by_name.size() != canonical_po_names.size()) {
    if (error) *error = "PI/PO name-set size mismatch";
    return false;
  }

  std::vector<std::string> signals;
  if (!build_signal_name_map(net, pi_position, target_position, &signals,
                             error)) {
    return false;
  }
  std::ofstream output(path);
  if (!output) {
    if (error) *error = "cannot open Verilog output " + path.string();
    return false;
  }

  output << "module top(";
  bool first = true;
  for (std::size_t i = 0; i < canonical_pi_names.size(); ++i) {
    if (!first) output << ", ";
    output << "pi_" << i;
    first = false;
  }
  for (std::size_t i = 0; i < canonical_po_names.size(); ++i) {
    if (!first) output << ", ";
    output << "po_" << i;
    first = false;
  }
  output << ");\n";
  output << "input ";
  for (std::size_t i = 0; i < canonical_pi_names.size(); ++i) {
    if (i) output << ", ";
    output << "pi_" << i;
  }
  output << ";\noutput ";
  for (std::size_t i = 0; i < canonical_po_names.size(); ++i) {
    if (i) output << ", ";
    output << "po_" << i;
  }
  output << ";\n";

  for (const auto& target : target_position) {
    output << "wire t_" << target.second << ";\n";
  }
  for (std::size_t idx = 0; idx < net.node_count(); ++idx) {
    const cell& node = net.get_cell(static_cast<int>(idx));
    if (node.ctype == CType::GATE &&
        target_position.find(static_cast<int>(idx)) == target_position.end()) {
      output << "wire n_" << idx << ";\n";
    }
  }

  for (int idx : net.eval_order()) {
    if (target_position.find(idx) != target_position.end()) continue;
    const cell& gate = net.get_cell(idx);
    if (gate.ctype != CType::GATE || gate.inputs.empty()) {
      if (error) *error = "invalid gate in Verilog serializer";
      return false;
    }
    output << primitive_name(gate.gtype) << " gate_" << idx << "("
           << signals[static_cast<std::size_t>(idx)];
    for (int input : gate.inputs) {
      if (input < 0 || static_cast<std::size_t>(input) >= signals.size()) {
        if (error) *error = "gate input out of range in Verilog serializer";
        return false;
      }
      output << ", " << signals[static_cast<std::size_t>(input)];
    }
    output << ");\n";
  }
  for (std::size_t i = 0; i < canonical_po_names.size(); ++i) {
    auto found = po_by_name.find(canonical_po_names[i]);
    if (found == po_by_name.end()) {
      if (error) *error = "PO name sets do not match";
      return false;
    }
    output << "buf output_" << i << "(po_" << i << ", "
           << signals[static_cast<std::size_t>(found->second)] << ");\n";
  }
  output << "endmodule\n";
  if (!output) {
    if (error) *error = "failed while writing Verilog";
    return false;
  }
  return true;
}

bool write_weight_file(const circuit& trojan,
                       const std::vector<std::string>& canonical_pi_names,
                       const std::vector<std::string>& canonical_po_names,
                       const std::unordered_map<int, std::size_t>& targets,
                       const fs::path& path,
                       std::string* error) {
  std::ofstream output(path);
  if (!output) {
    if (error) *error = "cannot open weight file";
    return false;
  }
  for (std::size_t i = 0; i < canonical_pi_names.size(); ++i) {
    output << "pi_" << i << " 1\n";
  }
  for (std::size_t i = 0; i < canonical_po_names.size(); ++i) {
    output << "po_" << i << " 1\n";
  }
  for (std::size_t idx = 0; idx < trojan.node_count(); ++idx) {
    if (trojan.get_cell(static_cast<int>(idx)).ctype == CType::GATE &&
        targets.find(static_cast<int>(idx)) == targets.end()) {
      output << "n_" << idx << " 1\n";
    }
  }
  for (const auto& target : targets) {
    output << "t_" << target.second << " 1\n";
  }
  return static_cast<bool>(output);
}

bool atomic_write_bench(const fs::path& path,
                        circuit* net,
                        std::string* error) {
  if (!net) return false;
  std::error_code ec;
  if (!path.parent_path().empty()) {
    fs::create_directories(path.parent_path(), ec);
    if (ec) {
      if (error) *error = "cannot create output directory: " + ec.message();
      return false;
    }
  }
  const fs::path temporary =
      path.string() + ".tmp." + std::to_string(static_cast<long long>(getpid()));
  if (!bench_io::write_bench_file(temporary.string(), *net, error)) {
    fs::remove(temporary, ec);
    return false;
  }
  fs::rename(temporary, path, ec);
  if (ec) {
    fs::remove(temporary, ec);
    if (error) *error = "cannot atomically replace output: " + ec.message();
    return false;
  }
  return true;
}

std::string unique_node_name(const circuit& net, const std::string& prefix) {
  std::size_t suffix = 0;
  std::string name;
  do {
    name = prefix + std::to_string(suffix++);
  } while (net.has_node(name));
  return name;
}

bool restore_interface_names(circuit* net,
                             const std::vector<std::string>& pi_names,
                             const std::vector<std::string>& po_names,
                             std::string* error) {
  if (!net || net->pi_count() != pi_names.size() ||
      net->po_count() != po_names.size()) {
    if (error) *error = "normalized patch PI/PO count mismatch";
    return false;
  }
  std::unordered_set<std::string> desired;
  std::unordered_map<std::string, std::size_t> pi_position;
  for (const std::string& name : pi_names) {
    const std::size_t position = pi_position.size();
    if (name.empty() || !desired.insert(name).second ||
        !pi_position.emplace(name, position).second) {
      if (error) *error = "duplicate/empty original interface name";
      return false;
    }
  }
  std::unordered_set<std::string> seen_po;
  for (const std::string& name : po_names) {
    if (name.empty() || !seen_po.insert(name).second) {
      if (error) *error = "duplicate/empty original PO name";
      return false;
    }
    // BENCH permits OUTPUT(pi_name).  The normalized ABC netlist represents
    // that output through a separate po_N node; restore the alias below by
    // redirecting the PO index to the corresponding restored PI.
    if (pi_position.find(name) == pi_position.end()) desired.insert(name);
  }

  std::vector<int> pi_nodes(net->pi_indices().begin(),
                            net->pi_indices().end());
  std::vector<int> po_nodes(net->po_indices().begin(),
                            net->po_indices().end());
  std::unordered_set<int> interface_nodes(pi_nodes.begin(), pi_nodes.end());
  interface_nodes.insert(po_nodes.begin(), po_nodes.end());

  // First free all current interface names.  Then move any internal node that
  // happens to use an original port name before restoring that port.  This
  // keeps the output drop-in compatible even when an original name resembles
  // ABC's generated n_N names.
  for (int node : interface_nodes) {
    const std::string temporary =
        unique_node_name(*net, "__dac25_port_tmp_");
    if (!net->rename_node(node, temporary, error)) return false;
  }
  for (const std::string& name : desired) {
    if (!net->has_node(name)) continue;
    const int conflict = net->node_index(name);
    const std::string temporary =
        unique_node_name(*net, "__dac25_internal_tmp_");
    if (!net->rename_node(conflict, temporary, error)) return false;
  }
  for (std::size_t i = 0; i < pi_nodes.size(); ++i) {
    if (!net->rename_node(pi_nodes[i], pi_names[i], error)) return false;
  }
  for (std::size_t i = 0; i < po_nodes.size(); ++i) {
    auto alias = pi_position.find(po_names[i]);
    if (alias != pi_position.end()) {
      net->set_po_index(i, pi_nodes[alias->second]);
    } else if (!net->rename_node(po_nodes[i], po_names[i], error)) {
      return false;
    }
  }
  return true;
}

bool normalize_bench_with_abc(const std::string& abc_executable,
                              const fs::path& workdir,
                              const fs::path& input,
                              const fs::path& output,
                              std::uint64_t timeout_seconds,
                              const std::string& log_stem,
                              ProcessResult* process,
                              circuit* parsed,
                              std::string* error) {
  if (!process || !parsed) return false;
  const std::string command =
      "read " + input.filename().string() +
      "; strash; write_bench -l " + output.filename().string();
  *process = run_abc_process(abc_executable, command, workdir,
                             std::min<std::uint64_t>(timeout_seconds, 30),
                             log_stem);
  if (!process->launched || process->timed_out || process->exit_code != 0 ||
      !fs::is_regular_file(output)) {
    if (error) *error = "ABC could not normalize BENCH " + input.string();
    return false;
  }
  if (!bench_io::parse_bench_file(output.string(), *parsed, error)) {
    if (error && error->empty()) *error = "normalized BENCH parse failed";
    return false;
  }
  return true;
}

std::size_t parse_metric(const std::string& text,
                         const std::regex& expression) {
  std::smatch match;
  if (!std::regex_search(text, match, expression) || match.size() < 2) {
    return 0;
  }
  try {
    return static_cast<std::size_t>(std::stoull(match[1].str()));
  } catch (const std::exception&) {
    return 0;
  }
}

}  // namespace

const char* dac25_runeco_status_name(Dac25RunecoStatus status) {
  switch (status) {
    case Dac25RunecoStatus::success:
      return "success";
    case Dac25RunecoStatus::invalid_input:
      return "invalid_input";
    case Dac25RunecoStatus::serialize_error:
      return "serialize_error";
    case Dac25RunecoStatus::launch_error:
      return "launch_error";
    case Dac25RunecoStatus::timeout:
      return "timeout";
    case Dac25RunecoStatus::runeco_failed:
      return "runeco_failed";
    case Dac25RunecoStatus::output_missing:
      return "output_missing";
    case Dac25RunecoStatus::conversion_failed:
      return "conversion_failed";
    case Dac25RunecoStatus::write_failed:
      return "write_failed";
  }
  return "invalid_input";
}

Dac25RunecoResult run_dac25_runeco(
    const circuit& golden,
    const circuit& trojan,
    const std::vector<int>& selected_target_nodes,
    const std::string& abc_executable,
    std::uint64_t hard_timeout_seconds,
    const std::string& output_bench_path) {
  Dac25RunecoResult result;
  const auto total_start = Clock::now();
  result.metrics.selected_targets = selected_target_nodes.size();
  if (selected_target_nodes.empty() || abc_executable.empty() ||
      hard_timeout_seconds == 0 || output_bench_path.empty()) {
    result.reason = "targets, ABC executable, timeout, and output are required";
    return result;
  }

  std::string resolved_abc = abc_executable;
  if (abc_executable.find('/') != std::string::npos) {
    std::error_code path_error;
    const fs::path absolute = fs::absolute(abc_executable, path_error);
    if (path_error) {
      result.reason = "cannot resolve ABC executable: " +
                      path_error.message();
      return result;
    }
    resolved_abc = absolute.lexically_normal().string();
  }

  std::unordered_map<int, std::size_t> target_position;
  for (std::size_t i = 0; i < selected_target_nodes.size(); ++i) {
    const int target = selected_target_nodes[i];
    if (target < 0 || static_cast<std::size_t>(target) >= trojan.node_count() ||
        trojan.get_cell(target).ctype != CType::GATE ||
        !target_position.emplace(target, i).second) {
      result.reason = "target must be a unique in-range Trojan gate";
      return result;
    }
    result.target_names.push_back(trojan.node_name(target));
  }

  std::vector<std::string> pi_names;
  std::vector<std::string> po_names;
  std::unordered_set<std::string> trojan_pis;
  std::unordered_set<std::string> trojan_pos;
  for (int idx : trojan.pi_indices()) trojan_pis.insert(trojan.node_name(idx));
  for (int idx : trojan.po_indices()) trojan_pos.insert(trojan.node_name(idx));
  for (int idx : golden.pi_indices()) {
    const std::string name = golden.node_name(idx);
    if (trojan_pis.find(name) == trojan_pis.end()) {
      result.reason = "PI name sets do not match";
      return result;
    }
    pi_names.push_back(name);
  }
  for (int idx : golden.po_indices()) {
    const std::string name = golden.node_name(idx);
    if (trojan_pos.find(name) == trojan_pos.end()) {
      result.reason = "PO name sets do not match";
      return result;
    }
    po_names.push_back(name);
  }
  if (pi_names.size() != trojan.pi_count() ||
      po_names.size() != trojan.po_count()) {
    result.reason = "PI/PO name-set size mismatch";
    return result;
  }

  TempDirectory temporary;
  std::string error;
  if (!create_temp_directory(&temporary, &error)) {
    result.status = Dac25RunecoStatus::serialize_error;
    result.reason = error;
    return result;
  }
  const auto serialize_start = Clock::now();
  const std::unordered_map<int, std::size_t> no_targets;
  if (!serialize_verilog(trojan, pi_names, po_names, target_position,
                         temporary.path / "F.v", &error) ||
      !serialize_verilog(trojan, pi_names, po_names, no_targets,
                         temporary.path / "T.v", &error) ||
      !serialize_verilog(golden, pi_names, po_names, no_targets,
                         temporary.path / "G.v", &error) ||
      !write_weight_file(trojan, pi_names, po_names, target_position,
                         temporary.path / "weight.txt", &error)) {
    result.status = Dac25RunecoStatus::serialize_error;
    result.reason = error;
    result.metrics.serialize_ms = elapsed_ms(serialize_start);
    result.metrics.total_ms = elapsed_ms(total_start);
    return result;
  }
  result.used_weight_file = true;
  result.metrics.serialize_ms = elapsed_ms(serialize_start);

  // QoR deltas and trial ranking must use one structural representation.
  // Normalize the unpatched Trojan through the same ABC strash/write_bench
  // flow used for every synthesized patch.
  const auto trojan_convert_start = Clock::now();
  ProcessResult trojan_conversion;
  circuit normalized_trojan;
  if (!normalize_bench_with_abc(
          resolved_abc, temporary.path, temporary.path / "T.v",
          temporary.path / "trojan_normalized.bench", hard_timeout_seconds,
          "normalize_trojan", &trojan_conversion, &normalized_trojan,
          &error)) {
    result.metrics.convert_ms += elapsed_ms(trojan_convert_start);
    result.status = Dac25RunecoStatus::conversion_failed;
    result.reason = error;
    result.stdout_log = trojan_conversion.stdout_text;
    result.stderr_log = trojan_conversion.stderr_text;
    result.metrics.total_ms = elapsed_ms(total_start);
    return result;
  }
  result.metrics.convert_ms += elapsed_ms(trojan_convert_start);
  result.metrics.trojan_area = normalized_trojan.area();
  result.metrics.trojan_level = normalized_trojan.level();

  const std::string runeco_command =
      "runeco -T " + std::to_string(hard_timeout_seconds) +
      " -c -u F.v G.v weight.txt";
  const auto runeco_start = Clock::now();
  ProcessResult runeco = run_abc_process(
      resolved_abc, runeco_command, temporary.path,
      hard_timeout_seconds + 2, "runeco");
  result.metrics.runeco_ms = elapsed_ms(runeco_start);
  result.exit_code = runeco.exit_code;
  result.stdout_log = runeco.stdout_text;
  result.stderr_log = runeco.stderr_text;
  if (!runeco.launched) {
    result.status = Dac25RunecoStatus::launch_error;
    result.reason = runeco.error;
    result.metrics.total_ms = elapsed_ms(total_start);
    return result;
  }
  if (runeco.timed_out) {
    result.status = Dac25RunecoStatus::timeout;
    result.timed_out = true;
    result.reason = "ABC runeco exceeded the hard deadline";
    result.metrics.total_ms = elapsed_ms(total_start);
    return result;
  }
  const bool verified =
      result.stdout_log.find("The ECO solution was verified successfully") !=
      std::string::npos;
  if (runeco.exit_code != 0 || !verified) {
    result.status = Dac25RunecoStatus::runeco_failed;
    result.reason = runeco.error.empty()
                        ? "runeco did not report a verified ECO solution"
                        : runeco.error;
    result.metrics.total_ms = elapsed_ms(total_start);
    return result;
  }
  if (!fs::is_regular_file(temporary.path / "out.v")) {
    result.status = Dac25RunecoStatus::output_missing;
    result.reason = "runeco did not produce out.v";
    result.metrics.total_ms = elapsed_ms(total_start);
    return result;
  }
  const std::string patch_verilog = read_text_file(temporary.path / "patch.v");

  result.metrics.patch_inputs = parse_metric(
      result.stdout_log, std::regex(R"(Patch has\s+([0-9]+)\s+inputs)"));
  result.metrics.patch_added_gates = parse_metric(
      result.stdout_log, std::regex(R"(Added\s+:\s+gate\s+=\s+([0-9]+))"));

  const auto convert_start = Clock::now();
  ProcessResult conversion;
  circuit patched;
  bool converted = normalize_bench_with_abc(
      resolved_abc, temporary.path, temporary.path / "out.v",
      temporary.path / "patched.bench", hard_timeout_seconds, "convert",
      &conversion, &patched, &error);
  result.metrics.convert_ms += elapsed_ms(convert_start);
  result.stdout_log += conversion.stdout_text;
  result.stderr_log += conversion.stderr_text;
  bool recovered_constant = false;
  if (!converted) {
    // Current ABC runeco emits a malformed zero-input module instance for a
    // constant patch.  Recover that fully specified special case directly
    // from patch.v, then normalize it through the exact same ABC flow as a
    // nonconstant patch before ranking or publishing it.
    if (result.metrics.patch_inputs == 0 && !patch_verilog.empty()) {
      circuit constant_patch = trojan;
      bool parsed_all = true;
      for (std::size_t i = 0; i < selected_target_nodes.size(); ++i) {
        const std::regex constant_expression(
            "(?:assign\\s+)?t_" + std::to_string(i) +
            R"([^;\n]*(1'b[01]))",
            std::regex::icase);
        std::smatch match;
        if (!std::regex_search(patch_verilog, match, constant_expression) ||
            match.size() < 2) {
          parsed_all = false;
          break;
        }
        const int value = match[1].str().back() == '1' ? 1 : 0;
        constant_patch.force_gate_const(selected_target_nodes[i], value);
      }
      if (parsed_all && bench_io::write_bench_file(
                            (temporary.path / "constant_raw.bench").string(),
                            constant_patch, &error)) {
        const auto constant_convert_start = Clock::now();
        ProcessResult constant_conversion;
        converted = normalize_bench_with_abc(
            resolved_abc, temporary.path,
            temporary.path / "constant_raw.bench",
            temporary.path / "constant_normalized.bench",
            hard_timeout_seconds, "convert_constant", &constant_conversion,
            &patched, &error);
        result.metrics.convert_ms += elapsed_ms(constant_convert_start);
        result.stdout_log += constant_conversion.stdout_text;
        result.stderr_log += constant_conversion.stderr_text;
        recovered_constant = converted;
      }
    }
  }
  if (!converted) {
    result.status = Dac25RunecoStatus::conversion_failed;
    result.reason = conversion.timed_out
                        ? "ABC BENCH conversion timed out"
                        : error.empty()
                              ? "ABC could not convert the runeco patch"
                              : error;
    result.stdout_log += "\npatch.v:\n" + patch_verilog;
    result.metrics.total_ms = elapsed_ms(total_start);
    return result;
  }

  if (!restore_interface_names(&patched, pi_names, po_names, &error)) {
    result.status = Dac25RunecoStatus::write_failed;
    result.reason = "could not restore original patch interface: " + error;
    result.metrics.total_ms = elapsed_ms(total_start);
    return result;
  }
  result.metrics.patched_area = patched.area();
  result.metrics.patched_level = patched.level();
  result.metrics.area_delta =
      static_cast<std::int64_t>(result.metrics.patched_area) -
      static_cast<std::int64_t>(result.metrics.trojan_area);
  result.metrics.level_delta =
      static_cast<std::int64_t>(result.metrics.patched_level) -
      static_cast<std::int64_t>(result.metrics.trojan_level);
  if (!atomic_write_bench(output_bench_path, &patched, &error)) {
    result.status = Dac25RunecoStatus::write_failed;
    result.reason = error;
    result.metrics.total_ms = elapsed_ms(total_start);
    return result;
  }

  result.status = Dac25RunecoStatus::success;
  result.reason = recovered_constant
                      ? "recovered and normalized verified constant ECO patch"
                      : "runeco synthesized and verified the ECO patch";
  result.metrics.total_ms = elapsed_ms(total_start);
  return result;
}
