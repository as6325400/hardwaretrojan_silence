#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "algorithm/candidate_selector.hpp"
#include "algorithm/miner.hpp"
#include "algorithm/pattern_sampler.hpp"
#include "algorithm/payload_analysis.hpp"
#include "algorithm/rule_patch.hpp"
#include "algorithm/trigger_fixer.hpp"
#include "algorithm/virtual_node.hpp"
#include "core/circuit_compare.hpp"
#include "core/packed_circuit.hpp"
#ifdef USE_CUDA
#include <cuda_runtime.h>
#include "core/gpu_circuit.cuh"
#endif
#include "io/bench_parser.hpp"
#include "io/bench_writer.hpp"
#include "io/cli_options.hpp"
#include "io/parallel_collect_log.hpp"

using namespace std;

namespace {

string shell_quote(const string& value) {
  string quoted = "'";
  for (char ch : value) {
    if (ch == '\'') {
      quoted += "'\\''";
    } else {
      quoted += ch;
    }
  }
  quoted += "'";
  return quoted;
}

string abc_quote(const string& value) {
  string quoted = "\"";
  for (char ch : value) {
    if (ch == '\\' || ch == '"') quoted += '\\';
    quoted += ch;
  }
  quoted += "\"";
  return quoted;
}

std::uint64_t popcount_ull(packed_circuit::word_t value) {
  return static_cast<std::uint64_t>(__builtin_popcountll(value));
}

packed_circuit::word_t take_first_bits(packed_circuit::word_t mask,
                                       size_t count) {
  packed_circuit::word_t out = 0;
  while (mask && count > 0) {
    const packed_circuit::word_t lsb = mask & (~mask + 1ULL);
    out |= lsb;
    mask &= (mask - 1);
    count -= 1;
  }
  return out;
}

// ---------------------------------------------------------------------------
// run_abc_cec: call ABC CEC and optionally extract counter-example pattern.
// Returns true if circuits are equivalent.
// On failure, *counter_example is filled with PI values from the
// counter-example (indexed by circuit PI position).
// ---------------------------------------------------------------------------
bool run_abc_cec(const string& golden_path,
                 const string& patched_path,
                 const circuit& golden_circuit,
                 vector<int>* counter_example) {
  if (counter_example) counter_example->clear();

  string abc_bin;
  const char* configured_abc = std::getenv("ABC_BIN");
  if (configured_abc && configured_abc[0] != '\0') {
    abc_bin = configured_abc;
  } else {
    // Backward-compatible fallback: infer the project root from a golden
    // circuit under <root>/benchmarks/.
    auto pos = golden_path.rfind('/');
    if (pos != string::npos) {
      abc_bin = golden_path.substr(0, pos);  // …/benchmarks -> project root
      pos = abc_bin.rfind('/');
      if (pos != string::npos) {
        abc_bin = abc_bin.substr(0, pos);
      } else {
        abc_bin = ".";
      }
    } else {
      abc_bin = ".";
    }
    abc_bin += "/abc";
  }

  const string abc_script =
      "cec " + abc_quote(golden_path) + " " + abc_quote(patched_path);
  const string cmd = shell_quote(abc_bin) + " -c " +
                     shell_quote(abc_script) + " 2>&1";
  FILE* pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    cerr << "cec: failed to run abc\n";
    return false;
  }

  string output;
  {
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) {
      output += buf;
    }
  }
  int rc = pclose(pipe);
  if (rc != 0) {
    cerr << "cec: abc exited with status " << rc << "\n";
    return false;
  }

  if (output.find("Networks are equivalent") != string::npos) {
    return true;
  }

  // Parse counter-example from INPUT: line.
  // Format: INPUT: name1 = 1'h1, name2 = 1'h0, ...
  if (!counter_example) return false;

  const auto& pi_indices = golden_circuit.pi_indices();
  unordered_map<string, size_t> pi_name_to_pos;
  pi_name_to_pos.reserve(pi_indices.size());
  for (size_t pos = 0; pos < pi_indices.size(); ++pos) {
    pi_name_to_pos[golden_circuit.node_name(pi_indices[pos])] = pos;
  }

  counter_example->assign(pi_indices.size(), 0);

  // Find the INPUT: section in the output.
  auto inp_pos = output.find("INPUT:");
  if (inp_pos == string::npos) {
    cerr << "cec: NOT EQUIVALENT but no INPUT section found\n";
    counter_example->clear();
    return false;
  }

  // Extract from "INPUT:" up to ".  OUTPUT:" or end of line.
  auto out_pos = output.find(".  OUTPUT:", inp_pos);
  string inp_section;
  if (out_pos != string::npos) {
    inp_section = output.substr(inp_pos + 7, out_pos - inp_pos - 7);
  } else {
    auto nl = output.find('\n', inp_pos);
    inp_section = output.substr(inp_pos + 7,
                                (nl != string::npos ? nl : output.size()) - inp_pos - 7);
  }

  // Parse comma-separated "name = 1'hX" entries.
  istringstream iss(inp_section);
  string token;
  while (getline(iss, token, ',')) {
    // Trim whitespace.
    auto start = token.find_first_not_of(" \t\n\r");
    if (start == string::npos) continue;
    token = token.substr(start);
    // Expected: "name = 1'hX"
    auto eq = token.find(" = ");
    if (eq == string::npos) continue;
    string name = token.substr(0, eq);
    string val_str = token.substr(eq + 3);
    int val = 0;
    if (val_str.find("1'h1") != string::npos) val = 1;
    auto it = pi_name_to_pos.find(name);
    if (it != pi_name_to_pos.end()) {
      (*counter_example)[it->second] = val;
    }
  }

  return false;
}

bool classify_cec_counterexample(const circuit& golden,
                                 const circuit& original_trojan,
                                 const vector<int>& golden_pi_values,
                                 bool* is_real_trigger,
                                 string* error) {
  if (error) {
    error->clear();
  }
  if (!is_real_trigger) {
    if (error) {
      *error = "is_real_trigger output pointer is null";
    }
    return false;
  }
  *is_real_trigger = true;
  if (golden_pi_values.size() != golden.pi_count()) {
    if (error) {
      *error = "CEC pattern PI count mismatch";
    }
    return false;
  }

  unordered_map<string, int> pi_value_by_name;
  pi_value_by_name.reserve(golden.pi_count());
  const auto& golden_pis = golden.pi_indices();
  for (size_t i = 0; i < golden_pis.size(); ++i) {
    pi_value_by_name[golden.node_name(golden_pis[i])] =
        golden_pi_values[i] ? 1 : 0;
  }

  vector<int> trojan_pi_values;
  trojan_pi_values.reserve(original_trojan.pi_count());
  for (int pi_idx : original_trojan.pi_indices()) {
    const string& name = original_trojan.node_name(pi_idx);
    auto it = pi_value_by_name.find(name);
    if (it == pi_value_by_name.end()) {
      if (error) {
        *error = "Trojan PI not found in CEC pattern: " + name;
      }
      return false;
    }
    trojan_pi_values.push_back(it->second);
  }

  try {
    circuit golden_eval = golden;
    circuit trojan_eval = original_trojan;
    const vector<int> golden_outputs =
        golden_eval.simulate(golden_pi_values);
    const vector<int> trojan_outputs =
        trojan_eval.simulate(trojan_pi_values);

    unordered_map<string, int> golden_po_by_name;
    golden_po_by_name.reserve(golden.po_count());
    const auto& golden_pos = golden.po_indices();
    for (size_t i = 0; i < golden_pos.size(); ++i) {
      golden_po_by_name[golden.node_name(golden_pos[i])] =
          golden_outputs[i] ? 1 : 0;
    }

    for (size_t i = 0; i < original_trojan.po_indices().size(); ++i) {
      const int po_idx = original_trojan.po_indices()[i];
      const string& name = original_trojan.node_name(po_idx);
      auto it = golden_po_by_name.find(name);
      if (it == golden_po_by_name.end()) {
        if (error) {
          *error = "Trojan PO not found in golden circuit: " + name;
        }
        return false;
      }
      if (it->second != (trojan_outputs[i] ? 1 : 0)) {
        *is_real_trigger = true;
        return true;
      }
    }
  } catch (const exception& e) {
    if (error) {
      *error = string("CEC classification simulation error: ") + e.what();
    }
    return false;
  }

  *is_real_trigger = false;
  return true;
}

bool build_stats_from_groundtruth(const circuit& golden,
                                  const circuit& trojan,
                                  const string& log_path,
                                  PatternStats* stats,
                                  string* error) {
  auto t0 = std::chrono::steady_clock::now();
  auto ms = [](auto start) {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();
  };

  if (error) {
    error->clear();
  }
  if (!stats) {
    if (error) {
      *error = "Stats output pointer is null";
    }
    return false;
  }

  *stats = PatternStats{};
  ParallelCollectLog log(log_path);
  cerr << "[TIMING]   groundtruth_parse: " << ms(t0) << " ms\n";
  t0 = std::chrono::steady_clock::now();

  const auto& log_pi_order = log.pi_order();
  if (log_pi_order.empty()) {
    if (error) {
      *error = "pi_order not available in groundtruth log";
    }
    return false;
  }

  const auto& pi_indices = trojan.pi_indices();
  unordered_map<string, size_t> pi_name_to_pos;
  pi_name_to_pos.reserve(pi_indices.size());
  for (size_t pos = 0; pos < pi_indices.size(); ++pos) {
    pi_name_to_pos[trojan.node_name(pi_indices[pos])] = pos;
  }

  vector<size_t> log_to_circuit;
  log_to_circuit.reserve(log_pi_order.size());
  vector<int> seen_pos(pi_indices.size(), 0);
  for (const auto& name : log_pi_order) {
    auto it = pi_name_to_pos.find(name);
    if (it == pi_name_to_pos.end()) {
      if (error) {
        *error = "pi_order entry not found in circuit: " + name;
      }
      return false;
    }
    log_to_circuit.push_back(it->second);
    if (it->second < seen_pos.size()) {
      seen_pos[it->second] += 1;
    }
  }
  for (size_t pos = 0; pos < seen_pos.size(); ++pos) {
    if (seen_pos[pos] == 0) {
      if (error) {
        *error = "circuit PI missing from groundtruth pi_order: " +
                 trojan.node_name(pi_indices[pos]);
      }
      return false;
    }
  }

  unordered_set<string> unique_bits;
  vector<string> ordered_bits;
  unique_bits.reserve(log.size());
  ordered_bits.reserve(log.size());
  for (size_t i = 0; i < log.size(); ++i) {
    auto bits = log.get_pattern_bits(static_cast<int>(i));
    if (!bits) {
      continue;
    }
    if (unique_bits.insert(*bits).second) {
      ordered_bits.push_back(*bits);
    }
  }

  if (ordered_bits.empty()) {
    if (error) {
      *error = "No pattern_bits found in groundtruth log";
    }
    return false;
  }

  stats->trigger_patterns.reserve(ordered_bits.size());
  for (const auto& bits : ordered_bits) {
    if (bits.size() != log_to_circuit.size()) {
      if (error) {
        *error = "pattern_bits length does not match pi_order";
      }
      return false;
    }
    vector<int> pi_values(pi_indices.size(), 0);
    for (size_t i = 0; i < log_to_circuit.size(); ++i) {
      char bit = bits[i];
      if (bit != '0' && bit != '1') {
        if (error) {
          *error = "pattern_bits contains invalid character";
        }
        return false;
      }
      pi_values[log_to_circuit[i]] = (bit == '1') ? 1 : 0;
    }
    stats->trigger_patterns.push_back(std::move(pi_values));
  }

  stats->trigger_patterns_total = stats->trigger_patterns.size();
  stats->mismatch_patterns = stats->trigger_patterns_total;

  stats->gate_indices.reserve(trojan.node_count());
  for (size_t i = 0; i < trojan.node_count(); ++i) {
    const auto& c = trojan.get_cell(static_cast<int>(i));
    if (c.ctype == CType::GATE) {
      stats->gate_indices.push_back(static_cast<int>(i));
    }
  }

  const std::size_t num_gates = stats->gate_indices.size();
  stats->ones_total.assign(num_gates, 0);
  stats->ones_trigger.assign(num_gates, 0);
  stats->ones_notrigger.assign(num_gates, 0);

  const size_t target_notrigger = stats->trigger_patterns.size();
  stats->notrigger_patterns_total = 0;
  stats->total_patterns = stats->trigger_patterns_total;

  if (target_notrigger == 0) {
    if (error) {
      *error = "No trigger patterns available";
    }
    return false;
  }

#ifdef USE_CUDA
  // ── GPU path: trigger sim + random non-trigger sim ─────────────────────────
  // Only use GPU for large circuits where overhead is amortised.
  if (trojan.node_count() >= 50000) try {
    cerr << "[TIMING]   pattern_build: " << ms(t0) << " ms\n";
    t0 = std::chrono::steady_clock::now();
    constexpr std::size_t kBits = 64;
    circuit golden_copy = golden;
    circuit trojan_copy = trojan;
    golden_copy.ensure_eval_order();
    trojan_copy.ensure_eval_order();

    const std::size_t num_pis = golden.pi_count();
    const std::size_t max_wb = gpu_compute_max_word_blocks(
        golden_copy.node_count(), trojan_copy.node_count(), num_pis, 0);

    GpuCircuit gpu_golden(golden_copy, max_wb);
    GpuCircuit gpu_trojan(trojan_copy, max_wb);
    cerr << "[TIMING]   gpu_init (GpuCircuit x2 + malloc): " << ms(t0) << " ms\n";
    t0 = std::chrono::steady_clock::now();

    // Device buffers
    GpuCircuit::word_t* d_pi_bits = nullptr;
    GpuCircuit::word_t* d_diff_mask = nullptr;
    GpuCircuit::word_t* d_accept_masks = nullptr;
    int* d_gate_indices = nullptr;
    unsigned long long* d_accum_trigger = nullptr;
    unsigned long long* d_accum_notrigger = nullptr;

    cudaMalloc(&d_pi_bits, num_pis * max_wb * sizeof(GpuCircuit::word_t));
    cudaMalloc(&d_diff_mask, max_wb * sizeof(GpuCircuit::word_t));
    cudaMalloc(&d_accept_masks, max_wb * sizeof(GpuCircuit::word_t));
    cudaMalloc(&d_gate_indices, num_gates * sizeof(int));
    cudaMalloc(&d_accum_trigger, num_gates * sizeof(unsigned long long));
    cudaMalloc(&d_accum_notrigger, num_gates * sizeof(unsigned long long));

    cudaMemcpy(d_gate_indices, stats->gate_indices.data(),
               num_gates * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemset(d_accum_trigger, 0, num_gates * sizeof(unsigned long long));
    cudaMemset(d_accum_notrigger, 0, num_gates * sizeof(unsigned long long));

    // ── Phase 1: Trigger sim on GPU ──
    {
      const std::size_t total = stats->trigger_patterns.size();
      std::size_t offset = 0;
      while (offset < total) {
        const std::size_t chunk = std::min(max_wb * kBits, total - offset);
        const std::size_t chunk_wb = (chunk + kBits - 1) / kBits;
        const GpuCircuit::word_t pmask =
            (chunk % kBits == 0) ? ~GpuCircuit::word_t(0)
                                 : (GpuCircuit::word_t(1) << (chunk % kBits)) - 1;

        std::vector<GpuCircuit::word_t> h_pi(num_pis * chunk_wb, 0);
        gpu_pack_pi_patterns(stats->trigger_patterns, offset, chunk,
                             num_pis, h_pi.data(), chunk_wb);
        cudaMemcpy(d_pi_bits, h_pi.data(),
                   num_pis * chunk_wb * sizeof(GpuCircuit::word_t),
                   cudaMemcpyHostToDevice);

        gpu_trojan.simulate(d_pi_bits, chunk_wb);
        gpu_accumulate_gate_ones(gpu_trojan.d_values(), d_gate_indices,
                                 num_gates, chunk_wb,
                                 gpu_trojan.num_nodes(), pmask,
                                 d_accum_trigger);
        offset += chunk;
      }
    }

    cudaDeviceSynchronize();
    cerr << "[TIMING]   gpu_trigger_sim: " << ms(t0) << " ms\n";
    t0 = std::chrono::steady_clock::now();

    // Download trigger accum
    std::vector<unsigned long long> h_trigger(num_gates);
    cudaMemcpy(h_trigger.data(), d_accum_trigger,
               num_gates * sizeof(unsigned long long),
               cudaMemcpyDeviceToHost);
    for (std::size_t g = 0; g < num_gates; ++g) {
      stats->ones_trigger[g] = h_trigger[g];
      stats->ones_total[g] = h_trigger[g];
    }

    // ── Phase 2: Random non-trigger sim on GPU ──
    {
      mt19937_64 rng(1337);
      size_t attempts = 0;
      const size_t max_attempts = target_notrigger * 50 + 1000;
      std::vector<GpuCircuit::word_t> h_diff(max_wb);
      std::vector<GpuCircuit::word_t> h_accept(max_wb);

      while (stats->notrigger_patterns_total < target_notrigger &&
             attempts < max_attempts) {
        const size_t remaining_attempts = max_attempts - attempts;
        const size_t batch = std::min(max_wb * kBits, remaining_attempts);
        const size_t batch_wb = (batch + kBits - 1) / kBits;
        if (batch == 0) break;

        // Generate random PI on GPU
        gpu_generate_random_pi(d_pi_bits, num_pis, batch_wb, rng());

        // Simulate both circuits
        gpu_golden.simulate(d_pi_bits, batch_wb);
        gpu_trojan.simulate(d_pi_bits, batch_wb);

        // Compare PO → diff_mask
        const GpuCircuit::word_t pmask =
            (batch % kBits == 0) ? ~GpuCircuit::word_t(0)
                                 : (GpuCircuit::word_t(1) << (batch % kBits)) - 1;
        gpu_compare_po(gpu_golden, gpu_trojan, d_diff_mask, batch_wb, pmask);

        // Download diff_mask, compute accept_masks on CPU
        cudaMemcpy(h_diff.data(), d_diff_mask,
                   batch_wb * sizeof(GpuCircuit::word_t),
                   cudaMemcpyDeviceToHost);

        std::size_t batch_take = 0;
        const std::size_t remaining_needed =
            target_notrigger - stats->notrigger_patterns_total;
        for (std::size_t w = 0; w < batch_wb; ++w) {
          GpuCircuit::word_t wb_mask =
              (w == batch_wb - 1) ? pmask : ~GpuCircuit::word_t(0);
          GpuCircuit::word_t notrigger = wb_mask & ~h_diff[w];
          const std::size_t avail = popcount_ull(notrigger);
          const std::size_t can_take =
              std::min(avail, remaining_needed - batch_take);
          if (can_take < avail) {
            notrigger = take_first_bits(notrigger, can_take);
          }
          h_accept[w] = notrigger;
          batch_take += can_take;
          if (batch_take >= remaining_needed) {
            // Zero remaining accept masks
            for (std::size_t w2 = w + 1; w2 < batch_wb; ++w2)
              h_accept[w2] = 0;
            break;
          }
        }

        if (batch_take > 0) {
          // Upload accept masks and accumulate
          cudaMemcpy(d_accept_masks, h_accept.data(),
                     batch_wb * sizeof(GpuCircuit::word_t),
                     cudaMemcpyHostToDevice);
          gpu_accumulate_gate_ones_masked(gpu_trojan.d_values(),
                                          d_gate_indices, num_gates,
                                          batch_wb, gpu_trojan.num_nodes(),
                                          d_accept_masks, d_accum_notrigger);
          stats->notrigger_patterns_total += batch_take;
          stats->total_patterns += batch_take;
        }

        attempts += batch;
      }
    }

    cudaDeviceSynchronize();
    cerr << "[TIMING]   gpu_notrigger_sim: " << ms(t0) << " ms\n";
    t0 = std::chrono::steady_clock::now();

    // Download notrigger accum
    std::vector<unsigned long long> h_notrigger(num_gates);
    cudaMemcpy(h_notrigger.data(), d_accum_notrigger,
               num_gates * sizeof(unsigned long long),
               cudaMemcpyDeviceToHost);
    for (std::size_t g = 0; g < num_gates; ++g) {
      stats->ones_notrigger[g] = h_notrigger[g];
      stats->ones_total[g] += h_notrigger[g];
    }

    cudaFree(d_pi_bits);
    cudaFree(d_diff_mask);
    cudaFree(d_accept_masks);
    cudaFree(d_gate_indices);
    cudaFree(d_accum_trigger);
    cudaFree(d_accum_notrigger);
    cerr << "[TIMING]   gpu_download+free: " << ms(t0) << " ms\n";

    if (stats->notrigger_patterns_total < target_notrigger) {
      if (error) {
        *error = "Not enough non-trigger patterns collected: " +
                 to_string(stats->notrigger_patterns_total) + "/" +
                 to_string(target_notrigger);
      }
      return false;
    }
    return true;
  } catch (...) {
    // GPU failed — fall through to CPU path
    stats->ones_total.assign(num_gates, 0);
    stats->ones_trigger.assign(num_gates, 0);
    stats->ones_notrigger.assign(num_gates, 0);
    stats->notrigger_patterns_total = 0;
    stats->total_patterns = stats->trigger_patterns_total;
  }
#endif

  // ── CPU fallback: trigger sim ──────────────────────────────────────────────
  {
    circuit trojan_trigger = trojan;
    packed_circuit trojan_packed(trojan_trigger);
    std::size_t trigger_offset = 0;
    while (trigger_offset < stats->trigger_patterns.size()) {
      const std::size_t remaining =
          stats->trigger_patterns.size() - trigger_offset;
      const std::size_t block_size =
          std::min(packed_circuit::kWordBits, remaining);
      std::vector<std::vector<int>> patterns;
      patterns.reserve(block_size);
      for (std::size_t p = 0; p < block_size; ++p) {
        patterns.push_back(stats->trigger_patterns[trigger_offset + p]);
      }

      try {
        trojan_packed.simulate(patterns);
      } catch (const std::exception& e) {
        if (error) {
          *error = string("Trigger simulation error: ") + e.what();
        }
        return false;
      }

      #pragma omp parallel for schedule(static)
      for (std::size_t g = 0; g < num_gates; ++g) {
        const int idx = stats->gate_indices[g];
        const std::uint64_t ones = popcount_ull(trojan_packed.node_bits(idx));
        stats->ones_trigger[g] += ones;
        stats->ones_total[g] += ones;
      }

      trigger_offset += block_size;
    }
  }

  // ── CPU fallback: random non-trigger sim ───────────────────────────────────
  {
    circuit golden_eval = golden;
    circuit trojan_eval = trojan;
    packed_circuit golden_packed(golden_eval);
    packed_circuit trojan_eval_packed(trojan_eval);
    golden_packed.prepare_batch();
    trojan_eval_packed.prepare_batch();
    mt19937_64 rng(1337);
    size_t attempts = 0;
    const size_t max_attempts = target_notrigger * 50 + 1000;
    const size_t block_bits = packed_circuit::kWordBits;
    const size_t stats_pi_count = golden_eval.pi_count();
    vector<packed_circuit::word_t> stats_pi_bits(stats_pi_count);

    while (stats->notrigger_patterns_total < target_notrigger &&
           attempts < max_attempts) {
      const size_t remaining_attempts = max_attempts - attempts;
      const size_t block_size = min(block_bits, remaining_attempts);
      if (block_size == 0) {
        break;
      }

      for (size_t i = 0; i < stats_pi_count; ++i) {
        stats_pi_bits[i] = rng();
      }

      try {
        golden_packed.simulate_bits_fast(stats_pi_bits.data(), block_size);
        trojan_eval_packed.simulate_bits_fast(stats_pi_bits.data(), block_size);
      } catch (const std::exception&) {
        attempts += block_size;
        continue;
      }

      const packed_circuit::word_t mask =
          packed_circuit::mask_for_count(block_size);
      packed_circuit::word_t diff_mask = 0;
      for (size_t o = 0; o < trojan_eval.po_count(); ++o) {
        diff_mask |= (golden_packed.po_bits(o) ^ trojan_eval_packed.po_bits(o));
      }
      diff_mask &= mask;
      packed_circuit::word_t notrigger_mask = mask & ~diff_mask;

      const size_t remaining_needed =
          target_notrigger - stats->notrigger_patterns_total;
      const size_t available = popcount_ull(notrigger_mask);
      const size_t take = min(remaining_needed, available);
      packed_circuit::word_t accept_mask =
          (take == available) ? notrigger_mask
                              : take_first_bits(notrigger_mask, take);

      if (take > 0) {
        stats->notrigger_patterns_total += take;
        stats->total_patterns += take;
        #pragma omp parallel for schedule(static)
        for (size_t g = 0; g < num_gates; ++g) {
          const int idx = stats->gate_indices[g];
          const packed_circuit::word_t bits =
              trojan_eval_packed.node_bits(idx) & accept_mask;
          const std::uint64_t ones = popcount_ull(bits);
          stats->ones_notrigger[g] += ones;
          stats->ones_total[g] += ones;
        }
      }

      attempts += block_size;
    }
  }

  if (stats->notrigger_patterns_total < target_notrigger) {
    if (error) {
      *error = "Not enough non-trigger patterns collected: " +
               to_string(stats->notrigger_patterns_total) + "/" +
               to_string(target_notrigger);
    }
    return false;
  }

  return true;
}

vector<vector<int>> select_spread_patterns(const vector<vector<int>>& patterns,
                                           size_t max_count) {
  vector<vector<int>> selected;
  if (max_count == 0 || patterns.empty()) {
    return selected;
  }
  if (patterns.size() <= max_count) {
    return patterns;
  }
  selected.reserve(max_count);
  if (max_count == 1) {
    selected.push_back(patterns.front());
    return selected;
  }
  for (size_t i = 0; i < max_count; ++i) {
    const size_t idx = (i * (patterns.size() - 1)) / (max_count - 1);
    selected.push_back(patterns[idx]);
  }
  return selected;
}

void collect_random_nontrigger_patterns(const circuit& golden,
                                        const circuit& trojan,
                                        size_t target_count,
                                        vector<vector<int>>* out) {
  if (!out || out->size() >= target_count) {
    return;
  }
  circuit golden_eval = golden;
  circuit trojan_eval = trojan;
  mt19937_64 rng(0x51a7e5eedULL);
  const size_t pi_count = golden.pi_count();
  const size_t max_attempts = target_count * 200 + 2000;
  for (size_t attempt = 0;
       out->size() < target_count && attempt < max_attempts;
       ++attempt) {
    vector<int> pattern(pi_count, 0);
    for (size_t i = 0; i < pi_count; ++i) {
      pattern[i] = static_cast<int>((rng() >> (i & 31U)) & 1ULL);
    }
    try {
      const vector<int> golden_out = golden_eval.simulate(pattern);
      const vector<int> trojan_out = trojan_eval.simulate(pattern);
      if (golden_out == trojan_out) {
        out->push_back(std::move(pattern));
      }
    } catch (const exception&) {
      continue;
    }
  }
}

vector<int> build_signature_base_pool(const PatternStats& stats,
                                      const vector<int>& base_candidates,
                                      const vector<int>& important_signals,
                                      size_t max_count) {
  vector<int> pool;
  if (max_count == 0) {
    return pool;
  }

  unordered_set<int> allowed(base_candidates.begin(), base_candidates.end());
  unordered_set<int> used;
  pool.reserve(max_count);
  for (int idx : important_signals) {
    if (allowed.count(idx) && used.insert(idx).second) {
      pool.push_back(idx);
      if (pool.size() >= max_count) {
        return pool;
      }
    }
  }

  unordered_map<int, size_t> gate_pos;
  gate_pos.reserve(stats.gate_indices.size());
  for (size_t i = 0; i < stats.gate_indices.size(); ++i) {
    gate_pos[stats.gate_indices[i]] = i;
  }

  struct RankedGate {
    int idx = -1;
    double score = 0.0;
  };
  vector<RankedGate> ranked;
  ranked.reserve(base_candidates.size());
  const double pos_total = static_cast<double>(
      max<uint64_t>(1, stats.trigger_patterns_total));
  const double neg_total = static_cast<double>(
      max<uint64_t>(1, stats.notrigger_patterns_total));
  for (int idx : base_candidates) {
    if (used.count(idx)) {
      continue;
    }
    auto it = gate_pos.find(idx);
    if (it == gate_pos.end()) {
      continue;
    }
    const size_t pos = it->second;
    const double p_trigger =
        static_cast<double>(stats.ones_trigger[pos]) / pos_total;
    const double p_normal =
        static_cast<double>(stats.ones_notrigger[pos]) / neg_total;
    const double separation = fabs(p_trigger - p_normal);
    const double trigger_bias = fabs(p_trigger - 0.5);
    ranked.push_back(RankedGate{
        idx,
        separation * 1000.0 + trigger_bias});
  }

  sort(ranked.begin(), ranked.end(),
       [](const RankedGate& a, const RankedGate& b) {
         if (fabs(a.score - b.score) > 1.0e-12) {
           return a.score > b.score;
         }
         return a.idx < b.idx;
       });
  for (const auto& rg : ranked) {
    if (used.insert(rg.idx).second) {
      pool.push_back(rg.idx);
      if (pool.size() >= max_count) {
        break;
      }
    }
  }
  return pool;
}

using SigWord = packed_circuit::word_t;

struct TriggerSignatureContext {
  std::vector<int> nodes;
  std::unordered_map<int, std::size_t> node_pos;
  std::vector<SigWord> node_sigs;
  std::vector<SigWord> target_sig;
  std::size_t pos_count = 0;
  std::size_t neg_count = 0;
  std::size_t total_count = 0;
  std::size_t words = 0;
  SigWord last_mask = 0;
};

struct TriggerSigStats {
  std::size_t rules_before = 0;
  std::size_t rules_after = 0;
  std::size_t literals_before = 0;
  std::size_t literals_after = 0;
  std::size_t single_model = 0;
  std::size_t single_rule = 0;
  std::size_t hit_rules = 0;
  std::size_t exact_mismatches = 0;
};

struct RuleSynthTelemetry {
  std::size_t candidate_count = 0;
  std::size_t dt_builds = 0;
  std::size_t strict_dt_builds = 0;
  std::size_t training_data_builds = 0;
  std::size_t vn_generated = 0;
  std::size_t vn_used = 0;
  std::size_t phase_rules = 0;
  std::size_t phase_literals = 0;
  std::size_t phase_depth = 0;
  RuleOptimizerStats optimizer_stats;
  std::size_t optimizer_calls = 0;
  std::size_t optimizer_accepted = 0;
  std::size_t optimizer_checks = 0;
  std::size_t optimizer_counterexamples = 0;
  double optimizer_solver_ms = 0.0;
};

struct LiteralPatchCutCandidate {
  int node_idx = -1;
  int forced_value = 0;
  int expected = 0;
  std::size_t feature_idx = 0;
  std::size_t cover_count = 0;
  uint64_t cover_mask = 0;
  std::size_t fanout = 0;
  double cost = 0.0;
};

std::size_t count_model_literals(const DecisionTreeModel& model) {
  std::size_t total = 0;
  for (const auto& rule : model.rules) {
    total += rule.terms.size();
  }
  return total;
}

std::size_t max_model_rule_literals(const DecisionTreeModel& model) {
  std::size_t maximum = 0;
  for (const auto& rule : model.rules) {
    maximum = std::max(maximum, rule.terms.size());
  }
  return maximum;
}

void refresh_model_rule_metadata(DecisionTreeModel* model) {
  if (!model) return;
  model->leaf_count = model->rules.size();
  model->max_depth_used = max_model_rule_literals(*model);
}

DecisionTreeRule make_literal_rule(std::size_t feature_idx, int expected);

bool is_virtual_node_name(const std::string& name) {
  return name.size() >= 3 && name[0] == 'v' && name[1] == 'n' &&
         name[2] == '_';
}

bool is_triggerish_name(const std::string& name) {
  if (name.size() < 2 || name[0] != 'r') {
    return false;
  }
  for (std::size_t i = 1; i < name.size(); ++i) {
    if (name[i] < '0' || name[i] > '9') {
      return false;
    }
  }
  return true;
}

std::vector<std::size_t> compute_fanout_counts(const circuit& net) {
  std::vector<std::size_t> fanout(net.node_count(), 0);
  for (std::size_t i = 0; i < net.node_count(); ++i) {
    const cell& c = net.get_cell(static_cast<int>(i));
    if (c.ctype != CType::GATE) {
      continue;
    }
    for (int inp : c.inputs) {
      if (inp >= 0 && static_cast<std::size_t>(inp) < fanout.size()) {
        fanout[static_cast<std::size_t>(inp)] += 1;
      }
    }
  }
  return fanout;
}

double literal_patch_cut_cost(const circuit& net,
                              int node_idx,
                              std::size_t fanout,
                              std::size_t cover_count) {
  const cell& c = net.get_cell(node_idx);
  double cost = 1000.0;
  cost += static_cast<double>(fanout) * 80.0;
  cost += static_cast<double>(c.inputs.size()) * 8.0;
  cost -= static_cast<double>(cover_count) * 120.0;
  if (is_triggerish_name(net.node_name(node_idx))) {
    cost -= 450.0;
  }
  if (fanout <= 1) {
    cost -= 120.0;
  }
  if (c.gtype == GType::XOR || c.gtype == GType::XNOR) {
    cost += 80.0;
  }
  return cost;
}

uint64_t literal_patch_cut_key(int node_idx, int forced_value) {
  return (static_cast<uint64_t>(static_cast<uint32_t>(node_idx)) << 1) |
         static_cast<uint64_t>(forced_value & 1);
}

std::vector<LiteralPatchCutCandidate> collect_literal_patch_cut_candidates(
    const circuit& net,
    const MiningResult& result) {
  std::vector<LiteralPatchCutCandidate> candidates;
  const std::size_t rule_count = result.model.rules.size();
  if (rule_count == 0) {
    return candidates;
  }

  std::unordered_map<uint64_t, std::size_t> by_key;
  by_key.reserve(count_model_literals(result.model) + 1);

  for (std::size_t ri = 0; ri < rule_count; ++ri) {
    std::unordered_set<uint64_t> seen_in_rule;
    for (const auto& term : result.model.rules[ri].terms) {
      if (term.first >= result.feature_nodes.size()) {
        continue;
      }
      const int node_idx = result.feature_nodes[term.first];
      if (node_idx < 0 ||
          static_cast<std::size_t>(node_idx) >= net.node_count()) {
        continue;
      }
      const std::string& name = net.node_name(node_idx);
      if (is_virtual_node_name(name)) {
        continue;
      }
      const cell& c = net.get_cell(node_idx);
      if (c.ctype != CType::GATE) {
        continue;
      }

      const int expected = term.second ? 1 : 0;
      const int forced_value = expected ? 0 : 1;
      const uint64_t key = literal_patch_cut_key(node_idx, forced_value);
      if (!seen_in_rule.insert(key).second) {
        continue;
      }

      auto it = by_key.find(key);
      if (it == by_key.end()) {
        LiteralPatchCutCandidate cand;
        cand.node_idx = node_idx;
        cand.forced_value = forced_value;
        cand.expected = expected;
        cand.feature_idx = term.first;
        candidates.push_back(cand);
        const std::size_t pos = candidates.size() - 1;
        by_key.emplace(key, pos);
        it = by_key.find(key);
      }

      LiteralPatchCutCandidate& cand = candidates[it->second];
      cand.cover_count += 1;
      if (ri < 64) {
        cand.cover_mask |= (uint64_t{1} << ri);
      }
    }
  }

  std::vector<LiteralPatchCutCandidate> covering;
  covering.reserve(candidates.size());
  const std::vector<std::size_t> fanout = compute_fanout_counts(net);
  for (auto& cand : candidates) {
    if (cand.cover_count != rule_count) {
      continue;
    }
    cand.fanout = fanout[static_cast<std::size_t>(cand.node_idx)];
    cand.cost = literal_patch_cut_cost(net,
                                       cand.node_idx,
                                       cand.fanout,
                                       cand.cover_count);
    covering.push_back(cand);
  }

  std::sort(covering.begin(), covering.end(),
            [](const LiteralPatchCutCandidate& a,
               const LiteralPatchCutCandidate& b) {
              if (std::fabs(a.cost - b.cost) > 1.0e-9) {
                return a.cost < b.cost;
              }
              if (a.fanout != b.fanout) {
                return a.fanout < b.fanout;
              }
              return a.node_idx < b.node_idx;
            });
  return covering;
}

bool try_verified_literal_patch_cut(const circuit& golden,
                                    const circuit& base,
                                    const PatternStats& stats,
                                    const MiningResult& result,
                                    circuit* patched_out,
                                    int* selected_node,
                                    int* forced_value,
                                    long long* delta_area,
                                    long long* delta_level,
                                    std::string* error) {
  if (error) {
    error->clear();
  }
  if (!patched_out) {
    if (error) *error = "literal patch cut output pointer is null";
    return false;
  }
  if (stats.trigger_patterns.empty()) {
    if (error) *error = "no trigger patterns for literal patch cut";
    return false;
  }

  std::vector<LiteralPatchCutCandidate> candidates =
      collect_literal_patch_cut_candidates(base, result);
  cout << "literal_patch_cut_candidates " << candidates.size()
       << " rules " << result.model.rules.size() << "\n";
  if (candidates.empty()) {
    if (error) *error = "no single literal covers every rule";
    return false;
  }

  std::size_t base_area = 0;
  std::size_t base_level = 0;
  try {
    circuit base_eval = base;
    base_eval.ensure_eval_order();
    base_area = base_eval.area();
    base_level = base_eval.level();
  } catch (const std::exception& e) {
    if (error) *error = std::string("literal patch cut baseline error: ") + e.what();
    return false;
  }

  constexpr std::size_t kMaxLiteralPatchCutTries = 16;
  std::size_t tried = 0;
  for (const LiteralPatchCutCandidate& cand : candidates) {
    if (tried >= kMaxLiteralPatchCutTries) {
      break;
    }
    tried += 1;

    circuit trial = base;
    try {
      trial.force_gate_const(cand.node_idx, cand.forced_value);
    } catch (const std::exception& e) {
      cerr << "literal_patch_cut_try "
           << base.node_name(cand.node_idx)
           << " forced " << cand.forced_value
           << " failed: " << e.what() << "\n";
      continue;
    }

    std::size_t mismatch_index = 0;
    std::string verify_error;
    const auto verify_start = std::chrono::steady_clock::now();
    const bool verified = verify_patch_groundtruth(golden,
                                                   trial,
                                                   stats.trigger_patterns,
                                                   &mismatch_index,
                                                   &verify_error);
    const double verify_ms =
        std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - verify_start).count();
    if (!verified) {
      cerr << "[TIMING]   literal_patch_cut_verify: "
           << verify_ms << " ms (FAIL)\n";
      cerr << "literal_patch_cut_try "
           << base.node_name(cand.node_idx)
           << " forced " << cand.forced_value
           << " failed: " << verify_error;
      if (!stats.trigger_patterns.empty()) {
        cerr << " pattern " << mismatch_index;
      }
      cerr << "\n";
      continue;
    }
    cerr << "[TIMING]   final_verify: "
         << verify_ms << " ms (PASS)\n";

    std::size_t trial_area = 0;
    std::size_t trial_level = 0;
    try {
      trial.ensure_eval_order();
      trial_area = trial.area();
      trial_level = trial.level();
    } catch (const std::exception& e) {
      cerr << "literal_patch_cut area/level error: " << e.what() << "\n";
      continue;
    }

    cout << "literal_patch_cut_selected "
         << base.node_name(cand.node_idx)
         << " forced " << cand.forced_value
         << " covers " << cand.cover_count
         << " fanout " << cand.fanout
         << " cost " << cand.cost << "\n";

    if (selected_node) {
      *selected_node = cand.node_idx;
    }
    if (forced_value) {
      *forced_value = cand.forced_value;
    }
    if (delta_area) {
      *delta_area = static_cast<long long>(trial_area) -
                    static_cast<long long>(base_area);
    }
    if (delta_level) {
      *delta_level = static_cast<long long>(trial_level) -
                     static_cast<long long>(base_level);
    }
    *patched_out = std::move(trial);
    return true;
  }

  if (error) {
    *error = "no verified single literal patch cut";
  }
  return false;
}

bool literal_rejects_extra_negatives(const circuit& trojan,
                                     int node_idx,
                                     int expected,
                                     const std::vector<std::vector<int>>& extra_neg_patterns) {
  if (extra_neg_patterns.empty()) {
    return true;
  }
  circuit sim_net = trojan;
  packed_circuit sim(sim_net);
  sim.prepare_batch();
  std::size_t offset = 0;
  while (offset < extra_neg_patterns.size()) {
    const std::size_t block =
        std::min<std::size_t>(packed_circuit::kWordBits,
                              extra_neg_patterns.size() - offset);
    std::vector<std::vector<int>> patterns;
    patterns.reserve(block);
    for (std::size_t i = 0; i < block; ++i) {
      if (extra_neg_patterns[offset + i].size() != trojan.pi_count()) {
        return false;
      }
      patterns.push_back(extra_neg_patterns[offset + i]);
    }
    try {
      sim.simulate(patterns);
    } catch (const std::exception&) {
      return false;
    }
    const SigWord mask = packed_circuit::mask_for_count(block);
    const SigWord bits = sim.node_bits(node_idx) & mask;
    const SigWord literal_bits = expected ? bits : ((~bits) & mask);
    if (literal_bits != 0) {
      return false;
    }
    offset += block;
  }
  return true;
}

bool literal_matches_stats_trigger(const circuit& trojan,
                                   const PatternStats& stats,
                                   const std::vector<std::vector<int>>& extra_neg_patterns,
                                   int node_idx,
                                   int expected) {
  if (node_idx < 0 || static_cast<std::size_t>(node_idx) >= trojan.node_count()) {
    return false;
  }
  const cell& c = trojan.get_cell(node_idx);
  if (c.ctype != CType::GATE) {
    return false;
  }
  auto it = std::find(stats.gate_indices.begin(),
                      stats.gate_indices.end(),
                      node_idx);
  if (it == stats.gate_indices.end()) {
    return false;
  }
  const std::size_t pos =
      static_cast<std::size_t>(std::distance(stats.gate_indices.begin(), it));
  if (expected) {
    if (stats.ones_trigger[pos] != stats.trigger_patterns_total ||
        stats.ones_notrigger[pos] != 0) {
      return false;
    }
  } else {
    if (stats.ones_trigger[pos] != 0 ||
        stats.ones_notrigger[pos] != stats.notrigger_patterns_total) {
      return false;
    }
  }
  return literal_rejects_extra_negatives(trojan,
                                         node_idx,
                                         expected,
                                         extra_neg_patterns);
}

bool reduce_model_to_stats_literal(const circuit& trojan,
                                   const PatternStats& stats,
                                   const std::vector<std::vector<int>>& extra_neg_patterns,
                                   MiningResult* result) {
  if (!result) {
    return false;
  }
  for (const auto& rule : result->model.rules) {
    for (const auto& term : rule.terms) {
      if (term.first >= result->feature_nodes.size()) {
        continue;
      }
      const int node_idx = result->feature_nodes[term.first];
      const int expected = term.second ? 1 : 0;
      if (!literal_matches_stats_trigger(trojan,
                                         stats,
                                         extra_neg_patterns,
                                         node_idx,
                                         expected)) {
        continue;
      }
      const std::size_t feature_idx = term.first;
      result->model.rules.clear();
      result->model.rules.push_back(make_literal_rule(feature_idx, expected));
      refresh_model_rule_metadata(&result->model);
      cout << "trigger_stats_literal "
           << trojan.node_name(node_idx)
           << "=" << expected << "\n";
      return true;
    }
  }
  return false;
}

SigWord word_mask_for(const TriggerSignatureContext& ctx, std::size_t w) {
  return (w + 1 == ctx.words) ? ctx.last_mask : ~SigWord(0);
}

const SigWord* node_sig_ptr(const TriggerSignatureContext& ctx,
                            std::size_t node_pos) {
  return ctx.node_sigs.data() + node_pos * ctx.words;
}

bool sig_equal_to_words(const std::vector<SigWord>& a,
                        const SigWord* b,
                        const TriggerSignatureContext& ctx) {
  if (a.size() != ctx.words) {
    return false;
  }
  for (std::size_t w = 0; w < ctx.words; ++w) {
    const SigWord mask = word_mask_for(ctx, w);
    if ((a[w] & mask) != (b[w] & mask)) {
      return false;
    }
  }
  return true;
}

bool sig_equal(const std::vector<SigWord>& a,
               const std::vector<SigWord>& b,
               const TriggerSignatureContext& ctx) {
  if (a.size() != ctx.words || b.size() != ctx.words) {
    return false;
  }
  for (std::size_t w = 0; w < ctx.words; ++w) {
    const SigWord mask = word_mask_for(ctx, w);
    if ((a[w] & mask) != (b[w] & mask)) {
      return false;
    }
  }
  return true;
}

std::size_t sig_mismatch_count(const std::vector<SigWord>& a,
                               const std::vector<SigWord>& b,
                               const TriggerSignatureContext& ctx) {
  std::size_t count = 0;
  for (std::size_t w = 0; w < ctx.words; ++w) {
    const SigWord mask = word_mask_for(ctx, w);
    count += static_cast<std::size_t>(
        __builtin_popcountll((a[w] ^ b[w]) & mask));
  }
  return count;
}

int sig_bit(const std::vector<SigWord>& sig, std::size_t row) {
  return static_cast<int>((sig[row / 64] >> (row % 64)) & SigWord(1));
}

int literal_bit(const TriggerSignatureContext& ctx,
                std::size_t node_pos,
                int expected,
                std::size_t row) {
  const SigWord* sig = node_sig_ptr(ctx, node_pos);
  const int bit = static_cast<int>((sig[row / 64] >> (row % 64)) & SigWord(1));
  return expected ? bit : (bit ? 0 : 1);
}

void collect_signature_nontrigger_patterns(
    const circuit& golden,
    const circuit& trojan,
    std::size_t target_count,
    std::vector<std::vector<int>>* out) {
  if (!out || out->size() >= target_count || target_count == 0) {
    return;
  }

  circuit golden_eval = golden;
  circuit trojan_eval = trojan;
  packed_circuit golden_packed(golden_eval);
  packed_circuit trojan_packed(trojan_eval);
  golden_packed.prepare_batch();
  trojan_packed.prepare_batch();

  std::mt19937_64 rng(0x7631a5f00dULL);
  const std::size_t pi_count = golden.pi_count();
  const std::size_t max_attempts = target_count * 200 + 2000;
  std::vector<SigWord> pi_bits(pi_count, 0);
  std::size_t attempts = 0;

  while (out->size() < target_count && attempts < max_attempts) {
    const std::size_t block_size =
        std::min<std::size_t>(packed_circuit::kWordBits,
                              max_attempts - attempts);
    if (block_size == 0) {
      break;
    }
    for (std::size_t i = 0; i < pi_count; ++i) {
      pi_bits[i] = rng();
    }

    try {
      golden_packed.simulate_bits_fast(pi_bits.data(), block_size);
      trojan_packed.simulate_bits_fast(pi_bits.data(), block_size);
    } catch (const std::exception&) {
      attempts += block_size;
      continue;
    }

    const SigWord mask = packed_circuit::mask_for_count(block_size);
    SigWord diff = 0;
    for (std::size_t o = 0; o < trojan_eval.po_count(); ++o) {
      diff |= (golden_packed.po_bits(o) ^ trojan_packed.po_bits(o));
    }
    SigWord accept = mask & ~diff;
    while (accept && out->size() < target_count) {
      const SigWord lsb = accept & (~accept + SigWord(1));
      const std::size_t bit =
          static_cast<std::size_t>(__builtin_ctzll(lsb));
      std::vector<int> pattern(pi_count, 0);
      for (std::size_t i = 0; i < pi_count; ++i) {
        pattern[i] = static_cast<int>((pi_bits[i] >> bit) & SigWord(1));
      }
      out->push_back(std::move(pattern));
      accept &= (accept - 1);
    }
    attempts += block_size;
  }
}

bool build_trigger_signature_context(
    const circuit& golden,
    const circuit& trojan,
    const PatternStats& stats,
    const std::vector<std::vector<int>>& extra_neg_patterns,
    const std::vector<int>& model_feature_nodes,
    const std::vector<int>& candidate_nodes,
    TriggerSignatureContext* ctx,
    std::string* error) {
  if (error) {
    error->clear();
  }
  if (!ctx) {
    if (error) *error = "signature context output pointer is null";
    return false;
  }
  *ctx = TriggerSignatureContext{};
  if (stats.trigger_patterns.empty()) {
    if (error) *error = "no trigger patterns for signature minimization";
    return false;
  }

  constexpr std::size_t kMaxSignatureNegatives = 65536;
  std::vector<std::vector<int>> neg_patterns;
  neg_patterns.reserve(std::min(kMaxSignatureNegatives,
                                extra_neg_patterns.size() + stats.trigger_patterns.size()));
  for (const auto& pat : extra_neg_patterns) {
    if (pat.size() == golden.pi_count()) {
      neg_patterns.push_back(pat);
      if (neg_patterns.size() >= kMaxSignatureNegatives) {
        break;
      }
    }
  }
  const std::size_t target_neg =
      std::min<std::size_t>(kMaxSignatureNegatives,
                            std::max<std::size_t>(stats.trigger_patterns.size(), 64));
  collect_signature_nontrigger_patterns(golden, trojan, target_neg,
                                        &neg_patterns);

  ctx->pos_count = stats.trigger_patterns.size();
  ctx->neg_count = neg_patterns.size();
  ctx->total_count = ctx->pos_count + ctx->neg_count;
  ctx->words = (ctx->total_count + 63) / 64;
  ctx->last_mask =
      packed_circuit::mask_for_count(ctx->total_count % 64 == 0
                                         ? 64
                                         : ctx->total_count % 64);
  if (ctx->words == 0 || ctx->total_count == 0) {
    if (error) *error = "empty signature pattern set";
    return false;
  }

  auto add_node = [&](int idx) {
    if (idx < 0 || static_cast<std::size_t>(idx) >= trojan.node_count()) {
      return;
    }
    const cell& c = trojan.get_cell(idx);
    if (c.ctype == CType::UNDEF) {
      return;
    }
    if (ctx->node_pos.find(idx) != ctx->node_pos.end()) {
      return;
    }
    ctx->node_pos[idx] = ctx->nodes.size();
    ctx->nodes.push_back(idx);
  };
  for (int idx : model_feature_nodes) {
    add_node(idx);
  }
  for (int idx : candidate_nodes) {
    add_node(idx);
  }
  if (ctx->nodes.empty()) {
    if (error) *error = "no nodes for signature minimization";
    return false;
  }

  ctx->target_sig.assign(ctx->words, 0);
  ctx->node_sigs.assign(ctx->nodes.size() * ctx->words, 0);

  circuit sim_net = trojan;
  packed_circuit sim(sim_net);
  sim.prepare_batch();
  std::vector<SigWord> pi_bits(trojan.pi_count(), 0);

  for (std::size_t offset = 0; offset < ctx->total_count; offset += 64) {
    const std::size_t block_count =
        std::min<std::size_t>(64, ctx->total_count - offset);
    std::fill(pi_bits.begin(), pi_bits.end(), SigWord(0));
    for (std::size_t b = 0; b < block_count; ++b) {
      const std::size_t row = offset + b;
      const std::vector<int>& pattern =
          row < ctx->pos_count ? stats.trigger_patterns[row]
                               : neg_patterns[row - ctx->pos_count];
      if (pattern.size() != pi_bits.size()) {
        if (error) *error = "signature pattern PI count mismatch";
        return false;
      }
      if (row < ctx->pos_count) {
        ctx->target_sig[offset / 64] |= (SigWord(1) << b);
      }
      for (std::size_t pi = 0; pi < pi_bits.size(); ++pi) {
        if (pattern[pi]) {
          pi_bits[pi] |= (SigWord(1) << b);
        }
      }
    }

    try {
      sim.simulate_bits_fast(pi_bits.data(), block_count);
    } catch (const std::exception& e) {
      if (error) *error = std::string("signature simulation error: ") + e.what();
      return false;
    }

    const SigWord mask = packed_circuit::mask_for_count(block_count);
    const std::size_t word = offset / 64;
    for (std::size_t ni = 0; ni < ctx->nodes.size(); ++ni) {
      ctx->node_sigs[ni * ctx->words + word] =
          sim.node_bits(ctx->nodes[ni]) & mask;
    }
  }

  return true;
}

bool compute_rule_signature(const TriggerSignatureContext& ctx,
                            const std::vector<int>& feature_nodes,
                            const DecisionTreeRule& rule,
                            std::vector<SigWord>* out) {
  if (!out) {
    return false;
  }
  out->assign(ctx.words, 0);
  for (std::size_t w = 0; w < ctx.words; ++w) {
    (*out)[w] = word_mask_for(ctx, w);
  }
  for (const auto& term : rule.terms) {
    if (term.first >= feature_nodes.size()) {
      return false;
    }
    auto it = ctx.node_pos.find(feature_nodes[term.first]);
    if (it == ctx.node_pos.end()) {
      return false;
    }
    const SigWord* sig = node_sig_ptr(ctx, it->second);
    for (std::size_t w = 0; w < ctx.words; ++w) {
      const SigWord mask = word_mask_for(ctx, w);
      const SigWord lit = term.second ? sig[w] : ((~sig[w]) & mask);
      (*out)[w] &= lit;
    }
  }
  return true;
}

bool compute_model_signature(const TriggerSignatureContext& ctx,
                             const std::vector<int>& feature_nodes,
                             const DecisionTreeModel& model,
                             std::vector<SigWord>* out) {
  if (!out) {
    return false;
  }
  out->assign(ctx.words, 0);
  std::vector<SigWord> rule_sig;
  for (const auto& rule : model.rules) {
    if (!compute_rule_signature(ctx, feature_nodes, rule, &rule_sig)) {
      return false;
    }
    for (std::size_t w = 0; w < ctx.words; ++w) {
      (*out)[w] |= rule_sig[w];
      (*out)[w] &= word_mask_for(ctx, w);
    }
  }
  return true;
}

bool find_literal_for_signature(const TriggerSignatureContext& ctx,
                                const std::vector<SigWord>& target,
                                int* node_idx,
                                int* expected) {
  if (node_idx) *node_idx = -1;
  if (expected) *expected = 1;
  for (std::size_t ni = 0; ni < ctx.nodes.size(); ++ni) {
    const SigWord* sig = node_sig_ptr(ctx, ni);
    if (sig_equal_to_words(target, sig, ctx)) {
      if (node_idx) *node_idx = ctx.nodes[ni];
      if (expected) *expected = 1;
      return true;
    }
    bool inv_equal = true;
    for (std::size_t w = 0; w < ctx.words; ++w) {
      const SigWord mask = word_mask_for(ctx, w);
      if ((target[w] & mask) != ((~sig[w]) & mask)) {
        inv_equal = false;
        break;
      }
    }
    if (inv_equal) {
      if (node_idx) *node_idx = ctx.nodes[ni];
      if (expected) *expected = 0;
      return true;
    }
  }
  return false;
}

std::size_t ensure_feature_for_node(std::vector<int>* feature_nodes,
                                    int node_idx) {
  for (std::size_t i = 0; i < feature_nodes->size(); ++i) {
    if ((*feature_nodes)[i] == node_idx) {
      return i;
    }
  }
  feature_nodes->push_back(node_idx);
  return feature_nodes->size() - 1;
}

DecisionTreeRule make_literal_rule(std::size_t feature_idx, int expected) {
  DecisionTreeRule rule;
  rule.terms.push_back({feature_idx, expected ? 1 : 0});
  return rule;
}

bool solve_hitting_set_exact(const std::vector<uint64_t>& constraints,
                             std::size_t term_count,
                             uint64_t* out_subset) {
  if (!out_subset || term_count == 0 || term_count > 22) {
    return false;
  }
  auto hits_all = [&](uint64_t subset) {
    for (uint64_t c : constraints) {
      if ((subset & c) == 0) {
        return false;
      }
    }
    return true;
  };
  for (std::size_t want = 1; want <= term_count; ++want) {
    bool found = false;
    uint64_t found_subset = 0;
    std::function<void(std::size_t, std::size_t, uint64_t)> dfs =
        [&](std::size_t start, std::size_t left, uint64_t subset) {
          if (found) {
            return;
          }
          if (left == 0) {
            if (hits_all(subset)) {
              found = true;
              found_subset = subset;
            }
            return;
          }
          for (std::size_t i = start; i <= term_count - left; ++i) {
            dfs(i + 1, left - 1, subset | (uint64_t{1} << i));
            if (found) {
              return;
            }
          }
        };
    dfs(0, want, 0);
    if (found) {
      *out_subset = found_subset;
      return true;
    }
  }
  return false;
}

uint64_t solve_hitting_set_greedy(const std::vector<uint64_t>& constraints,
                                  std::size_t term_count) {
  std::vector<char> covered(constraints.size(), 0);
  std::size_t remaining = constraints.size();
  uint64_t subset = 0;
  while (remaining > 0) {
    std::size_t best_term = term_count;
    std::size_t best_gain = 0;
    for (std::size_t ti = 0; ti < term_count; ++ti) {
      if (subset & (uint64_t{1} << ti)) {
        continue;
      }
      std::size_t gain = 0;
      for (std::size_t ci = 0; ci < constraints.size(); ++ci) {
        if (!covered[ci] && (constraints[ci] & (uint64_t{1} << ti))) {
          gain += 1;
        }
      }
      if (gain > best_gain) {
        best_gain = gain;
        best_term = ti;
      }
    }
    if (best_term >= term_count || best_gain == 0) {
      return (term_count >= 64) ? ~uint64_t{0}
                                : ((uint64_t{1} << term_count) - 1);
    }
    subset |= (uint64_t{1} << best_term);
    for (std::size_t ci = 0; ci < constraints.size(); ++ci) {
      if (!covered[ci] && (constraints[ci] & (uint64_t{1} << best_term))) {
        covered[ci] = 1;
        remaining -= 1;
      }
    }
  }
  return subset;
}

bool minimize_rule_literals_by_signature(
    const TriggerSignatureContext& ctx,
    const std::vector<int>& feature_nodes,
    const DecisionTreeRule& rule,
    const std::vector<SigWord>& original_sig,
    DecisionTreeRule* out_rule) {
  if (!out_rule) {
    return false;
  }
  *out_rule = rule;
  const std::size_t term_count = rule.terms.size();
  if (term_count <= 1 || term_count > 63) {
    return false;
  }

  std::vector<std::size_t> node_positions;
  node_positions.reserve(term_count);
  for (const auto& term : rule.terms) {
    if (term.first >= feature_nodes.size()) {
      return false;
    }
    auto it = ctx.node_pos.find(feature_nodes[term.first]);
    if (it == ctx.node_pos.end()) {
      return false;
    }
    node_positions.push_back(it->second);
  }

  std::unordered_set<uint64_t> unique_constraints;
  for (std::size_t row = 0; row < ctx.total_count; ++row) {
    if (sig_bit(original_sig, row)) {
      continue;
    }
    uint64_t violated = 0;
    for (std::size_t ti = 0; ti < term_count; ++ti) {
      const int lit_ok = literal_bit(ctx,
                                     node_positions[ti],
                                     rule.terms[ti].second,
                                     row);
      if (!lit_ok) {
        violated |= (uint64_t{1} << ti);
      }
    }
    if (violated == 0) {
      return false;
    }
    unique_constraints.insert(violated);
  }

  if (unique_constraints.empty()) {
    return false;
  }
  std::vector<uint64_t> constraints(unique_constraints.begin(),
                                    unique_constraints.end());
  uint64_t subset = 0;
  const bool exact_ok =
      solve_hitting_set_exact(constraints, term_count, &subset);
  if (!exact_ok) {
    subset = solve_hitting_set_greedy(constraints, term_count);
  }
  if (__builtin_popcountll(subset) >= static_cast<int>(term_count)) {
    return false;
  }

  DecisionTreeRule minimized;
  for (std::size_t ti = 0; ti < term_count; ++ti) {
    if (subset & (uint64_t{1} << ti)) {
      minimized.terms.push_back(rule.terms[ti]);
    }
  }
  std::sort(minimized.terms.begin(), minimized.terms.end());

  std::vector<SigWord> check_sig;
  if (!compute_rule_signature(ctx, feature_nodes, minimized, &check_sig) ||
      !sig_equal(check_sig, original_sig, ctx)) {
    return false;
  }

  *out_rule = std::move(minimized);
  return true;
}

bool signature_minimize_trigger_model(
    const circuit& golden,
    const circuit& trojan,
    const PatternStats& stats,
    const std::vector<std::vector<int>>& extra_neg_patterns,
    const std::vector<int>& candidate_nodes,
    MiningResult* result,
    TriggerSigStats* sig_stats,
    std::string* error) {
  if (error) {
    error->clear();
  }
  if (sig_stats) {
    *sig_stats = TriggerSigStats{};
  }
  if (!result || result->model.rules.empty()) {
    return true;
  }

  TriggerSignatureContext ctx;
  if (!build_trigger_signature_context(golden,
                                       trojan,
                                       stats,
                                       extra_neg_patterns,
                                       result->feature_nodes,
                                       candidate_nodes,
                                       &ctx,
                                       error)) {
    return false;
  }

  TriggerSigStats local;
  local.rules_before = result->model.rules.size();
  local.literals_before = count_model_literals(result->model);
  const DecisionTreeModel original_model = result->model;
  const std::vector<int> original_feature_nodes = result->feature_nodes;

  int whole_node = -1;
  int whole_expected = 1;
  if (find_literal_for_signature(ctx, ctx.target_sig,
                                 &whole_node, &whole_expected)) {
    const std::size_t feature_idx =
        ensure_feature_for_node(&result->feature_nodes, whole_node);
    result->model.rules.clear();
    result->model.rules.push_back(make_literal_rule(feature_idx,
                                                    whole_expected));
    local.single_model = 1;
  } else {
    std::vector<DecisionTreeRule> new_rules;
    new_rules.reserve(result->model.rules.size());
    for (const auto& rule : result->model.rules) {
      std::vector<SigWord> rule_sig;
      if (!compute_rule_signature(ctx, result->feature_nodes, rule, &rule_sig)) {
        new_rules.push_back(rule);
        continue;
      }

      int node_idx = -1;
      int expected = 1;
      if (find_literal_for_signature(ctx, rule_sig, &node_idx, &expected)) {
        const std::size_t feature_idx =
            ensure_feature_for_node(&result->feature_nodes, node_idx);
        new_rules.push_back(make_literal_rule(feature_idx, expected));
        local.single_rule += 1;
        continue;
      }

      DecisionTreeRule minimized;
      if (minimize_rule_literals_by_signature(ctx,
                                              result->feature_nodes,
                                              rule,
                                              rule_sig,
                                              &minimized)) {
        new_rules.push_back(std::move(minimized));
        local.hit_rules += 1;
      } else {
        new_rules.push_back(rule);
      }
    }
    result->model.rules = std::move(new_rules);
    simplify_rules(&result->model.rules);
  }

  refresh_model_rule_metadata(&result->model);
  local.rules_after = result->model.rules.size();
  local.literals_after = count_model_literals(result->model);

  std::vector<SigWord> final_sig;
  const bool final_signature_ok =
      compute_model_signature(ctx, result->feature_nodes, result->model,
                              &final_sig);
  if (final_signature_ok) {
    local.exact_mismatches =
        sig_mismatch_count(final_sig, ctx.target_sig, ctx);
  } else {
    local.exact_mismatches = ctx.total_count;
  }

  cout << "trigger_sig_patterns pos " << ctx.pos_count
       << " neg " << ctx.neg_count
       << " nodes " << ctx.nodes.size()
       << " words " << ctx.words << "\n";
  cout << "trigger_sig_minimize rules " << local.rules_before
       << " -> " << local.rules_after
       << " literals " << local.literals_before
       << " -> " << local.literals_after
       << " single_model " << local.single_model
       << " single_rule " << local.single_rule
       << " hit_rules " << local.hit_rules
       << " exact_mismatch " << local.exact_mismatches << "\n";

  if (sig_stats) {
    *sig_stats = local;
  }
  if (!final_signature_ok || local.exact_mismatches != 0) {
    result->model = original_model;
    result->feature_nodes = original_feature_nodes;
    if (error) {
      *error = !final_signature_ok
                   ? "could not verify minimized trigger signature"
                   : "minimized trigger signature changed " +
                         std::to_string(local.exact_mismatches) +
                         " sampled classifications";
    }
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  auto t_main_start = std::chrono::steady_clock::now();
  auto t_phase = t_main_start;
  auto ms_since = [](auto start) {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();
  };

  AppOptions options;
  string error;
  const ParseStatus status = parse_cli_options(argc, argv, &options, &error);
  if (status == ParseStatus::help) {
    print_usage(argv[0]);
    return 0;
  }
  if (status == ParseStatus::error) {
    if (!error.empty()) {
      cerr << error << "\n";
    }
    print_usage(argv[0]);
    return 1;
  }

  circuit golden;
  circuit trojan;
  if (!bench_io::parse_bench_file(options.golden_path, golden, &error)) {
    cerr << "Golden parse error: " << error << "\n";
    return 1;
  }
  if (!bench_io::parse_bench_file(options.trojan_path, trojan, &error)) {
    cerr << "Trojan parse error: " << error << "\n";
    return 1;
  }

  if (!align_circuits(golden, trojan, &error)) {
    cerr << "Circuit alignment error: " << error << "\n";
    return 1;
  }
  cerr << "[TIMING] parse+align: " << ms_since(t_phase) << " ms\n";
  t_phase = std::chrono::steady_clock::now();

  const string& groundtruth_path = options.groundtruth_path;
  cout << "groundtruth " << groundtruth_path << "\n";

  cout << "depth " << options.max_depth
       << " neg_ratio " << options.neg_ratio
       << " mine_rounds " << options.mine_rounds
       << " mine_max " << options.mine_max
       << " rule_method " << rule_method_name(options.rule_method)
       << " force_split " << (options.force_split ? 1 : 0)
       << " strict_retry " << (options.strict_retry ? 1 : 0) << "\n";
  if (options.rule_method == RuleMethod::z3_pb) {
    cout << "rule_optimizer_config"
         << " timeout_ms " << options.rule_opt_timeout_ms
         << " max_rounds " << options.rule_opt_max_rounds
         << " cex_batch " << options.rule_opt_cex_batch
         << " max_clauses " << options.rule_opt_max_clauses
         << " max_literals " << options.rule_opt_max_literals << "\n";
  }

  const int kMaxCecRounds = 5;
  std::vector<std::vector<int>> extra_trigger_patterns;
  std::vector<std::vector<int>> extra_nontrigger_patterns;
  int cec_round = 0;
  string fix_output_path;

  for (cec_round = 0; cec_round < kMaxCecRounds; ++cec_round) {

  circuit working_trojan = trojan;
  PatternStats stats;
  MiningResult result;
  NegSampleTrace neg_trace;
  bool did_rule_merge = false;
  int merged_match_idx = -1;
  bool fix_succeeded = false;
  bool trigger_sig_single_kill = false;
  std::size_t synth_pass = 0;

  if (cec_round > 0) {
    cout << "cec_retry_round " << cec_round + 1 << "\n";
  }

  while (true) {
    synth_pass += 1;
    RuleSynthTelemetry rule_synth_telemetry;
    auto add_mining_telemetry = [&](const MiningResult& mining_result) {
      rule_synth_telemetry.dt_builds += mining_result.dt_builds;
      rule_synth_telemetry.strict_dt_builds += mining_result.strict_dt_builds;
      rule_synth_telemetry.training_data_builds +=
          mining_result.training_data_builds;
      rule_synth_telemetry.optimizer_calls +=
          mining_result.rule_optimizer_calls;
      rule_synth_telemetry.optimizer_accepted +=
          mining_result.rule_optimizer_accepted;
      rule_synth_telemetry.optimizer_checks +=
          mining_result.rule_optimizer_checks;
      rule_synth_telemetry.optimizer_counterexamples +=
          mining_result.rule_optimizer_counterexamples;
      rule_synth_telemetry.optimizer_solver_ms +=
          mining_result.rule_optimizer_solver_ms;
      if (mining_result.rule_optimizer_calls != 0) {
        rule_synth_telemetry.optimizer_stats =
            mining_result.rule_optimizer_stats;
      }
    };
    t_phase = std::chrono::steady_clock::now();
    try {
      if (!build_stats_from_groundtruth(golden, working_trojan, groundtruth_path, &stats, &error)) {
        cerr << "Groundtruth error: " << error << "\n";
        return 1;
      }
    } catch (const std::exception& e) {
      cerr << "Groundtruth parse error: " << e.what() << "\n";
      return 1;
    }
    cerr << "[TIMING] build_stats (GPU sim): " << ms_since(t_phase) << " ms\n";

    // Append CEC counter-example patterns from previous rounds.
    if (!extra_trigger_patterns.empty()) {
      for (const auto& ep : extra_trigger_patterns) {
        stats.trigger_patterns.push_back(ep);
      }
      stats.trigger_patterns_total = stats.trigger_patterns.size();
      stats.mismatch_patterns = stats.trigger_patterns_total;
      cout << "cec_extra_patterns " << extra_trigger_patterns.size()
           << " total_trigger " << stats.trigger_patterns_total << "\n";
    }
    const std::vector<std::vector<int>>* extra_neg_patterns =
        extra_nontrigger_patterns.empty() ? nullptr : &extra_nontrigger_patterns;
    if (!extra_nontrigger_patterns.empty()) {
      cout << "cec_extra_neg_patterns " << extra_nontrigger_patterns.size()
           << "\n";
    }

    cout << "pattern_total " << stats.total_patterns << "\n";
    cout << "trigger_patterns " << stats.trigger_patterns_total << "\n";
    cout << "notrigger_patterns " << stats.notrigger_patterns_total << "\n";
    const double trojan_rate = compute_trojan_rate(stats);
    cout << "trojan_rates " << trojan_rate << '\n';
    cout << fixed << setprecision(4);

    t_phase = std::chrono::steady_clock::now();
    vector<CandidateInfo> candidates;
    if (!build_candidates(stats,
                          &candidates,
                          &error)) {
      cerr << error << "\n";
      return 1;
    }

    vector<int> candidate_indices = candidate_gate_indices(candidates);
    cerr << "[TIMING] build_candidates: " << ms_since(t_phase) << " ms\n";

    bool filter_rule_opt = did_rule_merge;
    if (!filter_rule_opt) {
      bool has_rule_opt = false;
      bool has_rule_match = false;
      for (std::size_t i = 0; i < working_trojan.node_count(); ++i) {
        const std::string& name = working_trojan.node_name(static_cast<int>(i));
        if (!has_rule_opt && name.rfind("rule_opt_gate_", 0) == 0) {
          has_rule_opt = true;
        }
        if (!has_rule_match && name.rfind("rule_match_", 0) == 0) {
          has_rule_match = true;
        }
        if (has_rule_opt && has_rule_match) {
          break;
        }
      }
      filter_rule_opt = has_rule_opt && has_rule_match;
    }

    if (filter_rule_opt) {
      std::vector<int> filtered;
      filtered.reserve(candidate_indices.size());
      for (int idx : candidate_indices) {
        const std::string& name = working_trojan.node_name(idx);
        if (name.rfind("rule_opt_gate_", 0) == 0) {
          continue;
        }
        filtered.push_back(idx);
      }
      candidate_indices.swap(filtered);
    }

    if (merged_match_idx >= 0 &&
        std::find(candidate_indices.begin(),
                  candidate_indices.end(),
                  merged_match_idx) == candidate_indices.end()) {
      candidate_indices.push_back(merged_match_idx);
    }
    rule_synth_telemetry.candidate_count = candidate_indices.size();

    const auto t_rule_synth = std::chrono::steady_clock::now();

    // --- Virtual node feature preprocessing (iterative multi-pass) ---
    // Virtual features are computed on-the-fly from simulation results.
    // The circuit is NOT modified during the VN iteration phase.
    // After iterations, only used VNs are inserted into the circuit.
    t_phase = std::chrono::steady_clock::now();
    std::vector<VirtualNodeDef> final_vn_defs;  // VN defs for the SAT loop.
    if (options.rule_method == RuleMethod::vn_retrain) {
      // Collect base candidates (exclude any previously added virtual nodes).
      std::vector<int> base_for_vn;
      base_for_vn.reserve(candidate_indices.size());
      for (int idx : candidate_indices) {
        const std::string& nm = working_trojan.node_name(idx);
        if (nm.rfind("vn_", 0) != 0) {
          base_for_vn.push_back(idx);
        }
      }

      if (base_for_vn.size() >= 2) {
        // Phase 1: Quick tree training to identify important features.
        MiningOptions phase1_opts;
        phase1_opts.max_depth = options.max_depth;
        phase1_opts.neg_ratio = options.neg_ratio;
        phase1_opts.eval_count = 0;
        phase1_opts.mine_rounds = 1;
        phase1_opts.mine_max = 0;
        phase1_opts.include_pi = options.include_pi;
        phase1_opts.force_split = options.force_split;
        phase1_opts.strict_retry = false;

        MiningResult phase1_result;
        string phase1_error;
        bool phase1_ok = run_mining(golden, working_trojan,
                                     stats.trigger_patterns,
                                     base_for_vn, phase1_opts,
                                     trojan_rate, extra_neg_patterns, nullptr,
                                     &phase1_result, &phase1_error);
        add_mining_telemetry(phase1_result);
        if (phase1_ok && !phase1_result.model.rules.empty()) {
          rule_synth_telemetry.phase_rules =
              phase1_result.model.rules.size();
          rule_synth_telemetry.phase_literals =
              count_model_literals(phase1_result.model);
          rule_synth_telemetry.phase_depth =
              phase1_result.model.max_depth_used;
          // Extract circuit node indices actually used by the tree.
          unordered_set<int> used_set;
          for (const auto& rule : phase1_result.model.rules) {
            for (const auto& term : rule.terms) {
              if (term.first < phase1_result.feature_nodes.size()) {
                used_set.insert(
                    phase1_result.feature_nodes[term.first]);
              }
            }
          }
          vector<int> important_signals(used_set.begin(), used_set.end());
          sort(important_signals.begin(), important_signals.end());

          cout << "vn_phase1_rules " << phase1_result.model.rules.size()
               << " important_signals " << important_signals.size()
               << " from_candidates " << base_for_vn.size() << "\n";

          size_t phase1_literal_count = 0;
          for (const auto& rule : phase1_result.model.rules) {
            phase1_literal_count += rule.terms.size();
          }

          if (phase1_result.model.rules.size() == 1 &&
              phase1_literal_count <= 1) {
            cout << "vn_signature_skip single_literal_phase1\n";
          } else {
            // Phase 2: Generate virtual nodes only through signature DP.
            // No structural fallback and no rule-mined expansion.
            std::vector<VirtualNodeDef> all_vn_defs;
            vector<int> signature_base = build_signature_base_pool(
                stats, base_for_vn, important_signals, 64);
            cout << "vn_signature_base " << signature_base.size()
                 << " important " << important_signals.size()
                 << " from_candidates " << base_for_vn.size() << "\n";
            if (signature_base.size() >= 2) {
              const std::size_t max_arity =
                  (signature_base.size() <= 64) ? 3 : 2;
              vector<vector<int>> sig_pos =
                  select_spread_patterns(stats.trigger_patterns, 32);
              vector<vector<int>> sig_neg =
                  select_spread_patterns(extra_nontrigger_patterns, 16);
              const size_t sig_neg_target =
                  min<size_t>(32, max<size_t>(8, sig_pos.size()));
              collect_random_nontrigger_patterns(golden,
                                                 working_trojan,
                                                 sig_neg_target,
                                                 &sig_neg);

              SignatureVirtualOptions sig_opts;
              sig_opts.max_arity = max_arity;
              sig_opts.max_candidates = 300;
              sig_opts.max_pair_states = 300;
              SignatureVirtualStats sig_stats;
              string sig_error;
              const bool sig_ok = generate_signature_virtual_candidates(
                  working_trojan,
                  signature_base,
                  sig_pos,
                  sig_neg,
                  sig_opts,
                  &all_vn_defs,
                  &sig_stats,
                  &sig_error);
              if (!sig_ok) {
                cerr << "vn_signature_dp error: " << sig_error
                     << "; skipping virtual nodes\n";
                all_vn_defs.clear();
              }
              rule_synth_telemetry.vn_generated = all_vn_defs.size();
              cout << "vn_signature_patterns pos " << sig_pos.size()
                   << " neg " << sig_neg.size() << "\n";
              cout << "vn_signature_dp selected " << all_vn_defs.size()
                   << " base " << signature_base.size()
                   << " patterns " << sig_stats.pattern_count
                   << " pair_states " << sig_stats.pair_states
                   << " triple_ext " << sig_stats.triple_states
                   << " max_arity " << max_arity << "\n";
            }

            // Phase 3: Train once with the signature VNs to see which rules
            // the model can learn from the virtual features.
            if (!all_vn_defs.empty()) {
              cout << "vn_phase2_total " << all_vn_defs.size()
                   << " (virtual, circuit unchanged)\n";

              MiningOptions iter_opts;
              iter_opts.max_depth = options.max_depth;
              iter_opts.neg_ratio = options.neg_ratio;
              iter_opts.eval_count = 0;
              iter_opts.mine_rounds = 1;
              iter_opts.mine_max = 0;
              iter_opts.include_pi = options.include_pi;
              iter_opts.force_split = options.force_split;
              iter_opts.strict_retry = false;

              MiningResult iter_result;
              string iter_error;
              bool iter_ok = run_mining(golden, working_trojan,
                                         stats.trigger_patterns,
                                         base_for_vn, iter_opts,
                                         trojan_rate, extra_neg_patterns, nullptr,
                                         &iter_result, &iter_error,
                                         &all_vn_defs);
              add_mining_telemetry(iter_result);
              if (!iter_ok || iter_result.model.rules.empty()) {
                if (!iter_error.empty()) {
                  cerr << "vn_iter1 error: " << iter_error << "\n";
                }
              } else {
                const std::size_t iter_rules =
                    iter_result.model.rules.size();
                cout << "vn_iter1_rules " << iter_rules
                     << " vn_count " << all_vn_defs.size() << "\n";
                final_vn_defs = std::move(all_vn_defs);
                cout << "vn_best_rules " << iter_rules
                     << " vn_count " << final_vn_defs.size() << "\n";
              }
            }
          }
        } else {
          if (!phase1_error.empty()) {
            cerr << "virtual_node phase1 error: " << phase1_error << "\n";
          }
        }
      }
    }

    // --- Insert only used virtual nodes into the circuit ---
    // This happens BEFORE the SAT refinement loop, so the circuit
    // has only the VNs that actually appear in the best tree rules.
    // A final training pass determines which VNs are used.
    if (!final_vn_defs.empty()) {
      // Do one final training pass with the best VN set to identify
      // which VNs are actually referenced in the rules.
      MiningOptions final_vn_opts;
      final_vn_opts.max_depth = options.max_depth;
      final_vn_opts.neg_ratio = options.neg_ratio;
      final_vn_opts.eval_count = 0;
      final_vn_opts.mine_rounds = 1;
      final_vn_opts.mine_max = 0;
      final_vn_opts.include_pi = options.include_pi;
      final_vn_opts.force_split = options.force_split;
      final_vn_opts.strict_retry = false;

      // Collect base candidates again.
      std::vector<int> base_for_insert;
      for (int idx : candidate_indices) {
        const std::string& nm = working_trojan.node_name(idx);
        if (nm.rfind("vn_", 0) != 0) {
          base_for_insert.push_back(idx);
        }
      }

      MiningResult final_vn_result;
      string final_vn_error;
      bool final_vn_ok = run_mining(golden, working_trojan,
                                     stats.trigger_patterns,
                                     base_for_insert, final_vn_opts,
                                     trojan_rate, extra_neg_patterns, nullptr,
                                     &final_vn_result, &final_vn_error,
                                     &final_vn_defs);
      add_mining_telemetry(final_vn_result);

      if (final_vn_ok && !final_vn_result.model.rules.empty()) {
        // Find which VN indices are used in the rules.
        const std::size_t first_vn_feat = final_vn_result.feature_nodes.size();
        std::unordered_set<std::size_t> used_vn_set;
        for (const auto& rule : final_vn_result.model.rules) {
          for (const auto& term : rule.terms) {
            if (term.first >= first_vn_feat) {
              used_vn_set.insert(term.first - first_vn_feat);
            }
          }
        }

        // Collect only the used VN definitions.
        std::vector<VirtualNodeDef> used_defs;
        std::vector<std::size_t> used_vn_indices;
        for (std::size_t i = 0; i < final_vn_defs.size(); ++i) {
          if (used_vn_set.count(i)) {
            used_vn_indices.push_back(i);
            used_defs.push_back(final_vn_defs[i]);
          }
        }

        if (!used_defs.empty()) {
          // Add only used VNs to the circuit.
          std::vector<int> vn_circuit_indices =
              add_virtual_gates_to_circuit(working_trojan, used_defs);
          for (int vi : vn_circuit_indices) {
            candidate_indices.push_back(vi);
          }
          cout << "vn_insert_used " << used_defs.size()
               << " from " << final_vn_defs.size()
               << " circuit_nodes " << working_trojan.node_count() << "\n";
        }
        rule_synth_telemetry.vn_used = used_defs.size();
        // Clear final_vn_defs since the used VNs are now in the circuit.
        final_vn_defs.clear();
      }
    }

    cerr << "[TIMING] virtual_node: " << ms_since(t_phase) << " ms\n";

    t_phase = std::chrono::steady_clock::now();
    {
      MiningOptions mining_options;
      mining_options.max_depth = options.max_depth;
      mining_options.neg_ratio = options.neg_ratio;
      mining_options.eval_count = 0;
      mining_options.mine_rounds = 1;
      mining_options.mine_max = 0;
      mining_options.include_pi = options.include_pi;
      mining_options.force_split = options.force_split;
      mining_options.strict_retry = options.strict_retry;
      mining_options.enable_rule_optimizer =
          options.rule_method == RuleMethod::z3_pb;
      mining_options.rule_optimizer_options.timeout_ms =
          options.rule_opt_timeout_ms;
      mining_options.rule_optimizer_options.max_rounds =
          options.rule_opt_max_rounds;
      mining_options.rule_optimizer_options.counterexample_batch_size =
          options.rule_opt_cex_batch;
      mining_options.rule_optimizer_options.max_clauses =
          options.rule_opt_max_clauses;
      mining_options.rule_optimizer_options.max_literals_per_clause =
          options.rule_opt_max_literals;

      if (!run_mining(golden,
                      working_trojan,
                      stats.trigger_patterns,
                      candidate_indices,
                      mining_options,
                      trojan_rate,
                      extra_neg_patterns,
                      &neg_trace,
                      &result,
                      &error)) {
        if (!error.empty()) {
          cerr << error << "\n";
        }
        return 1;
      }
      add_mining_telemetry(result);

      const size_t rules_before = result.model.rules.size();
      simplify_rules(&result.model.rules);
      if (result.model.rules.size() != rules_before) {
        refresh_model_rule_metadata(&result.model);
        cout << "rule_simplify " << rules_before
             << " -> " << result.model.rules.size() << "\n";
      } else {
        // Earlier per-rule minimization can reduce literal width without
        // changing the number of rules.
        refresh_model_rule_metadata(&result.model);
      }
    }
    cerr << "[TIMING] final_mining: " << ms_since(t_phase) << " ms\n";

    const double rule_synth_ms = ms_since(t_rule_synth);
    cout << "rule_synth_summary"
         << " strategy " << rule_method_name(options.rule_method)
         << " cec_attempt " << (cec_round + 1)
         << " synth_pass " << synth_pass
         << " candidate_count " << rule_synth_telemetry.candidate_count
         << " dt_builds " << rule_synth_telemetry.dt_builds
         << " strict_dt_builds " << rule_synth_telemetry.strict_dt_builds
         << " training_data_builds "
         << rule_synth_telemetry.training_data_builds
         << " vn_generated " << rule_synth_telemetry.vn_generated
         << " vn_used " << rule_synth_telemetry.vn_used
         << " phase_rules " << rule_synth_telemetry.phase_rules
         << " phase_literals " << rule_synth_telemetry.phase_literals
         << " phase_depth " << rule_synth_telemetry.phase_depth
         << " optimizer_status "
         << (rule_synth_telemetry.optimizer_calls == 0
                 ? "disabled"
                 : rule_synth_telemetry.optimizer_stats.status)
         << " optimizer_calls " << rule_synth_telemetry.optimizer_calls
         << " optimizer_accepted "
         << (rule_synth_telemetry.optimizer_stats.accepted ? 1 : 0)
         << " optimizer_accepted_calls "
         << rule_synth_telemetry.optimizer_accepted
         << " optimizer_optimal "
         << (rule_synth_telemetry.optimizer_stats.optimal ? 1 : 0)
         << " optimizer_verified "
         << (rule_synth_telemetry.optimizer_stats.verified ? 1 : 0)
         << " optimizer_candidates "
         << rule_synth_telemetry.optimizer_stats.unique_candidate_features
         << " optimizer_signatures "
         << rule_synth_telemetry.optimizer_stats.unique_pattern_signatures
         << " optimizer_checks " << rule_synth_telemetry.optimizer_checks
         << " optimizer_cex "
         << rule_synth_telemetry.optimizer_counterexamples
         << " optimizer_rules_before "
         << rule_synth_telemetry.optimizer_stats.rules_before
         << " optimizer_rules_after "
         << rule_synth_telemetry.optimizer_stats.rules_after
         << " optimizer_literals_before "
         << rule_synth_telemetry.optimizer_stats.literals_before
         << " optimizer_literals_after "
         << rule_synth_telemetry.optimizer_stats.literals_after
         << " optimizer_solver_ms "
         << rule_synth_telemetry.optimizer_solver_ms
         << " synthesized_rules " << result.model.rules.size()
         << " synthesized_literals " << count_model_literals(result.model)
         << " synthesized_depth " << max_model_rule_literals(result.model)
         // Legacy aliases retained for existing log parsers.  These fields
         // describe the synthesis output before downstream rule/signature
         // minimization, not necessarily the condition used by the patch.
         << " final_rules " << result.model.rules.size()
         << " final_literals " << count_model_literals(result.model)
         << " final_depth " << max_model_rule_literals(result.model)
         << " synth_ms " << rule_synth_ms << "\n";
    if (rule_synth_telemetry.optimizer_calls != 0 &&
        !rule_synth_telemetry.optimizer_stats.reason.empty()) {
      std::string safe_reason = rule_synth_telemetry.optimizer_stats.reason;
      for (char& ch : safe_reason) {
        if (ch == '\n' || ch == '\r' || ch == '\t') ch = ' ';
      }
      if (safe_reason.size() > 512) safe_reason.resize(512);
      cout << "rule_optimizer_reason " << std::quoted(safe_reason) << "\n";
    }

    t_phase = std::chrono::steady_clock::now();
    int effective_literal_node = -1;
    int effective_literal_expected = -1;
    int effective_literal_forced = -1;
    if (!fix_succeeded &&
        !(result.model.rules.size() == 1U &&
          result.model.rules[0].terms.size() == 1U)) {
      circuit literal_cut;
      int literal_cut_node = -1;
      int literal_cut_value = 0;
      long long literal_cut_area_delta = 0;
      long long literal_cut_level_delta = 0;
      std::string literal_cut_error;
      if (try_verified_literal_patch_cut(golden,
                                         working_trojan,
                                         stats,
                                         result,
                                         &literal_cut,
                                         &literal_cut_node,
                                         &literal_cut_value,
                                         &literal_cut_area_delta,
                                         &literal_cut_level_delta,
                                         &literal_cut_error)) {
        (void)literal_cut_node;
        (void)literal_cut_value;
        fix_output_path = options.output_path.empty()
                              ? derive_patched_path(options.trojan_path)
                              : options.output_path;
        if (!bench_io::write_bench_file(fix_output_path,
                                        literal_cut,
                                        &error)) {
          cerr << "Write error: " << error << "\n";
          return 1;
        }
        cout << "payload_fix_selected 1 area_delta "
             << literal_cut_area_delta
             << " level_delta " << literal_cut_level_delta << "\n";
        cout << "payload_fix_bench " << fix_output_path << "\n";
        effective_literal_node = literal_cut_node;
        effective_literal_expected = literal_cut_value ? 0 : 1;
        effective_literal_forced = literal_cut_value;
        fix_succeeded = true;
      } else if (!literal_cut_error.empty()) {
        cerr << "literal_patch_cut skipped: " << literal_cut_error << "\n";
      }
      cerr << "[TIMING] literal_patch_cut: " << ms_since(t_phase) << " ms\n";
    }

    t_phase = std::chrono::steady_clock::now();
    std::string rule_apply_source = "mined_model";
    bool rule_model_used = true;
    std::size_t signature_exact_mismatch = 0;
    if (fix_succeeded) {
      rule_apply_source = "literal_patch_cut";
      rule_model_used = false;
      cerr << "[TIMING] trigger_sig_minimize: 0 ms (patch cut selected)\n";
    } else if (reduce_model_to_stats_literal(working_trojan,
                                             stats,
                                             extra_nontrigger_patterns,
                                             &result)) {
      rule_apply_source = "stats_literal";
      trigger_sig_single_kill = true;
      cout << "stats_literal_kill_candidate 1\n";
      cerr << "[TIMING] trigger_sig_minimize: 0 ms (stats literal)\n";
    } else if (result.model.rules.size() == 1U &&
        result.model.rules[0].terms.size() == 1U) {
      rule_apply_source = "tree_single_literal";
      trigger_sig_single_kill = true;
      cout << "tree_single_literal_kill_candidate 1\n";
      cerr << "[TIMING] trigger_sig_minimize: 0 ms (skipped single literal)\n";
    } else {
      rule_apply_source = "signature_minimize";
      TriggerSigStats trigger_sig_stats;
      std::string trigger_sig_error;
      if (!signature_minimize_trigger_model(golden,
                                            working_trojan,
                                            stats,
                                            extra_nontrigger_patterns,
                                            candidate_indices,
                                            &result,
                                            &trigger_sig_stats,
                                            &trigger_sig_error)) {
        rule_apply_source = "signature_minimize_skipped";
        cerr << "trigger_sig_minimize skipped: " << trigger_sig_error << "\n";
      }
      trigger_sig_single_kill =
          trigger_sig_stats.exact_mismatches == 0 &&
          result.model.rules.size() == 1U &&
          result.model.rules[0].terms.size() == 1U;
      signature_exact_mismatch = trigger_sig_stats.exact_mismatches;
      if (trigger_sig_single_kill) {
        rule_apply_source = "signature_single_literal";
        cout << "trigger_sig_single_literal_kill_candidate 1\n";
      }
      cerr << "[TIMING] trigger_sig_minimize: " << ms_since(t_phase) << " ms\n";
    }

    refresh_model_rule_metadata(&result.model);
    const std::size_t applied_rules =
        rule_model_used ? result.model.rules.size() : 0;
    const std::size_t applied_literals =
        rule_model_used ? count_model_literals(result.model) : 0;
    const std::size_t applied_depth =
        rule_model_used ? max_model_rule_literals(result.model) : 0;
    // A verified literal patch cut bypasses the conditional DNF model but is
    // still one effective predicate/action for compactness comparisons.
    const std::size_t effective_rules = rule_model_used ? applied_rules : 1;
    const std::size_t effective_literals =
        rule_model_used ? applied_literals : 1;
    const std::size_t effective_depth = rule_model_used ? applied_depth : 1;
    if (rule_model_used && effective_rules == 1 &&
        result.model.rules[0].terms.size() == 1) {
      const auto term = result.model.rules[0].terms[0];
      effective_literal_expected = term.second;
      if (term.first < result.feature_nodes.size()) {
        effective_literal_node = result.feature_nodes[term.first];
      }
    }
    cout << "rule_apply_summary"
         << " strategy " << rule_method_name(options.rule_method)
         << " cec_attempt " << (cec_round + 1)
         << " synth_pass " << synth_pass
         << " source " << rule_apply_source
         << " rule_model_used " << (rule_model_used ? 1 : 0)
         << " literal_node " << effective_literal_node
         << " literal_expected " << effective_literal_expected
         << " literal_forced " << effective_literal_forced
         << " signature_exact_mismatch " << signature_exact_mismatch
         << " applied_rules " << applied_rules
         << " applied_literals " << applied_literals
         << " applied_depth " << applied_depth
         << " effective_rules " << effective_rules
         << " effective_literals " << effective_literals
         << " effective_depth " << effective_depth << "\n";

    cout << "training_set pos=" << result.data_pos
         << " neg=" << result.data_neg << '\n';
    cout << "hard_mined " << result.hard_added
         << " rounds " << result.rounds_used << '\n';

    cout << "mis match " << stats.mismatch_patterns << '\n';

    if (fix_succeeded) {
      break;
    }

    if (!did_rule_merge && result.model.rules.size() > 1U) {
      circuit merged = working_trojan;
      std::string merge_error;
      int match_idx = -1;
      std::string match_name;
      if (append_rule_match_node(merged,
                                 result.feature_nodes,
                                 result.model,
                                 &match_idx,
                                 &match_name,
                                 &merge_error)) {
        const std::string merge_path = derive_rule_merged_path(options.trojan_path);
        if (!bench_io::write_bench_file(merge_path, merged, &merge_error)) {
          cerr << "rule_merge_write_error: " << merge_error << "\n";
        } else {
          cout << "rule_merge_bench " << merge_path << "\n";
        }
        cout << "rule_merge_node " << match_name << "\n";
        working_trojan = std::move(merged);
        merged_match_idx = match_idx;
        did_rule_merge = true;
        break;
      }
      if (!merge_error.empty()) {
        cerr << "rule_merge_error: " << merge_error << "\n";
      }
    }
    break;
  }

  t_phase = std::chrono::steady_clock::now();
  auto t_sub = std::chrono::steady_clock::now();

  if (!fix_succeeded && trigger_sig_single_kill) {
    int kill_trigger_idx = -1;
    int kill_value = 0;
    std::string kill_error;
    circuit killed = working_trojan;
    t_sub = std::chrono::steady_clock::now();
    if (try_kill_simple_trigger(killed,
                                result.feature_nodes,
                                result.model,
                                &kill_trigger_idx,
                                &kill_value,
                                &kill_error)) {
      std::size_t base_area = 0;
      std::size_t base_level = 0;
      std::size_t killed_area = 0;
      std::size_t killed_level = 0;
      try {
        circuit base_eval = working_trojan;
        base_eval.ensure_eval_order();
        base_area = base_eval.area();
        base_level = base_eval.level();
        killed.ensure_eval_order();
        killed_area = killed.area();
        killed_level = killed.level();
      } catch (const std::exception& e) {
        cerr << "trigger_sig_kill area/level error: " << e.what() << "\n";
        return 1;
      }

      cout << "trigger_sig_kill "
           << working_trojan.node_name(kill_trigger_idx)
           << " forced " << kill_value << "\n";
      cout << "trigger_sig_kill_area " << base_area << " -> "
           << killed_area << " level " << base_level << " -> "
           << killed_level << "\n";

      std::size_t mismatch_index = 0;
      auto t_verify = std::chrono::steady_clock::now();
      if (!verify_patch_groundtruth(golden,
                                    killed,
                                    stats.trigger_patterns,
                                    &mismatch_index,
                                    &error)) {
        cerr << "[TIMING]   trigger_sig_kill_verify: "
             << ms_since(t_verify) << " ms (FAIL)\n";
        cerr << "trigger_sig_kill verification failed: " << error;
        if (!stats.trigger_patterns.empty()) {
          cerr << " pattern " << mismatch_index;
        }
        cerr << "\n";
      } else {
        cerr << "[TIMING]   trigger_sig_kill_verify: "
             << ms_since(t_verify) << " ms (PASS)\n";
        const long long delta_area =
            static_cast<long long>(killed_area) -
            static_cast<long long>(base_area);
        const long long delta_level =
            static_cast<long long>(killed_level) -
            static_cast<long long>(base_level);
        fix_output_path = options.output_path.empty()
                              ? derive_patched_path(options.trojan_path)
                              : options.output_path;
        if (!bench_io::write_bench_file(fix_output_path, killed, &error)) {
          cerr << "Write error: " << error << "\n";
          return 1;
        }
        cout << "payload_fix_selected 1 area_delta " << delta_area
             << " level_delta " << delta_level << "\n";
        cout << "payload_fix_bench " << fix_output_path << "\n";
        fix_succeeded = true;
      }
    } else if (!kill_error.empty()) {
      cerr << "trigger_sig_kill skipped: " << kill_error << "\n";
    }
    cerr << "[TIMING]   trigger_sig_kill: " << ms_since(t_sub) << " ms\n";
    t_sub = std::chrono::steady_clock::now();
  }

  if (!fix_succeeded) {
    std::vector<int> payload_fix_nodes;
    analyze_payload_nodes(golden,
                          working_trojan,
                          stats,
                          result,
                          merged_match_idx,
                          &payload_fix_nodes);
    cerr << "[TIMING]   analyze_payload: " << ms_since(t_sub) << " ms\n";

    if (!payload_fix_nodes.empty()) {
      circuit base_eval = working_trojan;
      std::size_t base_area = 0;
      std::size_t base_level = 0;
      try {
        base_eval.ensure_eval_order();
        base_area = base_eval.area();
        base_level = base_eval.level();
      } catch (const std::exception& e) {
        cerr << "Payload fix baseline error: " << e.what() << "\n";
        return 1;
      }

      circuit patched = working_trojan;
      for (int fix_idx : payload_fix_nodes) {
        std::size_t step_area_before = 0;
        std::size_t step_level_before = 0;
        try {
          patched.ensure_eval_order();
          step_area_before = patched.area();
          step_level_before = patched.level();
        } catch (const std::exception& e) {
          cerr << "Payload fix step baseline error: " << e.what() << "\n";
          return 1;
        }

        const auto start = std::chrono::steady_clock::now();
        const std::size_t base_nodes = patched.node_count();
        bool used_bypass = false;
        if (!apply_rule_patch(patched,
                              result.feature_nodes,
                              result.model,
                              fix_idx,
                              base_nodes,
                              &used_bypass,
                              &error)) {
          cerr << "Payload fix apply error: " << error << "\n";
          return 1;
        }
        const auto end = std::chrono::steady_clock::now();
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::size_t step_area_after = 0;
        std::size_t step_level_after = 0;
        try {
          patched.ensure_eval_order();
          step_area_after = patched.area();
          step_level_after = patched.level();
        } catch (const std::exception& e) {
          cerr << "Payload fix step area/level error: " << e.what() << "\n";
          return 1;
        }

        cout << "payload_fix_step " << working_trojan.node_name(fix_idx)
             << " time_ms " << elapsed_ms
             << " area " << step_area_before << " -> " << step_area_after
             << " level " << step_level_before << " -> " << step_level_after
             << " bypass " << (used_bypass ? 1 : 0) << "\n";
      }

      std::size_t mismatch_index = 0;
      t_sub = std::chrono::steady_clock::now();
      if (!verify_patch_groundtruth(golden,
                                    patched,
                                    stats.trigger_patterns,
                                    &mismatch_index,
                                    &error)) {
        cerr << "[TIMING]   final_verify: " << ms_since(t_sub) << " ms (FAIL)\n";
        cerr << "Payload fix verification failed: " << error;
        if (!stats.trigger_patterns.empty()) {
          cerr << " pattern " << mismatch_index;
        }
        cerr << "\n";
        cout << "payload_fix_apply skipped: groundtruth_verify_failed\n";
      } else {
        cerr << "[TIMING]   final_verify: " << ms_since(t_sub) << " ms (PASS)\n";
        std::size_t patched_area = 0;
        std::size_t patched_level = 0;
        try {
          patched.ensure_eval_order();
          patched_area = patched.area();
          patched_level = patched.level();
        } catch (const std::exception& e) {
          cerr << "Payload fix area/level error: " << e.what() << "\n";
          return 1;
        }

        const long long delta_area =
            static_cast<long long>(patched_area) -
            static_cast<long long>(base_area);
        const long long delta_level =
            static_cast<long long>(patched_level) -
            static_cast<long long>(base_level);

        fix_output_path = options.output_path.empty()
                              ? derive_patched_path(options.trojan_path)
                              : options.output_path;
        if (!bench_io::write_bench_file(fix_output_path, patched, &error)) {
          cerr << "Write error: " << error << "\n";
          return 1;
        }
        cout << "payload_fix_selected " << payload_fix_nodes.size()
             << " area_delta " << delta_area
             << " level_delta " << delta_level << "\n";
        cout << "payload_fix_bench " << fix_output_path << "\n";
        fix_succeeded = true;
      }
    } else {
      cout << "payload_fix_apply skipped: no fix nodes\n";
    }
  }

  cerr << "[TIMING] kill+patch+verify+write: " << ms_since(t_phase) << " ms\n";

  // ── CEC check ────────────────────────────────────────────────────────────
  if (!fix_succeeded) {
    // No fix found this round — give up.
    break;
  }

  t_sub = std::chrono::steady_clock::now();
  std::vector<int> cec_counter;
  bool cec_pass = run_abc_cec(options.golden_path, fix_output_path,
                               golden, &cec_counter);
  cerr << "[TIMING]   abc_cec: " << ms_since(t_sub) << " ms"
       << (cec_pass ? " (PASS)" : " (FAIL)") << "\n";

  if (cec_pass) {
    cout << "cec_rounds " << cec_round << "\n";
    cerr << "[TIMING] TOTAL: " << ms_since(t_main_start) << " ms\n";
    return 0;
  }

  // CEC failed — classify the counter-example and retry.  If the original
  // trojan already differs from golden, it is a missed trigger.  If original
  // trojan matches golden but patched differs, it is a patch false-positive
  // and must be learned as a hard negative instead.
  if (cec_counter.empty()) {
    cerr << "cec: failed to parse counter-example, giving up\n";
    break;
  }
  bool is_real_trigger = true;
  string classify_error;
  if (!classify_cec_counterexample(golden, trojan, cec_counter,
                                   &is_real_trigger, &classify_error)) {
    cerr << "cec: failed to classify counter-example";
    if (!classify_error.empty()) {
      cerr << ": " << classify_error;
    }
    cerr << "; treating as trigger\n";
    is_real_trigger = true;
  }
  if (is_real_trigger) {
    extra_trigger_patterns.push_back(std::move(cec_counter));
    cout << "cec_new_pattern total_extra "
         << extra_trigger_patterns.size()
         << " type trigger\n";
  } else {
    extra_nontrigger_patterns.push_back(std::move(cec_counter));
    cout << "cec_new_negative total_extra_neg "
         << extra_nontrigger_patterns.size()
         << " type false_positive\n";
  }

  }  // end CEC retry loop

  cout << "cec_rounds " << std::min(cec_round, kMaxCecRounds) << "\n";
  cerr << "[TIMING] TOTAL: " << ms_since(t_main_start) << " ms\n";
  return 0;
}
