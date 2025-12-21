#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>
#include <omp.h>

#include "io/bench_parser.hpp"
#include "io/bench_writer.hpp"
#include "core/circuit_compare.hpp"
#include "algorithm/matching.hpp"

using namespace std;

int main(int argc, char** argv) {
  if (argc < 3) {
    cerr << "Usage: " << argv[0] << " <golden_bench> <trojan_bench>\n";
    return 1;
  }

  circuit golden;
  circuit trojan;
  string error;
  if (!bench_io::parse_bench_file(argv[1], golden, &error)) {
    cerr << "Golden parse error: " << error << "\n";
    return 1;
  }
  if (!bench_io::parse_bench_file(argv[2], trojan, &error)) {
    cerr << "Trojan parse error: " << error << "\n";
    return 1;
  }

  if (!align_circuits(golden, trojan, &error)) {
    cerr << "Circuit alignment error: " << error << "\n";
    return 1;
  }

  const size_t pattern_count = 10000000;
  vector<vector<int>> errors;

  vector<int> gate_indices;
  gate_indices.reserve(trojan.node_count());
  for (size_t i = 0; i < trojan.node_count(); ++i) {
    const auto& c = trojan.get_cell(static_cast<int>(i));
    if (c.ctype == CType::GATE) {
      gate_indices.push_back(static_cast<int>(i));
    }
  }

  const int thread_count = omp_get_max_threads();
  vector<vector<uint64_t>> ones_total_thread(thread_count, vector<uint64_t>(gate_indices.size(), 0));
  vector<vector<uint64_t>> ones_trigger_thread(thread_count, vector<uint64_t>(gate_indices.size(), 0));
  vector<vector<uint64_t>> ones_notrigger_thread(thread_count, vector<uint64_t>(gate_indices.size(), 0));
  vector<uint64_t> total_count_thread(thread_count, 0);
  vector<uint64_t> trigger_count_thread(thread_count, 0);
  vector<uint64_t> notrigger_count_thread(thread_count, 0);

  size_t mismatch_patterns = 0;

#pragma omp parallel reduction(+:mismatch_patterns)
{
  const int tid = omp_get_thread_num();
  mt19937 rng(0 + tid);
  uniform_int_distribution<int> dist(0, 1);
  circuit golden_local = golden;
  circuit trojan_local = trojan;

  #pragma omp for schedule(static)
  for (size_t p = 0; p < pattern_count; ++p) {

    vector<int> pi_values;
    pi_values.reserve(golden_local.pi_count());
    for (size_t i = 0; i < golden_local.pi_count(); ++i) {
      pi_values.push_back(dist(rng));
    }

    vector<int> golden_outputs;
    vector<int> trojan_outputs;
    try {
      golden_outputs = golden_local.simulate(pi_values);
      trojan_outputs = trojan_local.simulate(pi_values);
    } catch (const exception& e) {
      #pragma omp critical 
      {
        cerr << "Simulation error: " << e.what() << "\n";
      }
      continue;
    }

    size_t diff = 0;
    for (size_t i = 0; i < golden_outputs.size(); ++i) {
      if (golden_outputs[i] != trojan_outputs[i]) {
        ++diff;
      }
    }

    const bool triggered = diff > 0;
    total_count_thread[tid]++;
    if (triggered) {
      trigger_count_thread[tid]++;
    } else {
      notrigger_count_thread[tid]++;
    }

    for (size_t g = 0; g < gate_indices.size(); ++g) {
      const int idx = gate_indices[g];
      const int val = trojan_local.get_cell(idx).val;
      const uint64_t one = (val == 1) ? 1 : 0;
      ones_total_thread[tid][g] += one;
      if (triggered) {
        ones_trigger_thread[tid][g] += one;
      } else {
        ones_notrigger_thread[tid][g] += one;
      }
    }

    if (diff == 0) {
      // cout << "pattern " << p << ": match\n";
    } else {
      // cout << "pattern " << p << ": mismatch (" << diff << " outputs)\n";
      #pragma omp critical
      {
        errors.push_back(pi_values);
      }
      ++mismatch_patterns;
    }
    // if(p % 100000 == 0) cout << p << '\n';
  }
}

  vector<uint64_t> ones_total(gate_indices.size(), 0);
  vector<uint64_t> ones_trigger(gate_indices.size(), 0);
  vector<uint64_t> ones_notrigger(gate_indices.size(), 0);
  uint64_t total_patterns = 0;
  uint64_t trigger_patterns = 0;
  uint64_t notrigger_patterns = 0;

  for (int t = 0; t < thread_count; ++t) {
    total_patterns += total_count_thread[t];
    trigger_patterns += trigger_count_thread[t];
    notrigger_patterns += notrigger_count_thread[t];
    for (size_t g = 0; g < gate_indices.size(); ++g) {
      ones_total[g] += ones_total_thread[t][g];
      ones_trigger[g] += ones_trigger_thread[t][g];
      ones_notrigger[g] += ones_notrigger_thread[t][g];
    }
  }

  cout << "gate_zero_ratio\n";
  cout << fixed << setprecision(4);
  for (size_t g = 0; g < gate_indices.size(); ++g) {
    const string& name = trojan.node_name(gate_indices[g]);
    double zero_ratio = 0.0;
    if (total_patterns > 0) {
      zero_ratio = 1.0 - (static_cast<double>(ones_total[g]) / static_cast<double>(total_patterns));
    }
    cout << name << ' ' << zero_ratio << '\n';
  }

  cout << "trigger_candidates\n";
  const double high = 0.8;
  const double low = 0.2;
  vector<pair<double, size_t>> candidates;
  if (trigger_patterns > 0 && notrigger_patterns > 0) {
    for (size_t g = 0; g < gate_indices.size(); ++g) {
      const double p1_trigger =
          static_cast<double>(ones_trigger[g]) / static_cast<double>(trigger_patterns);
      const double p1_notrigger =
          static_cast<double>(ones_notrigger[g]) / static_cast<double>(notrigger_patterns);
      if (p1_trigger >= high && p1_notrigger <= low) {
        candidates.emplace_back(p1_trigger - p1_notrigger, g);
      }
    }
  }
  sort(candidates.begin(), candidates.end(),
       [](const auto& a, const auto& b) { return a.first > b.first; });
  for (const auto& item : candidates) {
    const size_t g = item.second;
    const string& name = trojan.node_name(gate_indices[g]);
    const double p1_trigger =
        (trigger_patterns > 0)
            ? static_cast<double>(ones_trigger[g]) / static_cast<double>(trigger_patterns)
            : 0.0;
    const double p1_notrigger =
        (notrigger_patterns > 0)
            ? static_cast<double>(ones_notrigger[g]) / static_cast<double>(notrigger_patterns)
            : 0.0;
    cout << name << " p1_trigger=" << p1_trigger << " p1_notrigger=" << p1_notrigger << '\n';
  }

  cout << "mismatch " << mismatch_patterns << '\n';

  return 0;
}
