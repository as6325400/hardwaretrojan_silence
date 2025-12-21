#include <iostream>
#include <random>
#include <string>
#include <vector>
#include <iomanip>
#include <omp.h>

#include "io/bench_parser.hpp"
#include "io/bench_writer.hpp"
#include "core/circuit_compare.hpp"
#include "algorithm/matching.hpp"

using namespace std;

int main(int argc, char** argv) {
  if (argc < 3) {
    cerr << "Usage: " << argv[0] << " <golden_bench> <trojan_bench> [output_bench]\n";
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


  const size_t pattern_count = 100000;
  vector<vector<int>> errors;

  size_t mismatch_patterns = 0;

#pragma omp parallel reduction(+:mismatch_patterns)
{
  
  mt19937 rng(0 + omp_get_thread_num());
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
    }

    size_t diff = 0;
    for (size_t i = 0; i < golden_outputs.size(); ++i) {
      if (golden_outputs[i] != trojan_outputs[i]) {
        ++diff;
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

  cout << "origin area, delay, pi, po\n";
  cout << trojan.area() << ' ' << trojan.level() << ' ' << trojan.pi_count() << ' ' << trojan.po_count() << '\n';
  cout << "-------------------------\n";
  int success_num = 0;

  for (int i = 0; i < (int)errors.size(); i++){
    auto error = errors[i];
    cout << "#case " << i + 1 << '\n';
    string msg;
    if(!apply_pattern_fix(error, golden, trojan, &msg)){
      cerr << "patch_fix_error\n";
    }
    bool success = golden.simulate(error) == trojan.simulate(error);
    if(success){
      success_num++;
      cout << "fix success\n";
      cout << "new area, delay\n";
      cout << trojan.area() << ' ' << trojan.level() << '\n';
    }
    else {
      cout << "fix_error\n";
    }
    cout << "-------------------------\n";
  }

  cout << "mis match " << mismatch_patterns << '\n';
  cout << "fix success " << success_num << '\n';

  if (argc >= 4) {
    if (!bench_io::write_bench_file(argv[3], trojan, &error)) {
      cerr << "Write error: " << error << "\n";
      return 1;
    }
  }

  return 0;
}
