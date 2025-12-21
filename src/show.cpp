#include <bits/stdc++.h>

#include "io/bench_parser.hpp"
#include "io/bench_writer.hpp"
#include "core/circuit_compare.hpp"
#include "algorithm/matching.hpp"

using namespace std;

int main(int argc, char** argv) {
  
  if (argc < 2) {
    cerr << "Usage: " << argv[0] << " <bench>\n";
    return 1;
  }

  circuit c;
  string error;

  if (!bench_io::parse_bench_file(argv[1], c, &error)) {
    cerr << "Circuit parse error: " << error << "\n";
    return 1;
  }

  cout << "area " << c.area() << "delay " << c.level() << '\n';

   

}