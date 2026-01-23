#include <chrono>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "../core/circuit.hpp"
#include "../core/packed_circuit.hpp"
#include "../io/bench_parser.hpp"

int main(int argc, char** argv) {
  std::string path = "benchmarks/c880.bench";
  if (argc > 1) path = argv[1];

  circuit c;
  std::string error;
  if (!bench_io::parse_bench_file(path, c, &error)) {
    std::cerr << "Parse error: " << error << "\n";
    return 1;
  }

  const std::size_t pattern_count = 1;
  std::mt19937 rng(12345);
  std::uniform_int_distribution<int> dist(0, 1);

  std::vector<std::vector<int>> patterns;
  patterns.reserve(pattern_count);
  for (std::size_t p = 0; p < pattern_count; ++p) {
    std::vector<int> pi_values;
    pi_values.reserve(c.pi_count());
    for (std::size_t i = 0; i < c.pi_count(); ++i) {
      pi_values.push_back(dist(rng));
    }
    patterns.push_back(std::move(pi_values));
  }

  packed_circuit packed(c);
  const std::size_t block = packed_circuit::kWordBits;
  const std::size_t node_count = c.node_count();
  const std::size_t po_count = c.po_count();

  std::vector<unsigned char> packed_nodes(pattern_count * node_count, 0);
  std::vector<unsigned char> scalar_nodes(pattern_count * node_count, 0);
  std::vector<unsigned char> packed_pos(pattern_count * po_count, 0);
  std::vector<unsigned char> scalar_pos(pattern_count * po_count, 0);

  auto node_index = [node_count](std::size_t p, std::size_t n) {
    return p * node_count + n;
  };
  auto po_index = [po_count](std::size_t p, std::size_t o) {
    return p * po_count + o;
  };

  std::chrono::duration<double> packed_elapsed(0);
  for (std::size_t start = 0; start < pattern_count; start += block) {
    const std::size_t count = std::min(block, pattern_count - start);
    std::vector<std::vector<int>> block_patterns(patterns.begin() + start,
                                                 patterns.begin() + start + count);
    const auto sim_start = std::chrono::steady_clock::now();
    packed.simulate(block_patterns);
    const auto sim_end = std::chrono::steady_clock::now();
    packed_elapsed += sim_end - sim_start;

    for (std::size_t i = 0; i < count; ++i) {
      const std::size_t pattern_idx = start + i;
      for (std::size_t o = 0; o < po_count; ++o) {
        packed_pos[po_index(pattern_idx, o)] =
            static_cast<unsigned char>(packed.po_value(o, i));
      }
      for (std::size_t n = 0; n < node_count; ++n) {
        packed_nodes[node_index(pattern_idx, n)] =
            static_cast<unsigned char>(
                packed.node_value(static_cast<int>(n), i));
      }
    }
  }
  std::chrono::duration<double> scalar_elapsed(0);
  for (std::size_t p = 0; p < pattern_count; ++p) {
    const auto sim_start = std::chrono::steady_clock::now();
    auto scalar_outputs = c.simulate(patterns[p]);
    const auto sim_end = std::chrono::steady_clock::now();
    scalar_elapsed += sim_end - sim_start;
    if (scalar_outputs.size() != po_count) {
      std::cerr << "Scalar output size mismatch at pattern " << p << "\n";
      return 1;
    }
    for (std::size_t o = 0; o < po_count; ++o) {
      scalar_pos[po_index(p, o)] =
          static_cast<unsigned char>(scalar_outputs[o]);
    }
    for (std::size_t n = 0; n < node_count; ++n) {
      scalar_nodes[node_index(p, n)] =
          static_cast<unsigned char>(
              c.get_cell(static_cast<int>(n)).val);
    }
  }
  for (std::size_t p = 0; p < pattern_count; ++p) {
    for (std::size_t o = 0; o < po_count; ++o) {
      if (packed_pos[po_index(p, o)] != scalar_pos[po_index(p, o)]) {
        std::cerr << "PO mismatch at pattern " << p << "\n";
        return 1;
      }
    }
    for (std::size_t n = 0; n < node_count; ++n) {
      if (packed_nodes[node_index(p, n)] != scalar_nodes[node_index(p, n)]) {
        std::cerr << "Node mismatch at pattern " << p << "\n";
        return 1;
      }
    }
  }

  std::cout << "Packed time (s): " << packed_elapsed.count() << "\n";
  std::cout << "Scalar time (s): " << scalar_elapsed.count() << "\n";
  if (packed_elapsed.count() > 0.0) {
    std::cout << "Speedup: " << (scalar_elapsed.count() / packed_elapsed.count())
              << "x\n";
  }
  std::cout << "Packed simulation matches scalar simulation.\n";
  return 0;
}
