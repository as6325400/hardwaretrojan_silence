#pragma once

#include <string>

#include "../core/circuit.hpp"

namespace bench_io {

bool parse_bench_file(const std::string& path, circuit& out, std::string* error); // Load a .bench file into a circuit.

}  // namespace bench_io
