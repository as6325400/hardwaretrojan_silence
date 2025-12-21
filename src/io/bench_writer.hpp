#pragma once

#include <string>

#include "../core/circuit.hpp"

namespace bench_io {

bool write_bench_file(const std::string& path, circuit& net, std::string* error); // Save a circuit as a .bench file.

}  // namespace bench_io
