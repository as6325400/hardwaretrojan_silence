#pragma once

#include <string>

#include "../core/circuit.hpp"

namespace bench_io {

bool parse_eqn_file(const std::string& path, circuit& out, std::string* error); // Load a Synopsys eqn file into a circuit.

}  // namespace bench_io
