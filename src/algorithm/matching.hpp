#pragma once

#include <string>
#include <vector>

#include "../core/circuit.hpp"

// Apply a pattern-specific patch to the trojan circuit so mismatched POs match golden.
bool apply_pattern_fix(const std::vector<int>& pattern,
                       const circuit& golden,
                       circuit& trojan,
                       std::string* error); // Patch trojan so this pattern matches golden outputs.
