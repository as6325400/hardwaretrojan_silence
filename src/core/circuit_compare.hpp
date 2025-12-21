#pragma once

#include <cstddef>
#include <string>

#include "circuit.hpp"

bool align_circuits(const circuit& golden, const circuit& trojan, std::string* error); // Verify PI/PO counts.
