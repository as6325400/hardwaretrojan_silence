#include "circuit_compare.hpp"

bool align_circuits(const circuit& golden, const circuit& trojan, std::string* error) {
  if (golden.pi_count() != trojan.pi_count()) {
    if (error) {
      *error = "PI count mismatch: " + std::to_string(golden.pi_count()) + " vs " +
               std::to_string(trojan.pi_count());
    }
    return false;
  }
  if (golden.po_count() != trojan.po_count()) {
    if (error) {
      *error = "PO count mismatch: " + std::to_string(golden.po_count()) + " vs " +
               std::to_string(trojan.po_count());
    }
    return false;
  }

  return true;
}
