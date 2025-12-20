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

  const auto& golden_pi_indices = golden.pi_indices();
  const auto& trojan_pi_indices = trojan.pi_indices();
  for (std::size_t i = 0; i < golden_pi_indices.size(); ++i) {
    const std::string golden_name = golden.node_name(golden_pi_indices[i]);
    const std::string trojan_name = trojan.node_name(trojan_pi_indices[i]);
    if (golden_name != trojan_name) {
      if (error) {
        *error = "PI order mismatch at index " + std::to_string(i) + ": " +
                 golden_name + " vs " + trojan_name;
      }
      return false;
    }
  }

  const auto& golden_po_indices = golden.po_indices();
  const auto& trojan_po_indices = trojan.po_indices();
  for (std::size_t i = 0; i < golden_po_indices.size(); ++i) {
    const std::string golden_name = golden.node_name(golden_po_indices[i]);
    const std::string trojan_name = trojan.node_name(trojan_po_indices[i]);
    if (golden_name != trojan_name) {
      if (error) {
        *error = "PO order mismatch at index " + std::to_string(i) + ": " +
                 golden_name + " vs " + trojan_name;
      }
      return false;
    }
  }

  return true;
}
