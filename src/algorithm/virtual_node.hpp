#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "../core/circuit.hpp"
#include "../core/packed_circuit.hpp"
#include "decision_tree.hpp"

struct VirtualNodeDef {
  GType op;
  // Each input: (circuit_node_index, inverted).
  std::vector<std::pair<int, bool>> inputs;
};

struct SignatureVirtualOptions {
  std::size_t max_arity = 3;
  std::size_t max_candidates = 300;
  std::size_t max_pair_states = 300;
};

struct SignatureVirtualStats {
  std::size_t pattern_count = 0;
  std::size_t positive_count = 0;
  std::size_t negative_count = 0;
  std::size_t base_count = 0;
  std::size_t pair_states = 0;
  std::size_t triple_states = 0;
  std::size_t selected = 0;
};

// Generate VN candidates by ranking their pattern signatures.  The input
// patterns are capped to one packed word; positives are the desired trigger
// side, negatives are hard/background non-trigger examples.  The function
// deduplicates candidates that have the same signature and keeps the cheaper
// expression for that behavior.
bool generate_signature_virtual_candidates(
    const circuit& net,
    const std::vector<int>& base_candidates,
    const std::vector<std::vector<int>>& positive_patterns,
    const std::vector<std::vector<int>>& negative_patterns,
    const SignatureVirtualOptions& options,
    std::vector<VirtualNodeDef>* out,
    SignatureVirtualStats* stats = nullptr,
    std::string* error = nullptr);

// Add virtual node gates to a circuit.  Inverted inputs are handled
// by inserting shared NOT gates (cached per signal).  Returns the
// circuit node index of each virtual gate in definition order.
std::vector<int> add_virtual_gates_to_circuit(
    circuit& net,
    const std::vector<VirtualNodeDef>& defs);

// After tree training, find the set of virtual gate indices that
// actually appear in the model rules.  original_node_count is the
// circuit node count before virtual gates were added.  Returns a
// sorted, deduplicated list of circuit node indices (>= original_node_count)
// used by the rules.
std::vector<int> find_used_virtual_gate_indices(
    const std::vector<int>& feature_nodes,
    const DecisionTreeModel& model,
    std::size_t original_node_count);

// Compute virtual feature bit-vectors from simulation results without
// modifying the circuit.  For each VirtualNodeDef, evaluates the boolean
// combination (AND/OR/NOT) on the packed simulation values and returns
// one word_t per definition.
std::vector<packed_circuit::word_t> compute_virtual_feature_bits(
    const packed_circuit& packed,
    const std::vector<VirtualNodeDef>& defs,
    packed_circuit::word_t pattern_mask);

// Compute a single virtual feature value from single-pattern simulation
// results (fallback path when packed simulation fails).
int compute_virtual_feature_value(
    const circuit& c,
    const VirtualNodeDef& def);
