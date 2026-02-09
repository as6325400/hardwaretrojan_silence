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

// Generate virtual node candidates as pairwise and triple boolean
// combinations (AND/OR with all polarity combinations) of the given
// base candidate signals.  max_arity controls whether triples (3) or
// only pairs (2) are generated.
void generate_virtual_candidates(
    const std::vector<int>& base_candidates,
    std::size_t max_arity,
    std::vector<VirtualNodeDef>* out);

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

// Mine frequently co-occurring literal subclauses from decision tree rules.
// Extracts all k-subsets of terms (k in [min_len, max_len]) from each rule,
// counts frequency across rules, and returns VirtualNodeDefs for the top
// max_candidates most frequent subclauses (AND gate with appropriate
// inversions).  Subclauses that already correspond to existing virtual nodes
// in existing_vn (by matching inputs exactly) are skipped.
// first_virtual_idx: feature indices >= this value are virtual features
// and will be excluded from subclause mining to prevent VN-on-VN composition.
void mine_subclauses_from_rules(
    const std::vector<int>& feature_nodes,
    const DecisionTreeModel& model,
    std::size_t min_len,
    std::size_t max_len,
    std::size_t max_candidates,
    const std::vector<VirtualNodeDef>& existing_vn,
    std::vector<VirtualNodeDef>* out,
    std::size_t first_virtual_idx = 0);
