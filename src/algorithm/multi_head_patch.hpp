#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "../core/circuit.hpp"
#include "decision_tree.hpp"

// One independently learned repair predicate for one primary output.  Feature
// node indices always refer to the immutable input circuit supplied to
// compose_multi_head_po_patch().
struct MultiHeadPatchHead {
  // Position in the primary-output array of the immutable base circuit.  The
  // caller must translate from any Golden/specification ordering before
  // composing a patch for a differently ordered implementation circuit.
  std::size_t base_po_position = 0;
  std::vector<int> feature_nodes;
  DecisionTreeModel model;
};

struct MultiHeadPatchMetrics {
  std::size_t head_count = 0;
  std::size_t nodes_before = 0;
  std::size_t nodes_after = 0;
  std::size_t predicate_nodes_added = 0;
  std::size_t output_xor_nodes_added = 0;
  std::size_t area_before = 0;
  std::size_t area_after = 0;
  std::size_t level_before = 0;
  std::size_t level_after = 0;
  long long area_delta = 0;
  long long level_delta = 0;
};

// Compose independent PO repair heads as
//
//   patched_po_i = original_po_i XOR R_i.
//
// Every R_i is materialized before any PO is changed, so all predicates are
// evaluated on the same immutable original circuit.  The function never
// rewrites original data-path fanouts.  It is transactional: patched_out and
// metrics_out are updated only after the complete candidate has been built
// and validated.
bool compose_multi_head_po_patch(
    const circuit& base,
    const std::vector<MultiHeadPatchHead>& heads,
    circuit* patched_out,
    MultiHeadPatchMetrics* metrics_out,
    std::string* error);
