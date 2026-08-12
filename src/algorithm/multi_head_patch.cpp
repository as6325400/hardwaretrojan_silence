#include "multi_head_patch.hpp"

#include <algorithm>
#include <exception>
#include <unordered_set>
#include <utility>

#include "rule_patch.hpp"

namespace {

std::string unique_node_name(const circuit& net, const std::string& prefix) {
  std::size_t suffix = 0;
  std::string name = prefix;
  while (net.has_node(name)) {
    name = prefix + std::to_string(suffix++);
  }
  return name;
}

bool validate_head(const circuit& base,
                   const MultiHeadPatchHead& head,
                   std::string* error) {
  if (head.base_po_position >= base.po_count()) {
    if (error) *error = "multi-head PO position out of range";
    return false;
  }
  if (head.model.rules.empty()) {
    if (error) *error = "multi-head predicate has no rules";
    return false;
  }
  for (int node_idx : head.feature_nodes) {
    if (node_idx < 0 ||
        static_cast<std::size_t>(node_idx) >= base.node_count()) {
      if (error) *error = "multi-head feature node index out of range";
      return false;
    }
  }
  for (const DecisionTreeRule& rule : head.model.rules) {
    if (rule.terms.empty()) {
      if (error) *error = "multi-head predicate is unconditional";
      return false;
    }
    for (const auto& term : rule.terms) {
      if (term.first >= head.feature_nodes.size()) {
        if (error) *error = "multi-head rule feature index out of range";
        return false;
      }
      if (term.second != 0 && term.second != 1) {
        if (error) *error = "multi-head rule literal must be zero or one";
        return false;
      }
    }
  }
  return true;
}

}  // namespace

bool compose_multi_head_po_patch(
    const circuit& base,
    const std::vector<MultiHeadPatchHead>& heads,
    circuit* patched_out,
    MultiHeadPatchMetrics* metrics_out,
    std::string* error) {
  if (error) error->clear();
  if (!patched_out) {
    if (error) *error = "multi-head patched output pointer is null";
    return false;
  }
  if (heads.empty()) {
    if (error) *error = "multi-head patch has no heads";
    return false;
  }

  std::unordered_set<std::size_t> seen_po_positions;
  seen_po_positions.reserve(heads.size());
  for (const MultiHeadPatchHead& head : heads) {
    if (!seen_po_positions.insert(head.base_po_position).second) {
      if (error) *error = "duplicate multi-head PO position";
      return false;
    }
    if (!validate_head(base, head, error)) return false;
  }

  // Renaming a shared PO driver would also rename an unpatched output.  Such
  // an interface cannot be represented safely by circuit's one-name-per-node
  // data model, so reject it instead of silently changing a PO name.
  for (const MultiHeadPatchHead& head : heads) {
    const int driver = base.po_indices()[head.base_po_position];
    if (base.get_cell(driver).ctype == CType::PI) {
      if (error) *error = "multi-head PO directly uses a primary input";
      return false;
    }
    const std::size_t uses = static_cast<std::size_t>(std::count(
        base.po_indices().begin(), base.po_indices().end(), driver));
    if (uses != 1U) {
      if (error) *error = "multi-head PO uses a shared output driver";
      return false;
    }
  }

  MultiHeadPatchMetrics metrics;
  metrics.head_count = heads.size();
  metrics.nodes_before = base.node_count();

  circuit candidate = base;
  try {
    candidate.ensure_eval_order();
    metrics.area_before = candidate.area();
    metrics.level_before = candidate.level();
  } catch (const std::exception& exception) {
    if (error) {
      *error = std::string("multi-head base topology error: ") +
               exception.what();
    }
    return false;
  }

  // Freeze every predicate against the unmodified original graph.  No PO or
  // original gate fanout is changed until all heads have materialized.
  try {
    std::vector<int> match_nodes;
    match_nodes.reserve(heads.size());
    for (const MultiHeadPatchHead& head : heads) {
      int match_idx = -1;
      std::string match_name;
      std::string build_error;
      if (!append_rule_match_node(candidate,
                                  head.feature_nodes,
                                  head.model,
                                  &match_idx,
                                  &match_name,
                                  &build_error)) {
        if (error) {
          *error = "multi-head predicate build failed";
          if (!build_error.empty()) *error += ": " + build_error;
        }
        return false;
      }
      match_nodes.push_back(match_idx);
    }
    metrics.predicate_nodes_added =
        candidate.node_count() - metrics.nodes_before;

    const std::vector<int> original_po_indices = base.po_indices();
    std::vector<int> xor_nodes;
    xor_nodes.reserve(heads.size());
    for (std::size_t i = 0; i < heads.size(); ++i) {
      const int original_po =
          original_po_indices[heads[i].base_po_position];
      xor_nodes.push_back(candidate.add_gate_auto(
          "multi_head_po_xor_", GType::XOR,
          std::vector<int>{original_po, match_nodes[i]}));
    }
    metrics.output_xor_nodes_added = xor_nodes.size();

    // Keep the externally visible PO names stable.  Renaming changes names
    // but never indices, so already-built predicates continue to reference
    // the original signal values.
    for (std::size_t i = 0; i < heads.size(); ++i) {
      const std::size_t po_position = heads[i].base_po_position;
      const int original_po = original_po_indices[po_position];
      const std::string interface_name = base.node_name(original_po);
      const std::string displaced_name = unique_node_name(
          candidate, interface_name + "_multi_head_orig_");
      std::string rename_error;
      if (!candidate.rename_node(original_po, displaced_name, &rename_error) ||
          !candidate.rename_node(xor_nodes[i], interface_name, &rename_error)) {
        if (error) {
          *error = "multi-head PO rename failed";
          if (!rename_error.empty()) *error += ": " + rename_error;
        }
        return false;
      }
      candidate.set_po_index(po_position, xor_nodes[i]);
    }
  } catch (const std::exception& exception) {
    if (error) {
      *error = std::string("multi-head composition error: ") +
               exception.what();
    }
    return false;
  }

  try {
    candidate.ensure_eval_order();
    metrics.nodes_after = candidate.node_count();
    metrics.area_after = candidate.area();
    metrics.level_after = candidate.level();
  } catch (const std::exception& exception) {
    if (error) {
      *error = std::string("multi-head patched topology error: ") +
               exception.what();
    }
    return false;
  }
  metrics.area_delta = static_cast<long long>(metrics.area_after) -
                       static_cast<long long>(metrics.area_before);
  metrics.level_delta = static_cast<long long>(metrics.level_after) -
                        static_cast<long long>(metrics.level_before);

  *patched_out = std::move(candidate);
  if (metrics_out) *metrics_out = metrics;
  return true;
}
