#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

enum class CType {
  UNDEF,
  GATE,
  PI,
  CONST
};

enum class GType {
  AND,
  OR,
  NAND,
  NOR,
  NOT,
  BUFF,
  XOR,
  XNOR
};

struct cell {
  CType ctype = CType::UNDEF;
  GType gtype = GType::AND;
  std::vector<int> inputs;
  int val = -1;
};

class circuit {
public:
  void clear(); // Reset all nodes and metadata.
  int ensure_node(const std::string& name); // Create or find a node, return its index.
  bool has_node(const std::string& name) const; // Check if a node exists.
  int node_index(const std::string& name) const; // Get node index or throw if missing.
  const std::string& node_name(int idx) const; // Get node name by index.

  void define_pi(const std::string& name); // Mark node as a primary input.
  void define_const(const std::string& name, int value); // Define a constant node value (0/1).
  void define_gate(const std::string& name, GType gtype, const std::vector<int>& inputs); // Define gate and its inputs.
  void force_gate_const(int idx, int value); // Force a gate node to constant 0/1 and clear its inputs.

  void add_output_name(const std::string& name); // Record an output signal name.
  void finalize_outputs(); // Resolve output names to indices and validate.

  const std::vector<int>& pi_indices() const; // Get PI indices in declaration order.
  const std::vector<int>& po_indices() const; // Get PO indices in declaration order.
  std::size_t pi_count() const; // Number of primary inputs.
  std::size_t po_count() const; // Number of primary outputs.
  const cell& get_cell(int idx) const; // Access a node cell by index.
  std::size_t node_count() const; // Number of total nodes.
  const std::vector<int>& eval_order() const; // Get gate indices in eval order.
  std::size_t level() const; // Compute max logic level from PI/CONST to PO.
  std::size_t area() const; // Count number of gate nodes.
  void ensure_eval_order(); // Ensure eval_order_ is topologically sorted.
  int add_gate_auto(const std::string& prefix, GType gtype, const std::vector<int>& inputs); // Create a gate with a unique name.
  int add_const_auto(const std::string& prefix, int value); // Create a constant node with a unique name.
  void set_po_index(std::size_t pos, int idx); // Replace a PO index by position.
  void replace_gate_inputs(int old_idx, int new_idx, std::size_t max_node); // Rewrite gate inputs (index < max_node) from old_idx to new_idx.

  std::vector<int> simulate(const std::vector<int>& pi_values); // Simulate one input vector and return PO values.

private:
  void rebuild_eval_order(); // Recompute eval_order_ using topological order.

  std::vector<cell> cells_;
  std::vector<std::string> names_;
  std::unordered_map<std::string, int> name_to_index_;
  std::vector<int> pi_;
  std::vector<int> po_;
  std::vector<std::string> po_names_;
  std::vector<int> eval_order_;
  std::size_t unique_id_ = 0;
  std::size_t gate_count_cached_ = 0;
};
