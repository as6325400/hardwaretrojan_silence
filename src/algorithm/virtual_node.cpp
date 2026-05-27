#include "virtual_node.hpp"

#include <algorithm>
#include <exception>
#include <cmath>
#include <string>
#include <unordered_map>
#include <unordered_set>

#ifdef _OPENMP
#include <omp.h>
#endif

namespace {

using SignatureWord = packed_circuit::word_t;

struct SignatureLiteral {
  int node = -1;
  bool inverted = false;
  SignatureWord bits = 0;
};

struct SignatureState {
  SignatureWord bits = 0;
  std::vector<std::pair<int, bool>> inputs;
  double score = 0.0;
  int cost = 0;
};

void canonicalize_inputs(std::vector<std::pair<int, bool>>* inputs) {
  std::sort(inputs->begin(), inputs->end(),
            [](const std::pair<int, bool>& a,
               const std::pair<int, bool>& b) {
              if (a.first != b.first) return a.first < b.first;
              return a.second < b.second;
            });
}

std::string input_key(const std::vector<std::pair<int, bool>>& inputs) {
  std::string key;
  for (const auto& inp : inputs) {
    key += std::to_string(inp.first);
    key += inp.second ? '~' : '+';
  }
  return key;
}

bool has_input_node(const std::vector<std::pair<int, bool>>& inputs,
                    int node) {
  for (const auto& inp : inputs) {
    if (inp.first == node) {
      return true;
    }
  }
  return false;
}

int expression_cost(const std::vector<std::pair<int, bool>>& inputs) {
  int inverted = 0;
  for (const auto& inp : inputs) {
    if (inp.second) {
      inverted += 1;
    }
  }
  // One VN gate plus an estimate for required input inversions.  NOT gates are
  // shared when materialized, so this is intentionally only a ranking cost.
  return 1 + inverted;
}

double signature_score(SignatureWord bits,
                       SignatureWord pos_mask,
                       SignatureWord neg_mask,
                       std::size_t pos_count,
                       std::size_t neg_count,
                       int cost,
                       std::size_t arity) {
  const std::size_t tp =
      static_cast<std::size_t>(__builtin_popcountll(bits & pos_mask));
  if (tp == 0) {
    return -1.0e30;
  }
  const std::size_t fp =
      static_cast<std::size_t>(__builtin_popcountll(bits & neg_mask));
  const std::size_t fn = pos_count - tp;

  const double precision =
      (tp + fp == 0) ? 0.0
                     : static_cast<double>(tp) / static_cast<double>(tp + fp);
  const double recall =
      pos_count == 0 ? 0.0
                     : static_cast<double>(tp) / static_cast<double>(pos_count);
  const double f1 =
      (precision + recall == 0.0)
          ? 0.0
          : (2.0 * precision * recall) / (precision + recall);

  // CEC hard/background negatives are precious; give precision the largest
  // voice, but keep recall high enough that the tree can still compose terms.
  const double neg_penalty =
      neg_count == 0 ? 0.0
                     : 120.0 * static_cast<double>(fp) /
                           static_cast<double>(neg_count);
  const double pos_penalty =
      pos_count == 0 ? 0.0
                     : 45.0 * static_cast<double>(fn) /
                           static_cast<double>(pos_count);
  return f1 * 10000.0 +
         precision * 1500.0 +
         recall * 700.0 -
         neg_penalty -
         pos_penalty -
         static_cast<double>(cost) * 20.0 -
         static_cast<double>(arity) * 5.0;
}

bool state_better(const SignatureState& a, const SignatureState& b) {
  if (std::fabs(a.score - b.score) > 1.0e-9) {
    return a.score > b.score;
  }
  if (a.cost != b.cost) {
    return a.cost < b.cost;
  }
  if (a.inputs.size() != b.inputs.size()) {
    return a.inputs.size() < b.inputs.size();
  }
  return input_key(a.inputs) < input_key(b.inputs);
}

void keep_best_signature(
    const SignatureState& state,
    std::unordered_map<SignatureWord, SignatureState>* best) {
  auto it = best->find(state.bits);
  if (it == best->end() || state_better(state, it->second)) {
    (*best)[state.bits] = state;
  }
}

void merge_signature_maps(
    const std::vector<std::unordered_map<SignatureWord, SignatureState>>& local,
    std::unordered_map<SignatureWord, SignatureState>* merged) {
  for (const auto& local_map : local) {
    for (const auto& kv : local_map) {
      keep_best_signature(kv.second, merged);
    }
  }
}

int signature_thread_count(std::size_t work_items) {
  constexpr std::size_t kParallelThreshold = 100000;
  if (work_items < kParallelThreshold) {
    return 1;
  }
  int max_threads = 1;
#ifdef _OPENMP
  max_threads = std::max(1, omp_get_max_threads());
#endif
  return std::min(max_threads, 8);
}

std::vector<SignatureState> sorted_states(
    const std::unordered_map<SignatureWord, SignatureState>& states) {
  std::vector<SignatureState> sorted;
  sorted.reserve(states.size());
  for (const auto& kv : states) {
    sorted.push_back(kv.second);
  }
  std::sort(sorted.begin(), sorted.end(), state_better);
  return sorted;
}

}  // namespace

bool generate_signature_virtual_candidates(
    const circuit& net,
    const std::vector<int>& base_candidates,
    const std::vector<std::vector<int>>& positive_patterns,
    const std::vector<std::vector<int>>& negative_patterns,
    const SignatureVirtualOptions& options,
    std::vector<VirtualNodeDef>* out,
    SignatureVirtualStats* stats,
    std::string* error) {
  if (error) {
    error->clear();
  }
  if (stats) {
    *stats = SignatureVirtualStats{};
  }
  if (!out) {
    if (error) {
      *error = "Signature VN output pointer is null";
    }
    return false;
  }
  out->clear();
  if (base_candidates.size() < 2 || positive_patterns.empty()) {
    return true;
  }

  std::vector<std::vector<int>> patterns;
  patterns.reserve(packed_circuit::kWordBits);

  std::size_t pos_take = positive_patterns.size();
  std::size_t neg_take = negative_patterns.size();
  if (pos_take + neg_take > packed_circuit::kWordBits) {
    if (neg_take == 0) {
      pos_take = packed_circuit::kWordBits;
    } else {
      pos_take = std::min<std::size_t>(pos_take, packed_circuit::kWordBits / 2);
      neg_take = std::min<std::size_t>(
          neg_take, packed_circuit::kWordBits - pos_take);
      if (neg_take == 0 && !negative_patterns.empty()) {
        pos_take = packed_circuit::kWordBits - 1;
        neg_take = 1;
      }
    }
  }

  for (std::size_t i = 0; i < pos_take; ++i) {
    patterns.push_back(positive_patterns[i]);
  }
  for (std::size_t i = 0; i < neg_take; ++i) {
    patterns.push_back(negative_patterns[i]);
  }
  if (patterns.empty()) {
    return true;
  }

  circuit net_copy = net;
  packed_circuit packed(net_copy);
  try {
    packed.simulate(patterns);
  } catch (const std::exception& e) {
    if (error) {
      *error = std::string("Signature VN simulation error: ") + e.what();
    }
    return false;
  }

  const SignatureWord mask = packed.pattern_mask();
  SignatureWord pos_mask = 0;
  SignatureWord neg_mask = 0;
  for (std::size_t i = 0; i < pos_take; ++i) {
    pos_mask |= (SignatureWord(1) << i);
  }
  for (std::size_t i = 0; i < neg_take; ++i) {
    neg_mask |= (SignatureWord(1) << (pos_take + i));
  }
  pos_mask &= mask;
  neg_mask &= mask;

  std::vector<SignatureWord> base_bits;
  base_bits.reserve(base_candidates.size());
  for (int node : base_candidates) {
    base_bits.push_back(packed.node_bits(node) & mask);
  }

  std::vector<SignatureLiteral> literals;
  literals.reserve(base_candidates.size() * 2);
  for (std::size_t i = 0; i < base_candidates.size(); ++i) {
    literals.push_back(SignatureLiteral{
        base_candidates[i], false, base_bits[i]});
    literals.push_back(SignatureLiteral{
        base_candidates[i], true, (~base_bits[i]) & mask});
  }

  const std::size_t n = base_candidates.size();
  std::unordered_map<SignatureWord, SignatureState> pair_states;
  pair_states.reserve(base_candidates.size() * 4);

  const std::size_t pair_work = (n * (n - 1) / 2) * 4;
  const int pair_thread_count = signature_thread_count(pair_work);
  std::vector<std::unordered_map<SignatureWord, SignatureState>> local_pairs(
      static_cast<std::size_t>(pair_thread_count));
  for (auto& local_map : local_pairs) {
    local_map.reserve(base_candidates.size() * 2);
  }

#pragma omp parallel for schedule(dynamic) num_threads(pair_thread_count) if(pair_thread_count > 1)
  for (std::size_t i = 0; i < n; ++i) {
#ifdef _OPENMP
    const int tid = omp_get_thread_num();
#else
    const int tid = 0;
#endif
    auto& local_map = local_pairs[static_cast<std::size_t>(tid)];
    for (std::size_t j = i + 1; j < n; ++j) {
      for (int pi = 0; pi < 2; ++pi) {
        const SignatureWord a_bits =
            pi ? ((~base_bits[i]) & mask) : base_bits[i];
        for (int pj = 0; pj < 2; ++pj) {
          const SignatureWord b_bits =
              pj ? ((~base_bits[j]) & mask) : base_bits[j];
          const SignatureWord bits = a_bits & b_bits;
          const std::size_t tp =
              static_cast<std::size_t>(__builtin_popcountll(bits & pos_mask));
          if (tp == 0) {
            continue;
          }
          std::vector<std::pair<int, bool>> inputs = {
              {base_candidates[i], pi != 0},
              {base_candidates[j], pj != 0}};
          canonicalize_inputs(&inputs);
          const int cost = expression_cost(inputs);
          const double score = signature_score(
              bits, pos_mask, neg_mask, pos_take, neg_take,
              cost, inputs.size());
          if (score <= -1.0e20) {
            continue;
          }
          keep_best_signature(
              SignatureState{bits, std::move(inputs), score, cost},
              &local_map);
        }
      }
    }
  }
  merge_signature_maps(local_pairs, &pair_states);

  std::vector<SignatureState> ranked_pairs = sorted_states(pair_states);
  if (ranked_pairs.size() > options.max_pair_states) {
    ranked_pairs.resize(options.max_pair_states);
  }

  std::unordered_map<SignatureWord, SignatureState> all_states = pair_states;
  std::size_t triple_state_count = 0;
  if (options.max_arity >= 3 && n >= 3) {
    const std::size_t triple_work = ranked_pairs.size() * literals.size();
    const int triple_thread_count = signature_thread_count(triple_work);
    std::vector<std::unordered_map<SignatureWord, SignatureState>> local_triples(
        static_cast<std::size_t>(triple_thread_count));
    for (auto& local_map : local_triples) {
      local_map.reserve(options.max_candidates);
    }

#pragma omp parallel for schedule(dynamic) num_threads(triple_thread_count) if(triple_thread_count > 1) reduction(+:triple_state_count)
    for (std::size_t pidx = 0; pidx < ranked_pairs.size(); ++pidx) {
#ifdef _OPENMP
      const int tid = omp_get_thread_num();
#else
      const int tid = 0;
#endif
      auto& local_map = local_triples[static_cast<std::size_t>(tid)];
      const auto& pair_state = ranked_pairs[pidx];
      for (const auto& lit : literals) {
        if (has_input_node(pair_state.inputs, lit.node)) {
          continue;
        }
        const SignatureWord bits = pair_state.bits & lit.bits;
        const std::size_t tp =
            static_cast<std::size_t>(__builtin_popcountll(bits & pos_mask));
        if (tp == 0) {
          continue;
        }
        std::vector<std::pair<int, bool>> inputs = pair_state.inputs;
        inputs.emplace_back(lit.node, lit.inverted);
        canonicalize_inputs(&inputs);
        const int cost = expression_cost(inputs);
        const double score = signature_score(
            bits, pos_mask, neg_mask, pos_take, neg_take,
            cost, inputs.size());
        if (score <= -1.0e20) {
          continue;
        }
        keep_best_signature(
            SignatureState{bits, std::move(inputs), score, cost},
            &local_map);
        triple_state_count += 1;
      }
    }
    merge_signature_maps(local_triples, &all_states);
  }

  std::vector<SignatureState> ranked = sorted_states(all_states);
  if (ranked.size() > options.max_candidates) {
    ranked.resize(options.max_candidates);
  }

  out->reserve(ranked.size());
  for (const auto& state : ranked) {
    if (state.inputs.size() < 2) {
      continue;
    }
    out->push_back(VirtualNodeDef{GType::AND, state.inputs});
  }

  if (stats) {
    stats->pattern_count = patterns.size();
    stats->positive_count = pos_take;
    stats->negative_count = neg_take;
    stats->base_count = base_candidates.size();
    stats->pair_states = pair_states.size();
    stats->triple_states = triple_state_count;
    stats->selected = out->size();
  }
  return true;
}

std::vector<int> add_virtual_gates_to_circuit(
    circuit& net,
    const std::vector<VirtualNodeDef>& defs) {
  // Cache NOT gates per original signal to avoid duplicates.
  std::unordered_map<int, int> not_cache;

  auto get_input = [&](int node_idx, bool inverted) -> int {
    if (!inverted) {
      return node_idx;
    }
    auto it = not_cache.find(node_idx);
    if (it != not_cache.end()) {
      return it->second;
    }
    const int not_idx =
        net.add_gate_auto("vn_not_", GType::NOT, {node_idx});
    not_cache[node_idx] = not_idx;
    return not_idx;
  };

  std::vector<int> result;
  result.reserve(defs.size());

  for (const auto& def : defs) {
    std::vector<int> actual_inputs;
    actual_inputs.reserve(def.inputs.size());
    for (const auto& inp : def.inputs) {
      actual_inputs.push_back(get_input(inp.first, inp.second));
    }
    const int gate_idx =
        net.add_gate_auto("vn_", def.op, actual_inputs);
    result.push_back(gate_idx);
  }

  return result;
}

std::vector<packed_circuit::word_t> compute_virtual_feature_bits(
    const packed_circuit& packed,
    const std::vector<VirtualNodeDef>& defs,
    packed_circuit::word_t pattern_mask) {
  std::vector<packed_circuit::word_t> result;
  result.reserve(defs.size());
  for (const auto& def : defs) {
    packed_circuit::word_t val = 0;
    if (def.op == GType::AND) {
      val = pattern_mask;  // Start with all-1s for AND.
      for (const auto& inp : def.inputs) {
        packed_circuit::word_t bits = packed.node_bits(inp.first);
        if (inp.second) {
          bits = (~bits) & pattern_mask;
        }
        val &= bits;
      }
    } else if (def.op == GType::OR) {
      val = 0;  // Start with all-0s for OR.
      for (const auto& inp : def.inputs) {
        packed_circuit::word_t bits = packed.node_bits(inp.first);
        if (inp.second) {
          bits = (~bits) & pattern_mask;
        }
        val |= bits;
      }
    } else if (def.op == GType::NOT && !def.inputs.empty()) {
      packed_circuit::word_t bits = packed.node_bits(def.inputs[0].first);
      val = (~bits) & pattern_mask;
    }
    result.push_back(val);
  }
  return result;
}

int compute_virtual_feature_value(
    const circuit& c,
    const VirtualNodeDef& def) {
  if (def.op == GType::AND) {
    for (const auto& inp : def.inputs) {
      int v = c.get_cell(inp.first).val;
      if (inp.second) v = !v;
      if (!v) return 0;
    }
    return 1;
  }
  if (def.op == GType::OR) {
    for (const auto& inp : def.inputs) {
      int v = c.get_cell(inp.first).val;
      if (inp.second) v = !v;
      if (v) return 1;
    }
    return 0;
  }
  if (def.op == GType::NOT && !def.inputs.empty()) {
    return !c.get_cell(def.inputs[0].first).val;
  }
  return 0;
}

std::vector<int> find_used_virtual_gate_indices(
    const std::vector<int>& feature_nodes,
    const DecisionTreeModel& model,
    std::size_t original_node_count) {
  std::unordered_set<int> used;
  for (const auto& rule : model.rules) {
    for (const auto& term : rule.terms) {
      const std::size_t fidx = term.first;
      if (fidx < feature_nodes.size()) {
        const int node_idx = feature_nodes[fidx];
        if (node_idx >= static_cast<int>(original_node_count)) {
          used.insert(node_idx);
        }
      }
    }
  }
  std::vector<int> sorted(used.begin(), used.end());
  std::sort(sorted.begin(), sorted.end());
  return sorted;
}
