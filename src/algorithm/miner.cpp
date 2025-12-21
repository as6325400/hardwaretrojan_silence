#include "miner.hpp"

#include <algorithm>
#include <iostream>
#include <random>

namespace {

struct TrainingData {
  std::vector<std::vector<int>> features;
  std::vector<int> labels;
  std::size_t pos_count = 0;
  std::size_t neg_count = 0;
};

struct EvalResult {
  std::size_t checked = 0;
  std::size_t false_pos = 0;
  std::size_t added = 0;
};

std::vector<int> build_feature_nodes(const circuit& trojan,
                                     const std::vector<int>& candidate_gate_indices,
                                     bool with_pi) {
  std::vector<int> nodes = candidate_gate_indices;
  if (with_pi) {
    const auto& pi_indices = trojan.pi_indices();
    nodes.insert(nodes.end(), pi_indices.begin(), pi_indices.end());
  }
  return nodes;
}

std::vector<int> collect_features(circuit& c, const std::vector<int>& feature_nodes) {
  std::vector<int> row;
  row.reserve(feature_nodes.size());
  for (int idx : feature_nodes) {
    row.push_back(c.get_cell(idx).val ? 1 : 0);
  }
  return row;
}

bool build_training_data(const circuit& golden,
                         const circuit& trojan,
                         const std::vector<std::vector<int>>& trigger_patterns,
                         const std::vector<int>& feature_nodes,
                         std::size_t neg_ratio,
                         TrainingData* data) {
  data->features.clear();
  data->labels.clear();
  data->pos_count = 0;
  data->neg_count = 0;

  circuit golden_train = golden;
  circuit trojan_train = trojan;

  for (const auto& pattern : trigger_patterns) {
    try {
      trojan_train.simulate(pattern);
    } catch (const std::exception& e) {
      std::cerr << "Training trigger simulation error: " << e.what() << "\n";
      continue;
    }
    data->features.push_back(collect_features(trojan_train, feature_nodes));
    data->labels.push_back(1);
    data->pos_count += 1;
  }

  if (data->pos_count == 0) {
    return false;
  }

  const std::size_t target_negatives = data->pos_count * std::max<std::size_t>(1, neg_ratio);
  data->features.reserve(data->pos_count + target_negatives);
  data->labels.reserve(data->pos_count + target_negatives);

  std::size_t attempts = 0;
  const std::size_t max_attempts = target_negatives * 20 + 1000;
  std::mt19937 rng(1337);
  std::uniform_int_distribution<int> dist(0, 1);

  while (data->neg_count < target_negatives && attempts < max_attempts) {
    std::vector<int> pi_values;
    pi_values.reserve(golden_train.pi_count());
    for (std::size_t i = 0; i < golden_train.pi_count(); ++i) {
      pi_values.push_back(dist(rng));
    }
    std::vector<int> golden_outputs;
    std::vector<int> trojan_outputs;
    try {
      golden_outputs = golden_train.simulate(pi_values);
      trojan_outputs = trojan_train.simulate(pi_values);
    } catch (const std::exception&) {
      ++attempts;
      continue;
    }

    bool triggered = false;
    for (std::size_t i = 0; i < golden_outputs.size(); ++i) {
      if (golden_outputs[i] != trojan_outputs[i]) {
        triggered = true;
        break;
      }
    }
    if (!triggered) {
      data->features.push_back(collect_features(trojan_train, feature_nodes));
      data->labels.push_back(0);
      data->neg_count += 1;
    }
    attempts += 1;
  }

  return true;
}

bool train_model(const TrainingData& data,
                 const DecisionTreeOptions& options,
                 DecisionTreeModel* model,
                 std::size_t* train_pos,
                 std::size_t* train_neg,
                 std::size_t* train_false_pos,
                 std::size_t* train_false_neg,
                 std::string* error) {
  if (error) {
    error->clear();
  }
  *model = build_decision_tree(data.features, data.labels, options, error);
  if (error && !error->empty()) {
    std::cerr << "Decision tree error: " << *error << "\n";
    return false;
  }

  *train_pos = 0;
  *train_neg = 0;
  *train_false_pos = 0;
  *train_false_neg = 0;
  for (std::size_t i = 0; i < data.features.size(); ++i) {
    const bool pred = eval_rules(model->rules, data.features[i]);
    if (data.labels[i] == 1) {
      *train_pos += 1;
      if (!pred) {
        *train_false_neg += 1;
      }
    } else {
      *train_neg += 1;
      if (pred) {
        *train_false_pos += 1;
      }
    }
  }
  return true;
}

EvalResult eval_and_mine(const circuit& golden,
                         const circuit& trojan,
                         const std::vector<int>& feature_nodes,
                         const DecisionTreeModel& model,
                         std::size_t eval_limit,
                         std::size_t max_add,
                         TrainingData* data,
                         std::uint32_t seed) {
  EvalResult result;
  std::size_t attempts = 0;
  const std::size_t max_attempts = eval_limit * 20 + 1000;
  std::mt19937 rng(seed);
  std::uniform_int_distribution<int> dist(0, 1);
  circuit golden_eval = golden;
  circuit trojan_eval = trojan;

  while (result.checked < eval_limit && attempts < max_attempts) {
    std::vector<int> pi_values;
    pi_values.reserve(golden_eval.pi_count());
    for (std::size_t i = 0; i < golden_eval.pi_count(); ++i) {
      pi_values.push_back(dist(rng));
    }
    std::vector<int> golden_outputs;
    std::vector<int> trojan_outputs;
    try {
      golden_outputs = golden_eval.simulate(pi_values);
      trojan_outputs = trojan_eval.simulate(pi_values);
    } catch (const std::exception&) {
      ++attempts;
      continue;
    }

    bool triggered = false;
    for (std::size_t i = 0; i < golden_outputs.size(); ++i) {
      if (golden_outputs[i] != trojan_outputs[i]) {
        triggered = true;
        break;
      }
    }
    if (!triggered) {
      const std::vector<int> row = collect_features(trojan_eval, feature_nodes);
      if (eval_rules(model.rules, row)) {
        result.false_pos += 1;
        if (data && result.added < max_add) {
          data->features.push_back(row);
          data->labels.push_back(0);
          data->neg_count += 1;
          result.added += 1;
        }
      }
      result.checked += 1;
    }
    attempts += 1;
  }
  return result;
}

void print_rules(const circuit& trojan,
                 const std::vector<int>& feature_nodes,
                 const DecisionTreeModel& model) {
  std::cout << "decision_tree_rules " << model.rules.size()
            << " depth_used " << model.max_depth_used
            << " leaf_count " << model.leaf_count << '\n';
  for (std::size_t i = 0; i < model.rules.size(); ++i) {
    const auto& rule = model.rules[i];
    std::cout << "rule " << (i + 1) << ": ";
    if (rule.terms.empty()) {
      std::cout << "TRUE\n";
      continue;
    }
    for (std::size_t t = 0; t < rule.terms.size(); ++t) {
      if (t > 0) {
        std::cout << " & ";
      }
      const std::size_t feature_idx = rule.terms[t].first;
      const int value = rule.terms[t].second;
      if (feature_idx < feature_nodes.size()) {
        std::cout << trojan.node_name(feature_nodes[feature_idx]) << '=' << value;
      } else {
        std::cout << "f" << feature_idx << '=' << value;
      }
    }
    std::cout << '\n';
  }
}

bool run_mining_loop(const circuit& golden,
                     const circuit& trojan,
                     const std::vector<int>& feature_nodes,
                     const DecisionTreeOptions& options,
                     TrainingData* data,
                     std::size_t rounds,
                     std::size_t max_add,
                     std::size_t eval_count,
                     double target_rate,
                     MiningResult* result,
                     std::string* error) {
  const std::size_t total_rounds = std::max<std::size_t>(1, rounds);
  result->feature_nodes = feature_nodes;
  result->hard_added = 0;
  result->rounds_used = 0;

  for (std::size_t round = 0; round < total_rounds; ++round) {
    if (!train_model(*data,
                     options,
                     &result->model,
                     &result->train_pos,
                     &result->train_neg,
                     &result->train_false_pos,
                     &result->train_false_neg,
                     error)) {
      return false;
    }

    const std::size_t add_cap = (round + 1 < total_rounds) ? max_add : 0;
    EvalResult eval = eval_and_mine(golden,
                                    trojan,
                                    feature_nodes,
                                    result->model,
                                    eval_count,
                                    add_cap,
                                    data,
                                    static_cast<std::uint32_t>(2027 + round));
    result->eval_checked = eval.checked;
    result->eval_false_pos = eval.false_pos;
    result->hard_added += eval.added;
    result->rounds_used = round + 1;
    result->data_pos = data->pos_count;
    result->data_neg = data->neg_count;

    double eval_rate = 0.0;
    if (eval.checked > 0) {
      eval_rate = static_cast<double>(eval.false_pos) /
                  static_cast<double>(eval.checked);
    }
    if (total_rounds > 1) {
      std::cout << "round " << (round + 1) << '\n';
      std::cout << "mine_round " << (round + 1)
                << " hard_added " << eval.added
                << " eval_rate " << eval_rate << '\n';
    }
    std::cout << "train_pos " << result->train_pos
              << " train_neg " << result->train_neg << '\n';
    std::cout << "eval_normal " << eval.checked
              << " eval_false_pos " << eval.false_pos;
    if (eval.checked > 0) {
      std::cout << " rate " << eval_rate;
    }
    std::cout << '\n';
    print_rules(trojan, feature_nodes, result->model);

    if (result->train_false_pos == 0 && eval.checked > 0 &&
        (eval_rate <= target_rate || target_rate == 0.0)) {
      break;
    }
    if (eval.added == 0) {
      break;
    }
  }

  return true;
}

}  // namespace

bool run_mining(const circuit& golden,
                const circuit& trojan,
                const std::vector<std::vector<int>>& trigger_patterns,
                const std::vector<int>& candidate_gate_indices,
                const MiningOptions& options,
                double target_rate,
                MiningResult* result,
                std::string* error) {
  if (error) {
    error->clear();
  }
  if (!result) {
    if (error) {
      *error = "Mining result pointer is null";
    }
    return false;
  }
  if (candidate_gate_indices.empty()) {
    if (error) {
      *error = "No candidate nets available for mining";
    }
    return false;
  }
  if (trigger_patterns.empty()) {
    if (error) {
      *error = "No mismatch patterns collected";
    }
    return false;
  }

  DecisionTreeOptions tree_options;
  tree_options.max_depth = options.max_depth;
  tree_options.force_split = options.force_split;

  std::vector<int> feature_nodes = build_feature_nodes(trojan, candidate_gate_indices, options.include_pi);
  if (feature_nodes.empty()) {
    if (error) {
      *error = "No feature nodes available for training";
    }
    return false;
  }

  TrainingData data;
  if (!build_training_data(golden,
                           trojan,
                           trigger_patterns,
                           feature_nodes,
                           options.neg_ratio,
                           &data)) {
    if (error) {
      *error = "Failed to build training data";
    }
    return false;
  }

  if (!run_mining_loop(golden,
                       trojan,
                       feature_nodes,
                       tree_options,
                       &data,
                       options.mine_rounds,
                       options.mine_max,
                       options.eval_count,
                       target_rate,
                       result,
                       error)) {
    if (error && error->empty()) {
      *error = "Failed to run mining loop";
    }
    return false;
  }

  if (options.strict_retry && result->train_false_pos > 0) {
    std::cout << "strict_mode 1\n";
    DecisionTreeOptions strict_options;
    strict_options.force_split = true;
    std::vector<int> strict_features = build_feature_nodes(trojan, candidate_gate_indices, true);
    strict_options.max_depth = std::max(options.max_depth, strict_features.size());
    TrainingData strict_data;
    if (build_training_data(golden,
                            trojan,
                            trigger_patterns,
                            strict_features,
                            options.neg_ratio,
                            &strict_data) &&
        run_mining_loop(golden,
                        trojan,
                        strict_features,
                        strict_options,
                        &strict_data,
                        options.mine_rounds,
                        options.mine_max,
                        options.eval_count,
                        target_rate,
                        result,
                        error)) {
      std::cout << "strict_features " << strict_features.size()
                << " strict_depth " << strict_options.max_depth << "\n";
    } else {
      std::cout << "strict_mode failed\n";
    }
  }

  return true;
}
