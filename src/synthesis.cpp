#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "io/bench_parser.hpp"
#include "io/bench_writer.hpp"
#include "io/eqn_parser.hpp"

struct Flow {
  std::string name;
  std::string description;
  std::string script;
};

const std::vector<Flow> kFlows = {
    {"resyn2",
     "balance + rewrite/refactor (general purpose)",
     "strash; balance; rewrite; refactor; balance; rewrite -z; refactor -z"},
    {"area",
     "rewrite/refactor focused (area oriented)",
     "strash; rewrite; refactor; rewrite -z; refactor -z; rewrite -z; refactor -z"},
    {"delay",
     "more balance passes (delay oriented)",
     "strash; balance; balance; rewrite; balance; rewrite -z; balance"},
};

const Flow* find_flow(const std::string& name) {
  for (const auto& flow : kFlows) {
    if (flow.name == name) {
      return &flow;
    }
  }
  return nullptr;
}

void print_flows() {
  std::cout << "Available flows:\n";
  for (std::size_t i = 0; i < kFlows.size(); ++i) {
    std::cout << "  " << (i + 1) << ") " << kFlows[i].name << " - " << kFlows[i].description
              << "\n";
  }
}

const Flow* prompt_flow() {
  print_flows();
  std::cout << "Select flow number [1-" << kFlows.size() << "] (default 1): ";
  std::string input;
  if (!std::getline(std::cin, input)) {
    return nullptr;
  }
  if (input.empty()) {
    return &kFlows[0];
  }
  std::size_t pos = 0;
  int choice = 0;
  try {
    choice = std::stoi(input, &pos);
  } catch (...) {
    return nullptr;
  }
  if (pos != input.size() || choice < 1 || choice > static_cast<int>(kFlows.size())) {
    return nullptr;
  }
  return &kFlows[static_cast<std::size_t>(choice - 1)];
}

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <input_bench> <output_bench> [--flow name]\n";
    std::cerr << "       " << argv[0] << " <input_bench> <output_bench> [--list]\n";
    return 1;
  }

  const std::string input_path = argv[1];
  const std::string output_path = argv[2];
  const std::string eqn_path = output_path + ".eqn";

  std::string flow_name;
  for (int i = 3; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--list") {
      print_flows();
      return 0;
    }
    if (arg == "--flow" || arg == "-f") {
      if (i + 1 >= argc) {
        std::cerr << "Missing value for " << arg << "\n";
        return 1;
      }
      flow_name = argv[++i];
      continue;
    }
    const std::string prefix = "--flow=";
    if (arg.rfind(prefix, 0) == 0) {
      flow_name = arg.substr(prefix.size());
      continue;
    }
    std::cerr << "Unknown argument: " << arg << "\n";
    return 1;
  }

  const Flow* flow = nullptr;
  if (!flow_name.empty()) {
    flow = find_flow(flow_name);
    if (!flow) {
      std::cerr << "Unknown flow: " << flow_name << "\n";
      print_flows();
      return 1;
    }
  } else {
    flow = prompt_flow();
    if (!flow) {
      std::cerr << "Invalid selection\n";
      return 1;
    }
  }

  circuit original;
  std::string error;
  if (!bench_io::parse_bench_file(input_path, original, &error)) {
    std::cerr << "Parse error: " << error << "\n";
    return 1;
  }

  std::cout << "original area level\n";
  std::cout << original.area() << ' ' << original.level() << "\n";

  const char* abc_bin = std::getenv("ABC_BIN");
  std::string abc_cmd = (abc_bin && *abc_bin) ? abc_bin : "abc";
  const std::string script = "read_bench '" + input_path + "'; " + flow->script +
                             "; short_names; write_eqn '" + eqn_path + "'";
  abc_cmd += " -c \"" + script + "\"";

  int ret = std::system(abc_cmd.c_str());
  if (ret != 0) {
    std::cerr << "ABC failed, make sure abc is in PATH or set ABC_BIN\n";
    return 1;
  }

  circuit synth;
  if (!bench_io::parse_eqn_file(eqn_path, synth, &error)) {
    std::cerr << "EQN parse error: " << error << "\n";
    return 1;
  }

  std::cout << "synth area level\n";
  std::cout << synth.area() << ' ' << synth.level() << "\n";

  if (!bench_io::write_bench_file(output_path, synth, &error)) {
    std::cerr << "Write error: " << error << "\n";
    return 1;
  }

  return 0;
}
