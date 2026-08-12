#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "../algorithm/dac25_runeco.hpp"
#include "../io/bench_parser.hpp"

namespace {

namespace fs = std::filesystem;
int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

circuit make_golden() {
  circuit net;
  net.define_pi("a");
  net.define_pi("b");
  net.define_gate("y", GType::BUFF, {net.node_index("a")});
  net.add_output_name("y");
  net.finalize_outputs();
  return net;
}

circuit make_trojan() {
  circuit net;
  net.define_pi("b");
  net.define_pi("a");
  net.define_gate("q", GType::NOT, {net.node_index("a")});
  net.define_gate("y", GType::BUFF, {net.node_index("q")});
  net.add_output_name("y");
  net.finalize_outputs();
  return net;
}

fs::path make_temp_directory() {
  std::string pattern = "/tmp/test-dac25-runeco-XXXXXX";
  std::vector<char> writable(pattern.begin(), pattern.end());
  writable.push_back('\0');
  char* path = mkdtemp(writable.data());
  if (!path) return {};
  return fs::path(path);
}

void test_input_validation() {
  circuit golden = make_golden();
  const circuit trojan = make_trojan();
  const Dac25RunecoResult missing_target = run_dac25_runeco(
      golden, trojan, {}, "abc", 1, "/tmp/unused-dac25.bench");
  expect(missing_target.status == Dac25RunecoStatus::invalid_input,
         "an empty target set is rejected before launch");
  const Dac25RunecoResult duplicate = run_dac25_runeco(
      golden, trojan,
      {trojan.node_index("q"), trojan.node_index("q")}, "abc", 1,
      "/tmp/unused-dac25.bench");
  expect(duplicate.status == Dac25RunecoStatus::invalid_input,
         "duplicate target nodes are rejected");
}

void test_real_abc_when_available() {
  const char* abc = std::getenv("DAC25_TEST_ABC");
  if (!abc || abc[0] == '\0') {
    std::cout << "DAC25_TEST_ABC unset; skipping external runeco test\n";
    return;
  }
  const fs::path temp = make_temp_directory();
  expect(!temp.empty(), "test temporary directory was created");
  if (temp.empty()) return;
  const fs::path output = temp / "patched.bench";
  circuit golden = make_golden();
  const circuit trojan = make_trojan();
  const Dac25RunecoResult result = run_dac25_runeco(
      golden, trojan, {trojan.node_index("q")}, abc, 10,
      output.string());
  expect(result.ok(), std::string("runeco succeeds: ") + result.reason);
  expect(result.metrics.selected_targets == 1,
         "runeco records selected target count");
  expect(result.metrics.patch_added_gates == 1,
         "runeco parses the one-gate synthetic patch");
  expect(fs::is_regular_file(output), "runeco writes a durable BENCH output");

  circuit patched;
  std::string error;
  expect(bench_io::parse_bench_file(output.string(), patched, &error),
         "runeco BENCH output parses: " + error);
  if (patched.po_count() == 1 && patched.pi_count() == 2) {
    for (int a = 0; a <= 1; ++a) {
      for (int b = 0; b <= 1; ++b) {
        std::vector<int> golden_pattern{a, b};
        std::vector<int> patched_pattern;
        for (int pi : patched.pi_indices()) {
          patched_pattern.push_back(patched.node_name(pi) == "pi_0" ? a : b);
        }
        const std::vector<int> golden_output = golden.simulate(golden_pattern);
        const std::vector<int> patched_output = patched.simulate(patched_pattern);
        expect(golden_output == patched_output,
               "patched synthetic circuit matches every PI assignment");
      }
    }
  }
  std::error_code ignored;
  fs::remove_all(temp, ignored);
}

}  // namespace

int main() {
  test_input_validation();
  test_real_abc_when_available();
  if (failures != 0) {
    std::cerr << failures << " DAC25 runeco test(s) failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "DAC25 runeco tests passed\n";
  return EXIT_SUCCESS;
}
