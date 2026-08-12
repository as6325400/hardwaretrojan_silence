#!/usr/bin/env python3
"""Regression tests for the rule-method A/B runner."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import compare_rule_methods as runner


FAKE_MAIN = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys
import time

if "--help" in sys.argv:
    print("Usage: fake <g> <t> <gt> <out> "
          "[--rule-method vn-retrain|dt|z3-pb|milp-cover] "
          "[--repair-method legacy|dac25-inspired] "
          "[--dac25-selector-timeout-ms N] [--dac25-candidate-limit N] "
          "[--dac25-max-targets N] [--dac25-max-sets N] "
          "[--dac25-runeco-timeout-s N] [--dac25-abc-bin PATH]")
    raise SystemExit(0)

expected_abc = os.environ.get("FAKE_EXPECT_ABC_BIN")
if expected_abc and os.environ.get("ABC_BIN") != expected_abc:
    print("ABC_BIN was not pinned to the runner's --abc", file=sys.stderr)
    raise SystemExit(3)

rule_method = sys.argv[sys.argv.index("--rule-method") + 1]
repair_method = (
    sys.argv[sys.argv.index("--repair-method") + 1]
    if "--repair-method" in sys.argv
    else "legacy"
)
method = "dac25-inspired" if repair_method == "dac25-inspired" else rule_method
if method == "dac25-inspired" and any(
    arg.startswith("--rule-formal-") for arg in sys.argv
):
    print("formal flags leaked into DAC25 invocation", file=sys.stderr)
    raise SystemExit(4)
counter = os.environ.get("FAKE_INVOCATION_COUNTER")
if counter:
    with Path(counter).open("a", encoding="utf-8") as sink:
        sink.write(method + "\n")
child_pid_path = os.environ.get("FAKE_CHILD_PID_PATH")
if child_pid_path:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        preexec_fn=os.setpgrp,
    )
    Path(child_pid_path).write_text(str(child.pid), encoding="ascii")
if os.environ.get("FAKE_MAIN_SLEEP"):
    time.sleep(float(os.environ["FAKE_MAIN_SLEEP"]))
if os.environ.get("FAKE_MUTATE_INPUT"):
    with Path(os.environ["FAKE_MUTATE_INPUT"]).open("a", encoding="utf-8") as sink:
        sink.write("# mutated during run\n")
if os.environ.get("FAKE_MUTATE_HIGHS"):
    with Path(os.environ["FAKE_MUTATE_HIGHS"]).open("a", encoding="utf-8") as sink:
        sink.write("# mutated during run\n")

Path(sys.argv[4]).write_text(
    "INPUT(a)\nOUTPUT(n1)\nn1 = BUF(a)\n# " + method + "\n",
    encoding="utf-8",
)
if method == "dac25-inspired":
    print("rectification_summary summary_kind overall strategy z3-pb "
          "repair_method dac25-inspired "
          "cec_attempt 1 synth_pass 1 rule_build_attempt 2 "
          "rectification_attempt 1 source selector status success "
          "raw_candidates 64 filtered_candidates 20 selector_ms 4.2")
    print("rectification_summary summary_kind trial strategy z3-pb "
          "repair_method dac25-inspired "
          "cec_attempt 1 synth_pass 1 rule_build_attempt 2 "
          "rectification_attempt 1 set_attempt 1 source dac25_runeco "
          "status success selected 1 sets_checked 3 feasible_sets 1 "
          "selected_targets 1 "
          "patch_trials 1 proved 1 patch_ms 31.0")
elif method == "z3-pb":
    print("rule_synth_summary strategy z3-pb cec_attempt 1 synth_pass 1 "
          "rule_build_attempt 1 dt_builds 1 candidate_count 17 solver_status optimal "
          "pb_variables 13 final_rules 2 final_literals 3 final_depth 2 synth_ms 4.5")
    print("rule_synth_summary strategy z3-pb cec_attempt 2 synth_pass 1 "
          "rule_build_attempt 2 dt_builds 2 candidate_count 19 solver_status optimal "
          "pb_variables 15 final_rules 1 final_literals 2 final_depth 1 synth_ms 5.5")
    print("rule_apply_summary strategy z3-pb cec_attempt 1 synth_pass 1 "
          "rule_build_attempt 1 source signature_minimize rule_model_used 1 effective_rules 2 "
          "effective_literals 3 effective_depth 2")
    print("rule_apply_summary strategy z3-pb cec_attempt 2 synth_pass 1 "
          "rule_build_attempt 2 source literal_patch_cut rule_model_used 0 effective_rules 1 "
          "effective_literals 1 effective_depth 1")
    if "--rule-formal-refine" in sys.argv:
        print("rule_miter_summary strategy z3-pb cec_attempt 1 synth_pass 1 "
              "rule_build_attempt 1 refine_rounds 1 status counterexamples "
              "proved 0 returned 2 added 2 checks 2 total_ms 2.5")
        print("rule_miter_summary strategy z3-pb cec_attempt 2 synth_pass 1 "
              "rule_build_attempt 2 refine_rounds 1 status proved "
              "proved 1 returned 0 added 0 checks 2 total_ms 1.5")
elif method == "milp-cover":
    print("rule_synth_summary strategy milp-cover cec_attempt 1 synth_pass 1 "
          "rule_build_attempt 1 dt_builds 1 candidate_count 17 optimizer_status accepted "
          "cover_variables 7 mip_nodes 3 synthesized_rules 1 "
          "synthesized_literals 2 synthesized_depth 2 synth_ms 3.5")
    print("rule_apply_summary strategy milp-cover cec_attempt 1 synth_pass 1 "
          "rule_build_attempt 1 source signature_minimize rule_model_used 1 effective_rules 1 "
          "effective_literals 2 effective_depth 2")
    if "--rule-formal-refine" in sys.argv:
        print("rule_miter_summary strategy milp-cover cec_attempt 1 synth_pass 1 "
              "rule_build_attempt 1 refine_rounds 0 status proved "
              "proved 1 returned 0 added 0 checks 2 total_ms 1.0")
else:
    print("rule_synth_summary strategy vn-retrain cec_attempt 1 synth_pass 1 "
          "rule_build_attempt 1 dt_builds 3 vn_generated 4 vn_used 1 final_rules 2 "
          "final_literals 4 final_depth 3 synth_ms 12.5")
    print("rule_apply_summary strategy vn-retrain cec_attempt 1 synth_pass 1 "
          "rule_build_attempt 1 source signature_minimize rule_model_used 1 effective_rules 2 "
          "effective_literals 3 effective_depth 2")
print("payload_fix_selected 1 area_delta 999 level_delta 999")
print("cec_rounds 1")
print("[TIMING]   final_verify: 1.0 ms (PASS)", file=sys.stderr)
print("[TIMING] TOTAL: 25.0 ms", file=sys.stderr)
'''


FAKE_ABC = r'''#!/usr/bin/env python3
import os
import shlex
import sys
patch_path = shlex.split(sys.argv[-1])[-1]
if not patch_path.endswith(".bench"):
    print("unknown file format")
    raise SystemExit(2)
if os.environ.get("FAKE_ABC_MODE") == "fail":
    print("Networks are NOT EQUIVALENT")
elif os.environ.get("FAKE_ABC_MODE") == "marker_nonzero":
    print("Networks are equivalent")
    raise SystemExit(7)
else:
    print("Networks are equivalent")
'''


FAKE_SHOW = r'''#!/usr/bin/env python3
from pathlib import Path
import sys

name = Path(sys.argv[1]).name
if name == "c1.bench":
    print("area 10 delay 2")
elif name == "trojan1.bench":
    print("area 14 delay 4")
else:
    print("area 11 delay 3")
'''


FAKE_LDD = r'''#!/usr/bin/env python3
import os
import sys

library = os.environ.get("FAKE_LDD_HIGHS")
if not library:
    print("not a dynamic executable", file=sys.stderr)
    raise SystemExit(1)
print("libhighs.so.1 => " + library + " (0x0000000000000000)")
'''


class RunnerFixture(unittest.TestCase):
    def setUp(self) -> None:
        # A space in the root exercises ABC command-language path quoting.
        self.temporary = tempfile.TemporaryDirectory(prefix="rule method ")
        self.root = Path(self.temporary.name)
        (self.root / "benchmarks").mkdir()
        (self.root / "trojans" / "c1").mkdir(parents=True)
        (self.root / "groundtruth" / "c1").mkdir(parents=True)
        (self.root / "bin").mkdir()
        (self.root / "benchmarks" / "c1.bench").write_text(
            "INPUT(a)\nOUTPUT(a)\n", encoding="utf-8"
        )
        (self.root / "trojans" / "c1" / "trojan1.bench").write_text(
            "INPUT(a)\nOUTPUT(n1)\nn1 = NOT(a)\n", encoding="utf-8"
        )
        (self.root / "groundtruth" / "c1" / "trojan1_error_patterns.json").write_text(
            '{"pattern_count": 1}\n', encoding="utf-8"
        )
        self.main_path = self._executable("bin/main", FAKE_MAIN)
        self.abc_path = self._executable("abc", FAKE_ABC)
        self.show_path = self._executable("bin/show", FAKE_SHOW)
        self.fake_tools = self.root / "fake-tools"
        self.ldd_path = self._executable("fake-tools/ldd", FAKE_LDD)
        self.highs_path = self.root / "lib" / "libhighs.so.1"
        self.highs_path.parent.mkdir()
        self.highs_path.write_text("fake highs library\n", encoding="utf-8")
        self.counter = self.root / "invocations.txt"
        self.manifest = self.root / "cases.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": runner.MANIFEST_SCHEMA_VERSION,
                    "dataset": {
                        "golden_root": "benchmarks",
                        "trojan_root": "trojans",
                        "groundtruth_root": "groundtruth",
                    },
                    "common_args": ["--depth", "10"],
                    "profiles": {"all": ["case1"]},
                    "cases": [
                        {
                            "case_id": "case1",
                            "circuit": "c1",
                            "trojan": "trojan1",
                            "cohort": "fixture",
                            "timeout_seconds": 2,
                            "legacy_v6": {"vn_rounds": 2},
                        }
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.output = self.root / "output"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _executable(self, relative: str, contents: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)
        return path

    def args(self, *extra: str) -> list[str]:
        return [
            "--repo-root", str(self.root),
            "--manifest", str(self.manifest),
            "--bin", str(self.main_path),
            "--abc", str(self.abc_path),
            "--show", str(self.show_path),
            "--output-root", str(self.output),
            *extra,
        ]

    def highs_environment(self, **extra: str) -> dict[str, str]:
        environment = {
            "PATH": str(self.fake_tools) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_LDD_HIGHS": str(self.highs_path),
        }
        environment.update(extra)
        return environment


class SummaryParserTest(unittest.TestCase):
    def test_preserves_generic_and_strategy_specific_keys(self) -> None:
        stdout = (
            "noise\n"
            "rule_synth_summary strategy z3-pb cec_attempt 1 "
            "rule_build_attempt 1 solver_status optimal pb_variables 31 synth_ms 1.25\n"
            "rule_synth_summary strategy z3-pb cec_attempt 2 "
            "rule_build_attempt 2 solver_status optimal pb_variables 29 synth_ms 2.75\n"
            "rule_apply_summary rule_build_attempt 1 source rule_model\n"
            "rule_apply_summary rule_build_attempt 2 source literal_patch_cut\n"
            # Deliberately reverse miter order: association must use the ID.
            "rule_miter_summary rule_build_attempt 2 status proved proved 1 "
            "total_ms 1.5\n"
            "rule_miter_summary rule_build_attempt 1 status counterexamples "
            "proved 0 returned 2 total_ms 2.5\n"
            # Rectification telemetry is also joined by build ID, not position.
            "rectification_summary rule_build_attempt 2 "
            "rectification_attempt 1 set_attempt 2 status selected "
            "source \"proof core\" solver_ms 6.75\n"
            "rectification_summary rule_build_attempt 1 "
            "rectification_attempt 1 set_attempt 1 status infeasible "
            "source selector solver_ms 3.25\n"
        )
        summaries = runner.parse_rule_synth_summaries(stdout)
        self.assertEqual(len(summaries), 2)
        self.assertEqual(summaries[0]["solver_status"], "optimal")
        self.assertEqual(summaries[0]["pb_variables"], 31)
        aggregates = runner._summary_aggregates(summaries)
        self.assertEqual(aggregates["last"]["pb_variables"], 29)
        self.assertEqual(aggregates["numeric_sum"]["synth_ms"], 4.0)

        apply = runner.parse_rule_apply_summaries(
            "rule_apply_summary source literal_patch_cut effective_rules 1\n"
        )
        self.assertEqual(apply[0]["source"], "literal_patch_cut")
        self.assertEqual(apply[0]["effective_rules"], 1)

        parsed = runner.parse_main_output(stdout, "")
        self.assertEqual(parsed["rule_miter_summary_count"], 2)
        self.assertEqual(
            parsed["rule_miter_aggregates"]["numeric_sum"]["total_ms"], 4.0
        )
        self.assertEqual(parsed["rectification_summary_count"], 2)
        self.assertEqual(
            parsed["rectification_aggregates"]["numeric_sum"]["solver_ms"],
            10.0,
        )
        self.assertNotIn(
            "set_attempt",
            parsed["rectification_aggregates"]["numeric_sum"],
        )
        self.assertEqual(parsed["rule_build_attempt_count"], 2)
        attempts = {
            item["rule_build_attempt"]: item
            for item in parsed["rule_build_attempts"]
        }
        self.assertEqual(
            attempts[1]["rule_miter_summaries"][0]["status"],
            "counterexamples",
        )
        self.assertEqual(
            attempts[2]["rule_miter_summaries"][0]["status"], "proved"
        )
        self.assertEqual(
            attempts[1]["rectification_summaries"][0]["status"],
            "infeasible",
        )
        self.assertEqual(
            attempts[2]["rectification_summaries"][0]["source"],
            "proof core",
        )
        self.assertEqual(
            parsed["rule_build_unlinked_summaries"],
            {
                "rule_synth_summaries": [],
                "rule_apply_summaries": [],
                "rule_miter_summaries": [],
                "rectification_summaries": [],
            },
        )

    def test_rectification_parser_preserves_malformed_lines(self) -> None:
        parsed = runner.parse_rectification_summaries(
            "rectification_summary status selected dangling\n"
            "rectification_summary status \"unterminated\n"
        )
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["status"], "selected")
        self.assertEqual(parsed[0]["_unparsed_tail"], "dangling")
        self.assertIn("_parse_error", parsed[1])

    def test_numeric_sum_is_exact_and_excludes_non_additive_metadata(self) -> None:
        uint64_max = (1 << 64) - 1
        summaries = [
            {
                "_line": 1,
                "rule_build_attempt": 1,
                "cec_attempt": 1,
                "synth_pass": 1,
                "refine_rounds": 1,
                "literal_node": 101,
                "literal_expected": 1,
                "literal_forced": -1,
                "cover_phase3_timeout_ms": uint64_max,
                "cover_phase4_timeout_ms": uint64_max,
                "cover_logic_risk_unique_weight": 0.25,
                "cover_logic_risk_fanout_weight": 0.25,
                "cover_logic_risk_timing_weight": 0.5,
                "optimizer_checks": uint64_max,
                "candidate_count": 2,
                "solver_ms": 1.25,
            },
            {
                "_line": 2,
                "rule_build_attempt": 2,
                "cec_attempt": 1,
                "synth_pass": 1,
                "refine_rounds": 2,
                "literal_node": 202,
                "literal_expected": 0,
                "literal_forced": 1,
                "cover_phase3_timeout_ms": uint64_max,
                "cover_phase4_timeout_ms": uint64_max,
                "cover_logic_risk_unique_weight": 0.25,
                "cover_logic_risk_fanout_weight": 0.25,
                "cover_logic_risk_timing_weight": 0.5,
                "optimizer_checks": uint64_max,
                "candidate_count": 3,
                "solver_ms": 2.75,
            },
        ]

        aggregates = runner._summary_aggregates(summaries)
        numeric_sum = aggregates["numeric_sum"]
        self.assertEqual(numeric_sum["optimizer_checks"], 2 * uint64_max)
        self.assertIsInstance(numeric_sum["optimizer_checks"], int)
        self.assertEqual(numeric_sum["candidate_count"], 5)
        self.assertEqual(numeric_sum["solver_ms"], 4.0)
        for key in runner._NON_ADDITIVE_SUMMARY_KEYS:
            self.assertNotIn(key, numeric_sum)

        # Non-additive fields remain available without loss in raw snapshots.
        self.assertEqual(
            aggregates["first"]["cover_phase3_timeout_ms"], uint64_max
        )
        self.assertEqual(aggregates["last"]["refine_rounds"], 2)


class EndToEndTest(RunnerFixture):
    def test_atomic_artifacts_metrics_and_resume(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "FAKE_INVOCATION_COUNTER": str(self.counter),
                "FAKE_EXPECT_ABC_BIN": str(self.abc_path),
            },
            clear=False,
        ):
            self.assertEqual(runner.main(self.args()), 0)
        self.assertEqual(self.counter.read_text(encoding="utf-8").splitlines(),
                         ["vn-retrain", "z3-pb"])

        summary = json.loads((self.output / "summary.json").read_text())
        self.assertEqual(summary["record_count"], 2)
        by_method = {record["method"]: record for record in summary["records"]}
        self.assertEqual(set(by_method), {"vn-retrain", "z3-pb"})
        for record in by_method.values():
            self.assertEqual(record["status"], "PASS")
            self.assertTrue(record["external_cec"]["equivalent"])
            self.assertTrue(record["command"][4].endswith(".bench"))
            cec_script = record["external_cec"]["command"][2]
            self.assertTrue(cec_script.endswith('bench"'))
            for key, relative in record["artifacts"].items():
                if relative is not None:
                    self.assertTrue((self.output / relative).is_file(), key)
                    self.assertIn(key, record["artifact_identities"])

        z3_record = by_method["z3-pb"]
        self.assertEqual(z3_record["parsed"]["rule_synth_summary_count"], 2)
        self.assertEqual(z3_record["parsed"]["rule_apply_summary_count"], 2)
        self.assertEqual(z3_record["parsed"]["rule_miter_summary_count"], 0)
        self.assertEqual(z3_record["parsed"]["rule_build_attempt_count"], 2)
        self.assertEqual(
            z3_record["parsed"]["rule_synth_aggregates"]["last"]["solver_status"],
            "optimal",
        )
        structure = z3_record["structural_metrics"]
        self.assertEqual(structure["golden"]["area"], 10)
        self.assertEqual(structure["trojan"]["area"], 14)
        self.assertEqual(structure["patched"]["area"], 11)
        self.assertEqual(structure["patch_minus_trojan"]["area_delta"], -3)
        self.assertEqual(structure["patch_minus_golden"]["level_delta"], 1)

        with (self.output / "results.csv").open(newline="", encoding="utf-8") as source:
            rows = {row["method"]: row for row in csv.DictReader(source)}
        self.assertEqual(rows["z3-pb"]["actual_area_delta_trojan"], "-3")
        self.assertEqual(rows["z3-pb"]["area_delta"], "-3")
        self.assertEqual(rows["z3-pb"]["reported_area_delta"], "999")
        self.assertEqual(rows["z3-pb"]["summary_last_solver_status"], "optimal")
        self.assertEqual(rows["z3-pb"]["summary_numeric_sum_synth_ms"], "10.0")
        self.assertEqual(rows["z3-pb"]["apply_last_source"], "literal_patch_cut")
        self.assertEqual(rows["z3-pb"]["apply_last_effective_literals"], "1")
        self.assertEqual(rows["z3-pb"]["rule_miter_summary_count"], "0")

        with mock.patch.dict(
            os.environ, {"FAKE_INVOCATION_COUNTER": str(self.counter)}, clear=False
        ):
            self.assertEqual(runner.main(self.args()), 0)
        self.assertEqual(len(self.counter.read_text(encoding="utf-8").splitlines()), 2)

    def test_external_cec_controls_success_even_when_main_returns_zero(self) -> None:
        with mock.patch.dict(os.environ, {"FAKE_ABC_MODE": "fail"}, clear=False):
            self.assertEqual(
                runner.main(self.args("--method", "vn-retrain")), 0
            )
        record = json.loads(
            (self.output / "records" / "case1--vn-retrain.json").read_text()
        )
        self.assertEqual(record["main"]["returncode"], 0)
        self.assertEqual(record["status"], "CEC_FAIL")
        self.assertFalse(record["success"])

    def test_formal_options_target_optimizer_methods_and_export_miter_data(self) -> None:
        formal_args = self.args(
            "--rule-formal-refine",
            "--rule-formal-timeout-ms", "0",
            "--rule-formal-max-rounds", "3",
            "--rule-formal-cex-batch", "4",
        )
        self.assertEqual(runner.main(formal_args), 0)

        vn_record = json.loads(
            (self.output / "records" / "case1--vn-retrain.json").read_text()
        )
        z3_record = json.loads(
            (self.output / "records" / "case1--z3-pb.json").read_text()
        )
        self.assertNotIn("--rule-formal-refine", vn_record["command"])
        self.assertIn("--rule-formal-refine", z3_record["command"])
        for option, value in (
            ("--rule-formal-timeout-ms", "0"),
            ("--rule-formal-max-rounds", "3"),
            ("--rule-formal-cex-batch", "4"),
        ):
            index = z3_record["command"].index(option)
            self.assertEqual(z3_record["command"][index + 1], value)

        parsed = z3_record["parsed"]
        self.assertEqual(parsed["rule_miter_summary_count"], 2)
        self.assertEqual(parsed["rule_build_attempt_count"], 2)
        self.assertEqual(
            parsed["rule_build_attempts"][1]["rule_miter_summaries"][0][
                "status"
            ],
            "proved",
        )
        self.assertEqual(
            parsed["rule_miter_aggregates"]["numeric_sum"]["total_ms"], 4.0
        )

        context = json.loads((self.output / "run_context.json").read_text())
        self.assertTrue(context["rule_formal_refine"])
        self.assertEqual(context["rule_formal_timeout_ms"], 0)
        summary = json.loads((self.output / "summary.json").read_text())
        self.assertEqual(summary["schema_version"], runner.SUMMARY_SCHEMA_VERSION)
        self.assertEqual(summary["invocation"]["rule_formal_cex_batch"], 4)
        with (self.output / "results.csv").open(
            newline="", encoding="utf-8"
        ) as source:
            rows = {row["method"]: row for row in csv.DictReader(source)}
        self.assertEqual(rows["z3-pb"]["miter_last_status"], "proved")
        self.assertEqual(rows["z3-pb"]["miter_numeric_sum_total_ms"], "4.0")
        self.assertEqual(rows["z3-pb"]["rule_miter_summary_count"], "2")
        linked = json.loads(rows["z3-pb"]["rule_build_attempts_json"])
        self.assertEqual(linked[0]["rule_build_attempt"], 1)

    def test_dac25_command_cache_artifacts_and_rectification_csv(self) -> None:
        self.assertEqual(
            runner.main(
                self.args(
                    "--method", "z3-pb",
                    "--method", "dac25-inspired",
                    "--rule-formal-refine",
                    "--rule-formal-timeout-ms", "7",
                    "--rule-formal-max-rounds", "2",
                    "--rule-formal-cex-batch", "3",
                    "--dac25-selector-timeout-ms", "11000",
                    "--dac25-candidate-limit", "40",
                    "--dac25-max-targets", "4",
                    "--dac25-max-sets", "9",
                    "--dac25-runeco-timeout-s", "22",
                    "--dac25-abc-bin", str(self.abc_path),
                )
            ),
            0,
        )

        z3_record = json.loads(
            (self.output / "records" / "case1--z3-pb.json").read_text()
        )
        dac_record = json.loads(
            (
                self.output
                / "records"
                / "case1--dac25-inspired.json"
            ).read_text()
        )
        self.assertNotEqual(z3_record["cache_key"], dac_record["cache_key"])
        self.assertIn("--rule-formal-refine", z3_record["command"])
        self.assertFalse(
            any(
                value.startswith("--rule-formal-")
                for value in dac_record["command"]
            )
        )
        self.assertEqual(
            dac_record["command"][
                dac_record["command"].index("--rule-method") + 1
            ],
            "z3-pb",
        )
        self.assertEqual(
            dac_record["command"][
                dac_record["command"].index("--repair-method") + 1
            ],
            "dac25-inspired",
        )
        for option, value in (
            ("--dac25-selector-timeout-ms", "11000"),
            ("--dac25-candidate-limit", "40"),
            ("--dac25-max-targets", "4"),
            ("--dac25-max-sets", "9"),
            ("--dac25-runeco-timeout-s", "22"),
            ("--dac25-abc-bin", str(self.abc_path.resolve())),
        ):
            index = dac_record["command"].index(option)
            self.assertEqual(dac_record["command"][index + 1], value)
            self.assertNotIn(option, z3_record["command"])

        self.assertEqual(dac_record["method"], "dac25-inspired")
        self.assertEqual(dac_record["parsed"]["rectification_summary_count"], 2)
        self.assertEqual(dac_record["parsed"]["rule_build_attempt_count"], 1)
        linked = dac_record["parsed"]["rule_build_attempts"][0]
        self.assertEqual(linked["rule_build_attempt"], 2)
        self.assertEqual(len(linked["rectification_summaries"]), 2)
        self.assertEqual(
            dac_record["parsed"]["rectification_aggregates"]["last"][
                "status"
            ],
            "success",
        )
        self.assertEqual(
            dac_record["parsed"]["rectification_selected_aggregates"]
            ["last"]["patch_ms"],
            31.0,
        )
        patched = self.output / dac_record["artifacts"]["patched_bench"]
        self.assertTrue(patched.is_file())
        self.assertIn("--dac25-inspired", patched.name)

        context = json.loads((self.output / "run_context.json").read_text())
        self.assertEqual(context["methods"], ["z3-pb", "dac25-inspired"])
        self.assertEqual(context["dac25_candidate_limit"], 40)
        dac25_abc_identity = dac_record["identities"]["tools"]["dac25_abc"]
        self.assertEqual(
            context["dac25_abc_sha256"], dac25_abc_identity["sha256"]
        )
        summary = json.loads((self.output / "summary.json").read_text())
        self.assertEqual(summary["invocation"]["dac25_max_sets"], 9)
        with (self.output / "results.csv").open(
            newline="", encoding="utf-8"
        ) as source:
            rows = {row["method"]: row for row in csv.DictReader(source)}
        dac_row = rows["dac25-inspired"]
        self.assertEqual(dac_row["rectification_summary_count"], "2")
        self.assertEqual(dac_row["rectification_last_status"], "success")
        self.assertEqual(dac_row["rectification_numeric_sum_selector_ms"], "4.2")
        self.assertNotIn("rectification_numeric_sum_patch_ms", dac_row)
        self.assertEqual(
            dac_row["rectification_selected_last_patch_ms"], "31.0"
        )
        self.assertEqual(
            dac_row["dac25_abc_sha256"], dac25_abc_identity["sha256"]
        )
        raw_rectification = json.loads(
            dac_row["rectification_summaries_json"]
        )
        self.assertEqual(len(raw_rectification), 2)
        self.assertEqual(raw_rectification[1]["selected"], 1)

    def test_dac25_filters_manifest_formal_flags_only_for_dac(self) -> None:
        common = (
            "--depth", "10", "--rule-formal-refine",
            "--rule-formal-timeout-ms", "8",
            "--rule-formal-max-rounds=2",
            "--rule-formal-cex-batch", "1",
        )
        self.assertEqual(
            runner._common_args_for_method(common, "z3-pb"), common
        )
        self.assertEqual(
            runner._common_args_for_method(common, "dac25-inspired"),
            ("--depth", "10"),
        )

    def test_dac25_options_require_dac25_method(self) -> None:
        self.assertEqual(
            runner.main(
                self.args(
                    "--method", "z3-pb", "--dac25-candidate-limit", "8"
                )
            ),
            2,
        )
        self.assertFalse(self.output.exists())

    def test_formal_knobs_require_refine_flag(self) -> None:
        self.assertEqual(
            runner.main(self.args("--rule-formal-timeout-ms", "10")), 2
        )
        self.assertFalse(self.output.exists())

    def test_external_cec_equivalence_marker_requires_zero_exit(self) -> None:
        with mock.patch.dict(
            os.environ, {"FAKE_ABC_MODE": "marker_nonzero"}, clear=False
        ):
            self.assertEqual(
                runner.main(self.args("--method", "vn-retrain")), 0
            )
        record = json.loads(
            (self.output / "records" / "case1--vn-retrain.json").read_text()
        )
        self.assertEqual(record["external_cec"]["returncode"], 7)
        self.assertEqual(record["status"], "ABC_ERROR")
        self.assertFalse(record["success"])

    def test_parallel_jobs_are_rejected_before_writes(self) -> None:
        self.assertEqual(runner.main(self.args("--jobs", "2")), 2)
        self.assertFalse(self.output.exists())

    def test_input_mutation_during_run_is_a_harness_error(self) -> None:
        trojan = self.root / "trojans" / "c1" / "trojan1.bench"
        with mock.patch.dict(
            os.environ, {"FAKE_MUTATE_INPUT": str(trojan)}, clear=False
        ):
            self.assertEqual(
                runner.main(self.args("--method", "vn-retrain")), 0
            )
        record = json.loads(
            (self.output / "records" / "case1--vn-retrain.json").read_text()
        )
        self.assertEqual(record["status"], "HARNESS_ERROR")
        self.assertIn("inputs.trojan", record["post_run_identity_changes"])
        self.assertFalse(record["success"])

    def test_timeout_is_recorded_and_does_not_run_cec(self) -> None:
        with mock.patch.dict(os.environ, {"FAKE_MAIN_SLEEP": "2"}, clear=False):
            self.assertEqual(
                runner.main(
                    self.args(
                        "--method", "vn-retrain", "--timeout", "0.15"
                    )
                ),
                0,
            )
        record = json.loads(
            (self.output / "records" / "case1--vn-retrain.json").read_text()
        )
        self.assertEqual(record["status"], "TIMEOUT")
        self.assertEqual(record["timeout_stage"], "main")
        self.assertIsNone(record["artifacts"]["cec_stdout"])

    def test_timeout_kills_child_in_a_separate_process_group(self) -> None:
        child_pid_path = self.root / "child.pid"
        with mock.patch.dict(
            os.environ,
            {
                "FAKE_MAIN_SLEEP": "2",
                "FAKE_CHILD_PID_PATH": str(child_pid_path),
            },
            clear=False,
        ):
            self.assertEqual(
                runner.main(
                    self.args(
                        "--method", "dac25-inspired", "--timeout", "0.15"
                    )
                ),
                0,
            )
        child_pid = int(child_pid_path.read_text(encoding="ascii"))
        deadline = time.monotonic() + 2.0
        while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(
            Path(f"/proc/{child_pid}").exists(),
            "outer timeout must not leave the runeco-style child alive",
        )

    def test_missing_nonnull_artifact_invalidates_resume(self) -> None:
        self.assertEqual(
            runner.main(self.args("--method", "vn-retrain")), 0
        )
        record_path = self.output / "records" / "case1--vn-retrain.json"
        record = json.loads(record_path.read_text())
        stdout_path = self.output / record["artifacts"]["stdout"]
        stdout_path.unlink()
        self.assertIsNone(
            runner._record_is_resumable(
                record_path, record["cache_key"], self.output
            )
        )

    def test_milp_cover_fingerprints_highs_library(self) -> None:
        with mock.patch.dict(
            os.environ,
            self.highs_environment(FAKE_INVOCATION_COUNTER=str(self.counter)),
            clear=False,
        ):
            self.assertEqual(
                runner.main(
                    self.args(
                        "--method", "milp-cover",
                        "--highs-library", str(self.highs_path),
                    )
                ),
                0,
            )

        self.assertEqual(
            self.counter.read_text(encoding="utf-8").splitlines(),
            ["milp-cover"],
        )
        record = json.loads(
            (self.output / "records" / "case1--milp-cover.json").read_text()
        )
        highs_identity = record["identities"]["tools"]["highs_library"]
        self.assertEqual(highs_identity["path"], str(self.highs_path.resolve()))
        self.assertEqual(record["post_run_identity_changes"], {})
        self.assertEqual(record["status"], "PASS")
        context = json.loads((self.output / "run_context.json").read_text())
        self.assertEqual(
            context["highs_library_sha256"], highs_identity["sha256"]
        )
        summary = json.loads((self.output / "summary.json").read_text())
        self.assertEqual(
            summary["invocation"]["highs_library"], str(self.highs_path)
        )
        with (self.output / "results.csv").open(
            newline="", encoding="utf-8"
        ) as source:
            row = next(csv.DictReader(source))
        self.assertEqual(row["method"], "milp-cover")
        self.assertEqual(row["highs_library_sha256"], highs_identity["sha256"])
        self.assertEqual(row["summary_last_cover_variables"], "7")

    def test_milp_cover_passes_p4_options_and_records_configuration(self) -> None:
        with mock.patch.dict(
            os.environ, self.highs_environment(), clear=False
        ):
            self.assertEqual(
                runner.main(
                    self.args(
                        "--method", "z3-pb",
                        "--method", "milp-cover",
                        "--highs-library", str(self.highs_path),
                        "--rule-cover-fourth-objective", "logic-risk",
                        "--rule-cover-logic-risk-unique-weight", "0.1",
                        "--rule-cover-logic-risk-fanout-weight", "0.2",
                        "--rule-cover-logic-risk-timing-weight", "0.7",
                        "--rule-cover-phase4-timeout-ms", "0",
                    )
                ),
                0,
            )

        z3_record = json.loads(
            (self.output / "records" / "case1--z3-pb.json").read_text()
        )
        milp_record = json.loads(
            (self.output / "records" / "case1--milp-cover.json").read_text()
        )
        self.assertNotIn("--rule-cover-fourth-objective", z3_record["command"])
        expected = (
            ("--rule-cover-fourth-objective", "logic-risk"),
            ("--rule-cover-logic-risk-unique-weight", "0.1"),
            ("--rule-cover-logic-risk-fanout-weight", "0.2"),
            ("--rule-cover-logic-risk-timing-weight", "0.7"),
            ("--rule-cover-phase4-timeout-ms", "0"),
        )
        for option, value in expected:
            index = milp_record["command"].index(option)
            self.assertEqual(milp_record["command"][index + 1], value)
        context = json.loads((self.output / "run_context.json").read_text())
        self.assertEqual(context["rule_cover_fourth_objective"], "logic-risk")
        self.assertEqual(
            context["rule_cover_logic_risk_weights"],
            {"unique": 0.1, "fanout": 0.2, "timing": 0.7},
        )
        self.assertEqual(context["rule_cover_phase4_timeout_ms"], 0)
        summary = json.loads((self.output / "summary.json").read_text())
        self.assertEqual(
            summary["invocation"]["rule_cover_fourth_objective"],
            "logic-risk",
        )

    def test_p4_options_require_milp_cover(self) -> None:
        self.assertEqual(
            runner.main(
                self.args("--rule-cover-fourth-objective", "logic-risk")
            ),
            2,
        )
        self.assertFalse(self.output.exists())

    def test_milp_cover_requires_highs_library_option(self) -> None:
        self.assertEqual(
            runner.main(self.args("--method", "milp-cover")), 2
        )
        self.assertFalse(self.output.exists())

    def test_milp_cover_rejects_missing_highs_library_file(self) -> None:
        missing = self.root / "lib" / "missing-libhighs.so"
        self.assertEqual(
            runner.main(
                self.args(
                    "--method", "milp-cover",
                    "--highs-library", str(missing),
                )
            ),
            2,
        )
        self.assertFalse(self.output.exists())

    def test_milp_cover_rejects_library_not_resolved_by_binary(self) -> None:
        other = self.root / "lib" / "libhighs-other.so.1"
        other.write_text("different fake highs library\n", encoding="utf-8")
        with mock.patch.dict(
            os.environ, self.highs_environment(), clear=False
        ):
            self.assertEqual(
                runner.main(
                    self.args(
                        "--method", "milp-cover",
                        "--highs-library", str(other),
                    )
                ),
                2,
            )
        self.assertFalse(self.output.exists())

    def test_highs_library_mutation_is_a_harness_error(self) -> None:
        with mock.patch.dict(
            os.environ,
            self.highs_environment(FAKE_MUTATE_HIGHS=str(self.highs_path)),
            clear=False,
        ):
            self.assertEqual(
                runner.main(
                    self.args(
                        "--method", "milp-cover",
                        "--highs-library", str(self.highs_path),
                    )
                ),
                0,
            )
        record = json.loads(
            (self.output / "records" / "case1--milp-cover.json").read_text()
        )
        self.assertEqual(record["status"], "HARNESS_ERROR")
        self.assertFalse(record["success"])
        self.assertIn(
            "tools.highs_library", record["post_run_identity_changes"]
        )


if __name__ == "__main__":
    unittest.main()
