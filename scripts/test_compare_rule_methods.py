#!/usr/bin/env python3
"""Regression tests for the rule-method A/B runner."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import compare_rule_methods as runner


FAKE_MAIN = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
import time

if "--help" in sys.argv:
    print("Usage: fake <g> <t> <gt> <out> [--rule-method vn-retrain|dt|z3-pb]")
    raise SystemExit(0)

expected_abc = os.environ.get("FAKE_EXPECT_ABC_BIN")
if expected_abc and os.environ.get("ABC_BIN") != expected_abc:
    print("ABC_BIN was not pinned to the runner's --abc", file=sys.stderr)
    raise SystemExit(3)

method = sys.argv[sys.argv.index("--rule-method") + 1]
counter = os.environ.get("FAKE_INVOCATION_COUNTER")
if counter:
    with Path(counter).open("a", encoding="utf-8") as sink:
        sink.write(method + "\n")
if os.environ.get("FAKE_MAIN_SLEEP"):
    time.sleep(float(os.environ["FAKE_MAIN_SLEEP"]))
if os.environ.get("FAKE_MUTATE_INPUT"):
    with Path(os.environ["FAKE_MUTATE_INPUT"]).open("a", encoding="utf-8") as sink:
        sink.write("# mutated during run\n")

Path(sys.argv[4]).write_text(
    "INPUT(a)\nOUTPUT(n1)\nn1 = BUF(a)\n# " + method + "\n",
    encoding="utf-8",
)
if method == "z3-pb":
    print("rule_synth_summary strategy z3-pb cec_attempt 1 synth_pass 1 "
          "dt_builds 1 candidate_count 17 solver_status optimal "
          "pb_variables 13 final_rules 2 final_literals 3 final_depth 2 synth_ms 4.5")
    print("rule_synth_summary strategy z3-pb cec_attempt 2 synth_pass 1 "
          "dt_builds 2 candidate_count 19 solver_status optimal "
          "pb_variables 15 final_rules 1 final_literals 2 final_depth 1 synth_ms 5.5")
    print("rule_apply_summary strategy z3-pb cec_attempt 1 synth_pass 1 "
          "source signature_minimize rule_model_used 1 effective_rules 2 "
          "effective_literals 3 effective_depth 2")
    print("rule_apply_summary strategy z3-pb cec_attempt 2 synth_pass 1 "
          "source literal_patch_cut rule_model_used 0 effective_rules 1 "
          "effective_literals 1 effective_depth 1")
else:
    print("rule_synth_summary strategy vn-retrain cec_attempt 1 synth_pass 1 "
          "dt_builds 3 vn_generated 4 vn_used 1 final_rules 2 "
          "final_literals 4 final_depth 3 synth_ms 12.5")
    print("rule_apply_summary strategy vn-retrain cec_attempt 1 synth_pass 1 "
          "source signature_minimize rule_model_used 1 effective_rules 2 "
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


class SummaryParserTest(unittest.TestCase):
    def test_preserves_generic_and_strategy_specific_keys(self) -> None:
        stdout = (
            "noise\n"
            "rule_synth_summary strategy z3-pb cec_attempt 1 "
            "solver_status optimal pb_variables 31 synth_ms 1.25\n"
            "rule_synth_summary strategy z3-pb cec_attempt 2 "
            "solver_status optimal pb_variables 29 synth_ms 2.75\n"
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


if __name__ == "__main__":
    unittest.main()
