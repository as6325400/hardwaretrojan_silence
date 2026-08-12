#!/usr/bin/env python3

import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
ANALYZER = REPO_ROOT / "scripts" / "analyze_dac25_vs_z3_formal.py"


class AnalyzerEndToEndTest(unittest.TestCase):
    def make_fake_abc(self, root: Path) -> tuple[Path, str]:
        abc = root / "fake_abc.py"
        abc.write_text(
            """#!/usr/bin/env python3
import sys
command = sys.argv[2]
if command.startswith('cec '):
    print('Networks are equivalent')
elif 'print_stats' in command:
    if 'z3.bench' in command:
        print('net : i/o = 2/1 and = 12 lev = 5')
    elif 'dac.bench' in command:
        print('net : i/o = 2/1 and = 10 lev = 4')
    elif 'trojan.bench' in command:
        print('net : i/o = 2/1 and = 11 lev = 5')
    else:
        print('net : i/o = 2/1 and = 9 lev = 3')
else:
    raise SystemExit(2)
""",
            encoding="utf-8",
        )
        abc.chmod(0o755)
        return abc, hashlib.sha256(abc.read_bytes()).hexdigest()

    def write_arm(
        self,
        root: Path,
        abc_sha: str,
        arm: str,
        method: str,
        status: str,
        runtime_ms: str,
        wall_ms: str,
    ) -> None:
        output_root = root / arm
        input_root = root / f"{arm}_inputs"
        golden = input_root / "golden.bench"
        trojan = input_root / "trojan.bench"
        patch = output_root / f"{arm}.bench"
        for path in (golden, trojan, patch):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("INPUT(a)\nOUTPUT(a)\n", encoding="utf-8")
        fields = [
            "case_id", "circuit", "trojan", "method", "status",
            "runtime_ms", "wall_ms", "abc_sha256", "patched_bench",
            "command_json",
        ]
        command = json.dumps(
            ["main", str(golden), str(trojan), "gt.json", "out.bench"]
        )
        with (output_root / "results.csv").open(
            "w", newline="", encoding="utf-8"
        ) as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerow(
                {
                    "case_id": "c1_t0", "circuit": "c1", "trojan": "t0",
                    "method": method, "status": status, "runtime_ms": runtime_ms,
                    "wall_ms": wall_ms, "abc_sha256": abc_sha,
                    "patched_bench": patch.name, "command_json": command,
                }
            )

    def run_analyzer(
        self, root: Path, abc: Path, cohort_label: str = "Tiny smoke"
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        output = root / "analysis"
        completed = subprocess.run(
            [
                sys.executable, str(ANALYZER),
                "--z3-results", str(root / "z3" / "results.csv"),
                "--z3-root", str(root / "z3"),
                "--dac-results", str(root / "dac" / "results.csv"),
                "--dac-root", str(root / "dac"),
                "--abc", str(abc), "--output-dir", str(output),
                "--workers", "2", "--require-cases", "1",
                "--cohort-label", cohort_label,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return completed, output

    def read_summary(self, output: Path) -> dict[str, str]:
        with (output / "dac25_vs_z3_formal_summary.csv").open(
            newline="", encoding="utf-8"
        ) as stream:
            return next(csv.DictReader(stream))

    def test_one_case_common_aig_and_cec_with_copied_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            abc, abc_sha = self.make_fake_abc(root)
            self.write_arm(root, abc_sha, "z3", "z3-pb", "PASS", "10", "12")
            self.write_arm(
                root, abc_sha, "dac", "dac25-inspired", "PASS", "10", "12"
            )

            completed, output = self.run_analyzer(root, abc)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = self.read_summary(output)
            self.assertEqual(summary["both_pass"], "1")
            self.assertEqual(summary["dac_node_wins"], "1")
            self.assertEqual(summary["dac_level_wins"], "1")
            self.assertEqual(summary["z3_cec_replayed"], "1")
            self.assertEqual(summary["dac_cec_replayed"], "1")
            self.assertEqual(summary["cohort_label"], "Tiny smoke")
            report = (output / "DAC25_VS_Z3_FORMAL_REPORT.md").read_text(
                encoding="utf-8"
            )
            self.assertIn("on 1 Golden/Trojan pairs (Tiny smoke)", report)
            self.assertNotIn("482 runnable V0", report)
            self.assertIn("DAC has 0 gains and 0 regressions", report)
            self.assertIn("Gains: none.", report)
            self.assertIn("Wilson intervals describe the observed cohort only", report)

    def test_missing_paired_runtime_is_reported_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            abc, abc_sha = self.make_fake_abc(root)
            self.write_arm(root, abc_sha, "z3", "z3-pb", "PASS", "", "12")
            self.write_arm(
                root, abc_sha, "dac", "dac25-inspired", "PASS", "", "15"
            )

            completed, output = self.run_analyzer(root, abc)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = self.read_summary(output)
            self.assertEqual(summary["both_pass"], "1")
            self.assertEqual(summary["paired_wall_samples"], "1")
            self.assertEqual(summary["paired_runtime_samples"], "0")
            self.assertEqual(summary["z3_over_dac_runtime_sum_ratio"], "")
            report = (output / "DAC25_VS_Z3_FORMAL_REPORT.md").read_text(
                encoding="utf-8"
            )
            self.assertIn("those runtime ratios are n/a", report)

    def test_zero_paired_pass_has_empty_optional_statistics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            abc, abc_sha = self.make_fake_abc(root)
            self.write_arm(
                root, abc_sha, "z3", "z3-pb", "CEC_FAIL", "10", "12"
            )
            self.write_arm(
                root, abc_sha, "dac", "dac25-inspired", "NO_PATCH", "", ""
            )

            completed, output = self.run_analyzer(root, abc)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = self.read_summary(output)
            self.assertEqual(summary["both_pass"], "0")
            self.assertEqual(summary["paired_wall_samples"], "0")
            self.assertEqual(summary["paired_runtime_samples"], "0")
            self.assertEqual(summary["z3_over_dac_wall_sum_ratio"], "")
            self.assertEqual(summary["z3_over_dac_aig_nodes_ratio"], "")
            self.assertEqual(summary["z3_delta_nodes_median"], "")
            report = (output / "DAC25_VS_Z3_FORMAL_REPORT.md").read_text(
                encoding="utf-8"
            )
            self.assertIn("wall-time ratios are n/a", report)
            self.assertIn("aggregate patched-node ratio Z3/DAC is n/a", report)


if __name__ == "__main__":
    unittest.main()
