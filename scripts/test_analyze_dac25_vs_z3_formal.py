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
    def test_one_case_common_aig_and_cec(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
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
            abc_sha = hashlib.sha256(abc.read_bytes()).hexdigest()
            golden = root / "golden.bench"
            trojan = root / "trojan.bench"
            z3_patch = root / "z3" / "z3.bench"
            dac_patch = root / "dac" / "dac.bench"
            for path in (golden, trojan, z3_patch, dac_patch):
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
            for method, output_root, patch in (
                ("z3-pb", root / "z3", z3_patch),
                ("dac25-inspired", root / "dac", dac_patch),
            ):
                results = output_root / "results.csv"
                with results.open("w", newline="", encoding="utf-8") as stream:
                    writer = csv.DictWriter(stream, fieldnames=fields)
                    writer.writeheader()
                    writer.writerow(
                        {
                            "case_id": "c1_t0", "circuit": "c1", "trojan": "t0",
                            "method": method, "status": "PASS", "runtime_ms": "10",
                            "wall_ms": "12", "abc_sha256": abc_sha,
                            "patched_bench": patch.name, "command_json": command,
                        }
                    )

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
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with (output / "dac25_vs_z3_formal_summary.csv").open(
                newline="", encoding="utf-8"
            ) as stream:
                summary = next(csv.DictReader(stream))
            self.assertEqual(summary["both_pass"], "1")
            self.assertEqual(summary["dac_node_wins"], "1")
            self.assertEqual(summary["dac_level_wins"], "1")
            self.assertEqual(summary["z3_cec_replayed"], "1")
            self.assertEqual(summary["dac_cec_replayed"], "1")


if __name__ == "__main__":
    unittest.main()
