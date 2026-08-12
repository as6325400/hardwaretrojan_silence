#!/usr/bin/env python3
"""Regression tests for the exact V4 multi-head analyzer."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from typing import Any, Dict, Iterable, List, Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import analyze_v4_multi_head as analyzer


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_csv(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    materialized = [dict(row) for row in rows]
    fields: List[str] = []
    for row in materialized:
        for key in row:
            if key not in fields:
                fields.append(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(materialized)


class AnalyzerFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.manifest = root / "manifest.json"
        self.scalar_a = root / "scalar_a" / "results.csv"
        self.scalar_b = root / "scalar_b" / "results.csv"
        self.multi_root = root / "multi"
        self.output = root / "report"
        self.case_ids = [f"case_{index:02d}" for index in range(13)]
        self.common_args = [
            "--depth", "10", "--neg-ratio", "50",
            "--mine-rounds", "15", "--mine-max", "5000",
        ]
        self.runner_scalar = "1" * 64
        self.runner_multi = "2" * 64
        self.binary_scalar = "3" * 64
        self.binary_multi = "4" * 64
        self.abc = "5" * 64
        self.show = "6" * 64
        self.cases: List[Dict[str, Any]] = []
        self.scalar_rows: List[Dict[str, str]] = []
        self.multi_rows: List[Dict[str, str]] = []
        self.multi_records: List[Dict[str, Any]] = []
        self._prepare()

    def _context(self, profile: str, *, multi_head: bool) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "runner_schema": (
                "rule-method-ab-run/4" if multi_head else "rule-method-ab-run/3"
            ),
            "runner_sha256": self.runner_multi if multi_head else self.runner_scalar,
            "manifest_sha256": "pending",
            "profile": profile,
            "methods": ["z3-pb"],
            "binary_sha256": self.binary_multi if multi_head else self.binary_scalar,
            "abc_sha256": self.abc,
            "show_sha256": self.show,
            "highs_library_sha256": None,
            "common_args": self.common_args,
            "timeout_override": 300.0,
            "abc_timeout": 60.0,
            "rule_cover_fourth_objective": None,
            "rule_cover_logic_risk_weights": {
                "unique": None, "fanout": None, "timing": None,
            },
            "rule_cover_phase4_timeout_ms": None,
            "rule_formal_refine": True,
            "rule_formal_timeout_ms": 10000,
            "rule_formal_max_rounds": 5,
            "rule_formal_cex_batch": 5,
        }
        if multi_head:
            payload["rule_multi_head"] = True
            payload["rule_multi_head_max_rounds"] = 20
        return payload

    @staticmethod
    def _finish_context(payload: Dict[str, Any], manifest_sha: str) -> Dict[str, Any]:
        payload = dict(payload)
        payload["manifest_sha256"] = manifest_sha
        payload["context_key"] = analyzer._context_key(payload)
        return payload

    def _prepare(self) -> None:
        input_root = self.root / "inputs"
        for index, case_id in enumerate(self.case_ids):
            golden = input_root / "golden" / f"g{index}.bench"
            trojan = input_root / "trojan" / f"t{index}.bench"
            groundtruth = input_root / "groundtruth" / f"e{index}.json"
            for path, content in (
                (golden, f"golden-{index}\n"),
                (trojan, f"trojan-{index}\n"),
                (groundtruth, json.dumps({"case": index}) + "\n"),
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            self.cases.append(
                {
                    "case_id": case_id,
                    "circuit": f"c{index}",
                    "cohort": "synthetic",
                    "trojan": case_id,
                    "v4": {
                        "phase_id": "core_final",
                        "split": "final_in_distribution",
                        "size_class": "small",
                        "trojan_count": 2,
                        "trigger_size": 3,
                        "trigger_topology": "disjoint",
                        "positive_pattern_count": 16,
                        "source_golden_sha256": _sha(golden),
                        "source_combined_sha256": _sha(trojan),
                        "source_combined_size_bytes": trojan.stat().st_size,
                        "source_groundtruth_sha256": _sha(groundtruth),
                        "source_groundtruth_size_bytes": groundtruth.stat().st_size,
                    },
                }
            )
        manifest_payload = {
            "common_args": self.common_args,
            "profiles": {
                "smoke_extended": self.case_ids,
                "baseline_a": self.case_ids[:7],
                "baseline_b": self.case_ids[7:],
            },
            "cases": self.cases,
        }
        self.manifest.write_text(
            json.dumps(manifest_payload, sort_keys=True), encoding="utf-8"
        )
        manifest_sha = _sha(self.manifest)
        scalar_a_context = self._finish_context(
            self._context("baseline_a", multi_head=False), manifest_sha
        )
        scalar_b_context = self._finish_context(
            self._context("baseline_b", multi_head=False), manifest_sha
        )
        multi_context = self._finish_context(
            self._context("smoke_extended", multi_head=True), manifest_sha
        )
        for path, context in (
            (self.scalar_a.parent / "run_context.json", scalar_a_context),
            (self.scalar_b.parent / "run_context.json", scalar_b_context),
            (self.multi_root / "run_context.json", multi_context),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(context, sort_keys=True), encoding="utf-8")

        for index, case in enumerate(self.cases):
            case_id = case["case_id"]
            golden = input_root / "golden" / f"g{index}.bench"
            trojan = input_root / "trojan" / f"t{index}.bench"
            groundtruth = input_root / "groundtruth" / f"e{index}.json"
            scalar_status = "PASS" if index == 1 else (
                "CEC_FAIL" if index == 0 else "NO_PATCH"
            )
            multi_status = "PASS" if index in (0, 1) else "CEC_FAIL"
            scalar_command = [
                "/frozen/scalar", str(golden), str(trojan), str(groundtruth),
                f"/patched/scalar-{case_id}.bench", *self.common_args,
                "--rule-method", "z3-pb", "--rule-formal-refine",
                "--rule-formal-timeout-ms", "10000",
                "--rule-formal-max-rounds", "5",
                "--rule-formal-cex-batch", "5",
            ]
            multi_command = [
                "/frozen/multi", str(golden), str(trojan), str(groundtruth),
                f"/patched/multi-{case_id}.bench", *self.common_args,
                "--rule-method", "z3-pb", "--rule-formal-refine",
                "--rule-formal-timeout-ms", "10000",
                "--rule-formal-max-rounds", "5",
                "--rule-formal-cex-batch", "5", "--rule-multi-head",
                "--rule-multi-head-max-rounds", "20",
            ]
            self.scalar_rows.append(
                self._row(
                    case_id, "baseline_a" if index < 7 else "baseline_b",
                    scalar_status, scalar_command, multi_head=False, index=index,
                )
            )
            multi_row = self._row(
                case_id, "smoke_extended", multi_status, multi_command,
                multi_head=True, index=index,
            )
            self.multi_rows.append(multi_row)
            self.multi_records.append(
                {
                    "schema_version": "rule-method-ab-run/4",
                    "case": {"case_id": case_id},
                    "method": "z3-pb",
                    "profile": "smoke_extended",
                    "status": multi_status,
                    "success": multi_status == "PASS",
                    "cache_key": multi_row["cache_key"],
                    "command": multi_command,
                    "external_cec": {
                        "equivalent": True if multi_status == "PASS" else False,
                        "returncode": 0,
                        "timed_out": False,
                    },
                    "identities": {
                        "tools": {
                            "binary": {"sha256": self.binary_multi},
                            "abc": {"sha256": self.abc},
                            "show": {"sha256": self.show},
                            "runner": {"sha256": self.runner_multi},
                        },
                        "inputs": {
                            "golden": {"path": str(golden), "sha256": _sha(golden)},
                            "trojan": {"path": str(trojan), "sha256": _sha(trojan)},
                            "groundtruth": {
                                "path": str(groundtruth), "sha256": _sha(groundtruth),
                            },
                        },
                    },
                }
            )
        self.write_results()

    def _row(
        self, case_id: str, profile: str, status: str, command: List[str],
        *, multi_head: bool, index: int,
    ) -> Dict[str, str]:
        passed = status == "PASS"
        row = {
            "case_id": case_id,
            "method": "z3-pb",
            "profile": profile,
            "status": status,
            "success": str(passed),
            "abc_equivalent": str(passed) if status in ("PASS", "CEC_FAIL") else "",
            "gt_verify": "PASS" if passed else "FAIL",
            "timeout_stage": "",
            "wall_ms": str(100 + index + (50 if multi_head else 0)),
            "runtime_ms": str(90 + index + (50 if multi_head else 0)),
            "main_wall_ms": str(95 + index + (50 if multi_head else 0)),
            "cec_wall_ms": "5" if status in ("PASS", "CEC_FAIL") else "",
            "cec_rounds": "1" if multi_head else "0",
            "golden_area": "100",
            "golden_level": "10",
            "trojan_area": "110",
            "trojan_level": "11",
            "patched_area": "113" if passed or multi_head else "",
            "patched_level": "12" if passed or multi_head else "",
            "actual_area_delta_trojan": "3" if passed or multi_head else "",
            "actual_level_delta_trojan": "1" if passed or multi_head else "",
            "binary_sha256": self.binary_multi if multi_head else self.binary_scalar,
            "abc_sha256": self.abc,
            "cache_key": f"cache-{case_id}-{'multi' if multi_head else 'scalar'}",
            "cec_stdout_log": f"{case_id}.cec.out" if passed else "",
            "cec_stderr_log": f"{case_id}.cec.err" if passed else "",
            "patched_bench": f"{case_id}.bench" if passed else "",
            "command_json": json.dumps(command, separators=(",", ":")),
        }
        if multi_head:
            discovery = [{"heads": 2, "candidates": 10, "candidate_source": "all_physical_gates"}]
            rules = [
                {
                    "head": 0, "pass": 1, "miter_status": "counterexamples",
                    "proved": 0, "returned": 1, "added": 1, "global_added": 1,
                    "checks": 2, "miter_ms": 3.0, "optimizer_ms": 1.0,
                    "total_ms": 5.0,
                },
                {
                    "head": 0, "pass": 2, "miter_status": "proved",
                    "proved": 1, "returned": 0, "added": 0, "global_added": 0,
                    "checks": 2, "miter_ms": 3.0, "optimizer_ms": 1.0,
                    "total_ms": 5.0,
                },
                {
                    "head": 1, "pass": 1, "miter_status": "proved",
                    "proved": 1, "returned": 0, "added": 0, "global_added": 0,
                    "checks": 2, "miter_ms": 3.0, "optimizer_ms": 1.0,
                    "total_ms": 5.0,
                },
            ]
            patches = [{"heads": 2, "proved_heads": 2}]
            feedback = [{"round": 1, "labels_added": 2, "corpus_added": 1, "new_heads": 1}]
            for prefix, values in (
                ("multi_head_discovery", discovery),
                ("multi_head_rule", rules),
                ("multi_head_patch", patches),
                ("multi_head_cec_feedback", feedback),
            ):
                row[f"{prefix}_summary_count"] = str(len(values))
                row[f"{prefix}_summaries_json"] = json.dumps(values)
        return row

    def write_results(self) -> None:
        _write_csv(self.scalar_a, self.scalar_rows[:7])
        _write_csv(self.scalar_b, self.scalar_rows[7:])
        _write_csv(self.multi_root / "results.csv", self.multi_rows)
        multi_context = json.loads(
            (self.multi_root / "run_context.json").read_text(encoding="utf-8")
        )
        invocation_keys = (
            "context_key", "manifest_sha256", "profile", "methods",
            "rule_formal_refine", "rule_formal_timeout_ms",
            "rule_formal_max_rounds", "rule_formal_cex_batch",
            "rule_multi_head", "rule_multi_head_max_rounds",
        )
        summary = {
            "schema_version": "rule-method-ab-summary/4",
            "record_count": len(self.multi_records),
            "records": self.multi_records,
            "invocation": {key: multi_context[key] for key in invocation_keys},
        }
        (self.multi_root / "summary.json").write_text(
            json.dumps(summary), encoding="utf-8"
        )

    def analyze(self) -> Dict[str, Any]:
        return analyzer.analyze(
            manifest=self.manifest,
            baseline_results=[self.scalar_a, self.scalar_b],
            multi_head_root=self.multi_root,
            output_dir=self.output,
        )


class V4MultiHeadAnalyzerTest(unittest.TestCase):
    def test_exact_comparison_uses_external_cec_and_emits_reports(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = AnalyzerFixture(Path(raw))
            summary = fixture.analyze()
            aggregate = summary["aggregate"]
            self.assertEqual(aggregate["case_count"], 13)
            self.assertEqual(aggregate["scalar_pass"], 1)
            self.assertEqual(aggregate["multi_head_pass"], 2)
            self.assertEqual(aggregate["gains"], 1)
            self.assertEqual(aggregate["regressions"], 0)
            telemetry = aggregate["multi_head_telemetry"]
            self.assertEqual(
                telemetry["scoped_formal_refinement_rebuild_events"], 13
            )
            self.assertEqual(telemetry["formal_global_cex_added"], 13)
            self.assertEqual(summary["correctness_authority"], "external ABC CEC")
            for name in ("paired_results.csv", "summary.json", "REPORT.md", "SHA256SUMS"):
                self.assertTrue((fixture.output / name).is_file())
            report = (fixture.output / "REPORT.md").read_text(encoding="utf-8")
            self.assertIn("Scalar Z3-PB + formal: **1/13 PASS**", report)
            self.assertIn("Multi-head Z3-PB + formal: **2/13 PASS**", report)

    def test_incomplete_multi_head_raw_fails_without_writing_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = AnalyzerFixture(Path(raw))
            fixture.multi_rows.pop()
            fixture.multi_records.pop()
            fixture.write_results()
            with self.assertRaisesRegex(
                analyzer.IncompleteRunError, "multi-head raw is incomplete"
            ):
                fixture.analyze()
            self.assertFalse(fixture.output.exists())

    def test_missing_multi_head_summary_is_an_explicit_incomplete_run(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = AnalyzerFixture(Path(raw))
            (fixture.multi_root / "summary.json").unlink()
            with self.assertRaisesRegex(
                analyzer.IncompleteRunError, "multi-head raw is incomplete"
            ):
                fixture.analyze()
            self.assertFalse(fixture.output.exists())

    def test_pass_without_external_abc_equivalence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = AnalyzerFixture(Path(raw))
            fixture.multi_rows[0]["abc_equivalent"] = "False"
            fixture.write_results()
            with self.assertRaisesRegex(RuntimeError, "external ABC CEC"):
                fixture.analyze()
            self.assertFalse(fixture.output.exists())

    def test_changed_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = AnalyzerFixture(Path(raw))
            command = json.loads(fixture.multi_rows[0]["command_json"])
            Path(command[2]).write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "input SHA mismatch"):
                fixture.analyze()
            self.assertFalse(fixture.output.exists())


if __name__ == "__main__":
    unittest.main()
