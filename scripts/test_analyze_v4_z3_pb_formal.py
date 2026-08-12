#!/usr/bin/env python3
"""Regression tests for the paired V4 formal analyzer."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import analyze_v4_z3_pb_formal as analyzer


class V4FormalAnalyzerTest(unittest.TestCase):
    def test_pairing_and_aggregate(self) -> None:
        manifest = {
            "a": {
                "circuit": "c880",
                "v4": {
                    "phase_id": "core_final", "split": "final",
                    "size_class": "small", "trojan_count": 2,
                    "trigger_size": 3, "trigger_topology": "disjoint",
                    "positive_pattern_count": 16,
                },
            },
            "b": {
                "circuit": "c880",
                "v4": {
                    "phase_id": "core_final", "split": "final",
                    "size_class": "small", "trojan_count": 3,
                    "trigger_size": 5, "trigger_topology": "disjoint",
                    "positive_pattern_count": 32,
                },
            },
        }
        common = {"method": "z3-pb", "binary_sha256": "bin", "abc_sha256": "abc"}
        off_command = json.dumps(["main", "--rule-method", "z3-pb"])
        on_command = json.dumps(
            [
                "main", "--rule-method", "z3-pb", "--rule-formal-refine",
                "--rule-formal-timeout-ms", "10000",
                "--rule-formal-max-rounds", "5",
                "--rule-formal-cex-batch", "5",
            ]
        )
        off = {
            "a": {**common, "command_json": off_command, "status": "CEC_FAIL", "success": "False", "wall_ms": "10"},
            "b": {**common, "command_json": off_command, "status": "PASS", "success": "True", "wall_ms": "20"},
        }
        on = {
            "a": {
                **common, "command_json": on_command,
                "status": "PASS", "success": "True", "wall_ms": "15",
                "miter_numeric_sum_added": "5", "miter_numeric_sum_returned_fn": "2",
                "miter_numeric_sum_returned_fp": "3",
            },
            "b": {**common, "command_json": on_command, "status": "PASS", "success": "True", "wall_ms": "25"},
        }
        pairs = analyzer.build_pairs(manifest, off, on)
        aggregate = analyzer._aggregate(pairs)
        self.assertEqual(aggregate["off_pass"], 1)
        self.assertEqual(aggregate["on_pass"], 2)
        self.assertEqual(aggregate["gains"], 1)
        self.assertEqual(aggregate["regressions"], 0)
        self.assertEqual(aggregate["on_formal_counterexamples_added"], 5)
        self.assertEqual(pairs[0]["transition"], "CEC_FAIL->PASS")

    def test_identity_mismatch_is_rejected(self) -> None:
        metadata = {
            "x": {
                "circuit": "c880",
                "v4": {
                    "phase_id": "core", "split": "final", "size_class": "small",
                    "trojan_count": 1, "trigger_size": 3,
                    "trigger_topology": "disjoint", "positive_pattern_count": 1,
                },
            }
        }
        off = {"x": {"binary_sha256": "a", "abc_sha256": "z", "success": "True", "command_json": '["main"]'}}
        on = {"x": {"binary_sha256": "b", "abc_sha256": "z", "success": "True", "command_json": '["main","--rule-formal-refine","--rule-formal-timeout-ms","1","--rule-formal-max-rounds","1","--rule-formal-cex-batch","1"]'}}
        with self.assertRaisesRegex(RuntimeError, "binary_sha256 mismatch"):
            analyzer.build_pairs(metadata, off, on)

    def test_run_context_treatment_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            results = root / "results.csv"
            results.write_text("case_id\n", encoding="utf-8")
            context = {
                "manifest_sha256": "manifest",
                "methods": ["z3-pb"],
                "rule_formal_refine": True,
                "rule_formal_timeout_ms": 10000,
                "rule_formal_max_rounds": 5,
                "rule_formal_cex_batch": 5,
                "context_key": "key",
            }
            (root / "run_context.json").write_text(
                json.dumps(context), encoding="utf-8"
            )
            loaded = analyzer._load_and_validate_contexts(
                [results], expected_enabled=True, manifest_sha256="manifest"
            )
            self.assertEqual(loaded[0]["context_key"], "key")
            with self.assertRaisesRegex(RuntimeError, "unexpected formal setting"):
                analyzer._load_and_validate_contexts(
                    [results], expected_enabled=False, manifest_sha256="manifest"
                )


if __name__ == "__main__":
    unittest.main()
