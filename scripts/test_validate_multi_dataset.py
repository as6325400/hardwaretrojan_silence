#!/usr/bin/env python3
"""Focused regression tests for validate_multi_dataset.py."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import validate_multi_dataset as validator


BENCH = """INPUT(a)
INPUT(b)
INPUT(c)
INPUT(d)
INPUT(e)
INPUT(f)
OUTPUT(y)
n1 = AND(a,b)
n2 = OR(c,d)
y = XOR(n1,n2)
"""


class DatasetValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.case_dir = self.root / "c880" / "c880_k2_t3_s1000"
        (self.case_dir / "individual").mkdir(parents=True)
        for relative in (
            "golden.bench",
            "combined.bench",
            "individual/HT0.bench",
            "individual/HT1.bench",
        ):
            (self.case_dir / relative).write_text(BENCH, encoding="utf-8")

        file_table = {}
        for relative in (
            "golden.bench",
            "combined.bench",
            "individual/HT0.bench",
            "individual/HT1.bench",
        ):
            path = self.case_dir / relative
            file_table[relative] = {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size_bytes": path.stat().st_size,
            }

        literals_0 = [
            {"net": "a", "required_value": 1},
            {"net": "b", "required_value": 1},
            {"net": "c", "required_value": 1},
        ]
        literals_1 = [
            {"net": "d", "required_value": 1},
            {"net": "e", "required_value": 1},
            {"net": "f", "required_value": 1},
        ]
        self.manifest = {
            "schema_version": validator.CASE_SCHEMA,
            "case_id": "c880_k2_t3_s1000",
            "benchmark": "c880",
            "golden_path": "golden.bench",
            "combined_path": "combined.bench",
            "interfaces": {
                "primary_inputs": ["a", "b", "c", "d", "e", "f"],
                "primary_outputs": ["y"],
            },
            "generation": {
                "seed": 1000,
                "trigger_size": 3,
                "trojan_count": 2,
                "topology": "disjoint",
                "payload_placement": {
                    "requested": "random",
                    "actual_strategy": "same_topological_depth_antichain",
                    "fallback_used": False,
                    "fallback_reason": None,
                },
            },
            "files": file_table,
            "instances": [
                {
                    "instance_id": "HT0",
                    "individual_path": "individual/HT0.bench",
                    "victim_net": "n1",
                    "trigger": {"gate": "AND", "trigger_net": "t0", "literals": literals_0},
                    "payload": {"type": "XOR_TOGGLE", "source_net": "n1", "result_net": "p0"},
                },
                {
                    "instance_id": "HT1",
                    "individual_path": "individual/HT1.bench",
                    "victim_net": "n2",
                    "trigger": {"gate": "AND", "trigger_net": "t1", "literals": literals_1},
                    "payload": {"type": "XOR_TOGGLE", "source_net": "n2", "result_net": "p1"},
                },
            ],
            "trigger_witnesses": {
                "mask_encoding": "left-to-right follows instances[]",
                "partial_pi_assignments": {
                    "00": {"a": 0, "b": 1, "c": 1, "d": 0, "e": 1, "f": 1},
                    "01": {"a": 0, "b": 1, "c": 1, "d": 1, "e": 1, "f": 1},
                    "10": {"a": 1, "b": 1, "c": 1, "d": 0, "e": 1, "f": 1},
                    "11": {"a": 1, "b": 1, "c": 1, "d": 1, "e": 1, "f": 1},
                },
            },
        }
        self.groundtruth = {
            "schema_version": validator.GT_SCHEMA,
            "case_id": "c880_k2_t3_s1000",
            "benchmark": "c880",
            "complete": True,
            "origin_path": "golden.bench",
            "trojan_path": "combined.bench",
            "origin_sha256": file_table["golden.bench"]["sha256"],
            "trojan_sha256": file_table["combined.bench"]["sha256"],
            "pi_order": ["a", "b", "c", "d", "e", "f"],
            "po_order": ["y"],
            "instance_order": ["HT0", "HT1"],
            "solver": {"witnesses_per_mask": 1},
            "patterns": [
                {
                    "pattern_bits": "111011",
                    "activation_mask": "10",
                    "activation_mask_value": 2,
                    "active_instances": ["HT0"],
                    "mismatched_outputs": ["y"],
                    "output": "y",
                    "sample_class": "singleton",
                    "requested_mask": "10",
                },
                {
                    "pattern_bits": "011111",
                    "activation_mask": "01",
                    "activation_mask_value": 1,
                    "active_instances": ["HT1"],
                    "mismatched_outputs": ["y"],
                    "output": "y",
                    "sample_class": "singleton",
                    "requested_mask": "01",
                },
                {
                    "pattern_bits": "111111",
                    "activation_mask": "11",
                    "activation_mask_value": 3,
                    "active_instances": ["HT0", "HT1"],
                    "mismatched_outputs": ["y"],
                    "output": "y",
                    "sample_class": "pair",
                    "requested_mask": "11",
                },
            ],
            "pattern_count": 3,
            "mask_results": [
                {"requested_mask": "10", "status": "sat", "requested_witnesses": 1, "witness_count": 1},
                {"requested_mask": "01", "status": "sat", "requested_witnesses": 1, "witness_count": 1},
                {"requested_mask": "11", "status": "sat", "requested_witnesses": 1, "witness_count": 1},
            ],
            "trigger_consistency": [
                {"instance_id": "HT0", "status": "equivalent"},
                {"instance_id": "HT1", "status": "equivalent"},
            ],
        }
        self.negatives = {
            "schema_version": validator.NEGATIVE_SCHEMA,
            "case_id": "c880_k2_t3_s1000",
            "benchmark": "c880",
            "origin_path": "golden.bench",
            "trojan_path": "combined.bench",
            "origin_sha256": file_table["golden.bench"]["sha256"],
            "trojan_sha256": file_table["combined.bench"]["sha256"],
            "pi_order": ["a", "b", "c", "d", "e", "f"],
            "instance_order": ["HT0", "HT1"],
            "patterns": [
                {
                    "pattern_bits": "011011",
                    "activation_mask": "00",
                    "activation_mask_value": 0,
                    "active_instances": [],
                    "mismatched_outputs": [],
                    "sample_class": "near_miss",
                    "requested_mask": "00",
                    "near_instance": "HT0",
                    "flipped_literal": {"net": "a", "required_value": 1},
                    "simulated_equal": True,
                    "label": 0,
                }
            ],
            "pattern_count": 1,
            "generation": {
                "requested": 1,
                "generated": 1,
                "complete": True,
                "conditions": ["all_triggers_off", "po_equal", "one_literal_near_miss"],
            },
        }
        self._write_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_fixture(self) -> None:
        (self.case_dir / "case_manifest.json").write_text(
            json.dumps(self.manifest), encoding="utf-8"
        )
        (self.case_dir / "groundtruth.json").write_text(
            json.dumps(self.groundtruth), encoding="utf-8"
        )
        (self.case_dir / "negative_patterns.json").write_text(
            json.dumps(self.negatives), encoding="utf-8"
        )

    def _run(self) -> tuple[int, dict]:
        summary_path = self.root / "summary.json"
        result = validator.main(
            [
                "--dataset-root",
                str(self.root),
                "--summary-json",
                str(summary_path),
                "--strict",
            ]
        )
        return result, json.loads(summary_path.read_text(encoding="utf-8"))

    def _matrix(self) -> dict:
        bench_path = self.case_dir / "golden.bench"
        return {
            "benchmark_catalog": {
                "c880": {
                    "path": str(bench_path.relative_to(self.root)),
                    "sha256": hashlib.sha256(bench_path.read_bytes()).hexdigest(),
                    "primary_inputs": 6,
                    "primary_outputs": 1,
                    "gate_assignments": 3,
                }
            },
            "defaults": {"victim_placement": "random"},
            "groundtruth_profiles": {
                "fixture": {
                    "witnesses_per_requested_mask": 1,
                    "hard_negatives_per_case": 1,
                }
            },
            "phases": [
                {
                    "id": "fixture_phase",
                    "enabled": True,
                    "split": "development",
                    "groundtruth_profile": "fixture",
                    "victim_placement": "random",
                    "circuits": ["c880"],
                    "trojan_counts": [2],
                    "trigger_sizes": [3],
                    "trigger_topologies": ["disjoint"],
                    "seeds": [1000],
                    "expected_case_count": 1,
                }
            ],
        }

    def _run_profile(self, matrix: dict) -> tuple[int, dict, Path, Path]:
        matrix_path = self.root / "matrix.json"
        summary_path = self.root / "profile_summary.json"
        ready_path = self.root / "ready.jsonl"
        rejected_path = self.root / "rejected.jsonl"
        matrix_path.write_text(json.dumps(matrix), encoding="utf-8")
        result = validator.main(
            [
                "--dataset-root", str(self.root),
                "--matrix", str(matrix_path),
                "--repo-root", str(self.root),
                "--strict",
                "--require-complete-matrix",
                "--ready-index", str(ready_path),
                "--rejected-index", str(rejected_path),
                "--summary-json", str(summary_path),
            ]
        )
        return (
            result,
            json.loads(summary_path.read_text(encoding="utf-8")),
            ready_path,
            rejected_path,
        )

    def test_valid_case_passes(self) -> None:
        result, summary = self._run()
        self.assertEqual(result, 0)
        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(summary["counts"]["cases"], 1)
        self.assertEqual(summary["counts"]["instances"], 2)
        self.assertEqual(summary["counts"]["patterns"], 3)
        self.assertEqual(summary["counts"]["hard_negatives"], 1)
        self.assertEqual(summary["counts"]["hashes_verified"], 4)

    def test_duplicate_victim_pattern_and_bad_hash_fail(self) -> None:
        self.manifest["instances"][1]["victim_net"] = "n1"
        self.manifest["files"]["golden.bench"]["sha256"] = "0" * 64
        self.groundtruth["patterns"][1]["pattern_bits"] = "111011"
        self._write_fixture()

        result, summary = self._run()
        self.assertEqual(result, 1)
        codes = {issue["code"] for issue in summary["issues"]}
        self.assertIn("DUPLICATE_VICTIM", codes)
        self.assertIn("DUPLICATE_PATTERN", codes)
        self.assertIn("SHA256_MISMATCH", codes)

    def test_invalid_negative_is_rejected(self) -> None:
        self.negatives["patterns"][0]["pattern_bits"] = "111011"
        self._write_fixture()

        result, summary = self._run()
        self.assertEqual(result, 1)
        codes = {issue["code"] for issue in summary["issues"]}
        self.assertIn("DUPLICATE_POSITIVE_NEGATIVE_PATTERN", codes)
        self.assertIn("NEGATIVE_TRIGGER_ACTIVE", codes)

    def test_missing_singleton_witness_fails(self) -> None:
        self.groundtruth["patterns"] = [
            pattern for pattern in self.groundtruth["patterns"] if pattern["activation_mask"] != "01"
        ]
        self.groundtruth["pattern_count"] = len(self.groundtruth["patterns"])
        self._write_fixture()

        result, summary = self._run()
        self.assertEqual(result, 1)
        missing = [
            issue for issue in summary["issues"] if issue["code"] == "MISSING_SINGLETON_WITNESS"
        ]
        self.assertEqual(len(missing), 1)
        self.assertIn("HT1", missing[0]["message"])

    def test_profile_exact_counts_and_atomic_indexes_pass(self) -> None:
        result, summary, ready_path, rejected_path = self._run_profile(self._matrix())
        self.assertEqual(result, 0)
        self.assertEqual(summary["acceptance"]["gt_ready_cases"], 1)
        self.assertEqual(summary["acceptance"]["rejected_cases"], 0)
        ready_rows = [json.loads(line) for line in ready_path.read_text().splitlines()]
        self.assertEqual([row["case_id"] for row in ready_rows], ["c880_k2_t3_s1000"])
        self.assertEqual(
            ready_rows[0]["artifacts"]["case_manifest"],
            "c880/c880_k2_t3_s1000/case_manifest.json",
        )
        self.assertEqual(len(ready_rows[0]["artifacts"]["groundtruth_sha256"]), 64)
        self.assertEqual(rejected_path.read_text(), "")
        self.assertFalse(ready_path.with_suffix(".jsonl.tmp").exists())

    def test_profile_witness_quota_mismatch_is_rejected(self) -> None:
        matrix = self._matrix()
        matrix["groundtruth_profiles"]["fixture"]["singleton_witnesses_per_instance"] = 2
        result, summary, ready_path, rejected_path = self._run_profile(matrix)
        self.assertEqual(result, 1)
        codes = {issue["code"] for issue in summary["issues"]}
        self.assertIn("GT_PROFILE_WITNESS_COUNT_MISMATCH", codes)
        self.assertIn("GT_PROFILE_PATTERN_COUNT_MISMATCH", codes)
        self.assertEqual(ready_path.read_text(), "")
        rejected = json.loads(rejected_path.read_text().strip())
        self.assertEqual(rejected["status"], "rejected")
        self.assertTrue(rejected["failures"])

    def test_profile_hard_negative_quota_mismatch_is_rejected(self) -> None:
        matrix = self._matrix()
        matrix["groundtruth_profiles"]["fixture"]["hard_negatives_per_case"] = 2
        result, summary, _, _ = self._run_profile(matrix)
        self.assertEqual(result, 1)
        codes = {issue["code"] for issue in summary["issues"]}
        self.assertIn("HARD_NEGATIVE_PROFILE_COUNT_MISMATCH", codes)
        self.assertIn("HARD_NEGATIVE_PROFILE_GENERATION_MISMATCH", codes)


if __name__ == "__main__":
    unittest.main()
