#!/usr/bin/env python3
"""Regression tests for the V4 rule-benchmark projection tools."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import generate_v4_rule_benchmark_manifest as generator
from scripts import materialize_v4_benchmark_inputs as materializer


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class V4ManifestTest(unittest.TestCase):
    def _create_case(
        self,
        root: Path,
        benchmark: str,
        case_id: str,
        phase: str,
        count: int,
        trigger_size: int,
        topology: str,
        seed: int,
        golden_text: str,
    ) -> dict:
        case_dir = root / benchmark / case_id
        case_dir.mkdir(parents=True)
        golden = case_dir / "golden.bench"
        combined = case_dir / "combined.bench"
        groundtruth = case_dir / "groundtruth.json"
        golden.write_text(golden_text, encoding="utf-8")
        combined.write_text(golden_text + f"# {case_id}\n", encoding="utf-8")
        groundtruth.write_text(
            json.dumps(
                {
                    "complete": True,
                    "pattern_count": count * 10,
                    "pi_order": ["a"],
                    "patterns": [{"pattern_bits": "1"}] * (count * 10),
                },
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        case_manifest = {
            "files": {
                "combined.bench": {"sha256": _sha(combined)},
                "golden.bench": {"sha256": _sha(golden)},
            }
        }
        manifest_path = case_dir / "case_manifest.json"
        manifest_path.write_text(
            json.dumps(case_manifest, sort_keys=True) + "\n", encoding="utf-8"
        )
        rel = case_dir.relative_to(root)
        return {
            "schema_version": generator.READY_SCHEMA,
            "status": "gt_ready",
            "case_id": case_id,
            "benchmark": benchmark,
            "phase_id": phase,
            "split": "final_in_distribution" if phase == "core_final" else "stress",
            "generation": {
                "trojan_count": count,
                "trigger_size": trigger_size,
                "trigger_topology": topology,
                "seed": seed,
            },
            "validation": {
                "positive_pattern_count": count * 10,
                "hard_negative_count": 8,
            },
            "artifacts": {
                "case_manifest": str(rel / "case_manifest.json"),
                "case_manifest_sha256": _sha(manifest_path),
                "groundtruth": str(rel / "groundtruth.json"),
                "groundtruth_sha256": _sha(groundtruth),
            },
        }

    def test_generate_and_materialize(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            source = temp / "source"
            validation = source / "validation"
            validation.mkdir(parents=True)
            rows = [
                self._create_case(
                    source, "c880", "c880_n1", "core_final", 1, 3,
                    "disjoint", 1, "INPUT(a)\nOUTPUT(a)\n",
                ),
                self._create_case(
                    source, "c880", "c880_n3", "five_trojan_stress", 3, 5,
                    "shared_trigger_literals", 2, "INPUT(a)\nOUTPUT(a)\n",
                ),
            ]
            (validation / "final_gt_ready_index.jsonl").write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                encoding="utf-8",
            )
            (validation / "final_rejected_cases.jsonl").write_text(
                json.dumps(
                    {
                        "case_id": "c880_rejected",
                        "failure_category": "groundtruth_validation_failure",
                    },
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )
            matrix = temp / "matrix.json"
            matrix.write_text(
                json.dumps(
                    {"benchmark_catalog": {"c880": {"size_class": "small"}}}
                ),
                encoding="utf-8",
            )
            manifest = generator.build_manifest(
                source, Path("validation/v4_inputs"), 123.0, matrix
            )
            self.assertEqual(manifest["inventory"]["scheduled_count"], 3)
            self.assertEqual(manifest["inventory"]["ready_count"], 2)
            self.assertEqual(manifest["profiles"]["all_ready"], ["c880_n1", "c880_n3"])
            self.assertEqual(manifest["profiles"]["core_final"], ["c880_n1"])
            self.assertEqual(manifest["profiles"]["n3"], ["c880_n3"])
            self.assertEqual(manifest["profiles"]["shared_trigger_literals"], ["c880_n3"])
            self.assertEqual(manifest["profile_metadata"], {})
            self.assertEqual(manifest["cases"][0]["timeout_seconds"], 123.0)

            target = temp / "target"
            target.mkdir()
            created, reused = materializer.materialize(
                source, target, manifest, "all_ready"
            )
            self.assertEqual((created, reused), (5, 1))
            golden_target = target / "validation/v4_inputs/golden/c880.bench"
            self.assertTrue(golden_target.is_file())
            for case_id in ("c880_n1", "c880_n3"):
                source_case = source / "c880" / case_id
                trojan_target = (
                    target / "validation/v4_inputs/trojan/c880" / f"{case_id}.bench"
                )
                gt_target = (
                    target / "validation/v4_inputs/groundtruth/c880"
                    / f"{case_id}_error_patterns.json"
                )
                self.assertEqual(source_case.joinpath("combined.bench").stat().st_ino,
                                 trojan_target.stat().st_ino)
                self.assertEqual(source_case.joinpath("groundtruth.json").stat().st_ino,
                                 gt_target.stat().st_ino)
            created_again, reused_again = materializer.materialize(
                source, target, manifest, "all_ready"
            )
            self.assertEqual(created_again, 0)
            self.assertEqual(reused_again, 6)

    def test_rejects_equal_copy_instead_of_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            source = temp / "source"
            (source / "validation").mkdir(parents=True)
            row = self._create_case(
                source, "c880", "case0", "core_final", 1, 3,
                "disjoint", 1, "INPUT(a)\nOUTPUT(a)\n",
            )
            (source / "validation/final_gt_ready_index.jsonl").write_text(
                json.dumps(row) + "\n", encoding="utf-8"
            )
            (source / "validation/final_rejected_cases.jsonl").write_text(
                "", encoding="utf-8"
            )
            manifest = generator.build_manifest(
                source, Path("validation/v4_inputs"), 10.0
            )
            target = temp / "target"
            copied = target / "validation/v4_inputs/trojan/c880/case0.bench"
            copied.parent.mkdir(parents=True)
            copied.write_bytes((source / "c880/case0/combined.bench").read_bytes())
            with self.assertRaisesRegex(RuntimeError, "not the declared source hardlink"):
                materializer.materialize(source, target, manifest, "all_ready")

    def test_rejects_tampered_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "source"
            (source / "validation").mkdir(parents=True)
            row = self._create_case(
                source, "c880", "case0", "core_final", 1, 3,
                "disjoint", 1, "INPUT(a)\nOUTPUT(a)\n",
            )
            (source / row["artifacts"]["groundtruth"]).write_text("{}\n")
            (source / "validation/final_gt_ready_index.jsonl").write_text(
                json.dumps(row) + "\n", encoding="utf-8"
            )
            (source / "validation/final_rejected_cases.jsonl").write_text(
                "", encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "groundtruth SHA mismatch"):
                generator.build_manifest(
                    source, Path("validation/v4_inputs"), 10.0
                )

    def test_materializer_rejects_manifest_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            source = temp / "source"
            (source / "validation").mkdir(parents=True)
            row = self._create_case(
                source, "c880", "case0", "core_final", 1, 3,
                "disjoint", 1, "INPUT(a)\nOUTPUT(a)\n",
            )
            (source / "validation/final_gt_ready_index.jsonl").write_text(
                json.dumps(row) + "\n", encoding="utf-8"
            )
            (source / "validation/final_rejected_cases.jsonl").write_text(
                "", encoding="utf-8"
            )
            manifest = generator.build_manifest(
                source, Path("validation/v4_inputs"), 10.0
            )
            manifest["cases"][0]["circuit"] = ".."
            with self.assertRaisesRegex(RuntimeError, "unsafe circuit"):
                materializer.materialize(source, temp / "target", manifest, "all_ready")

    def test_generator_rejects_dot_components(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unsafe benchmark"):
            generator._safe_component("..", "benchmark")
        with self.assertRaisesRegex(RuntimeError, "unsafe case_id"):
            generator._safe_component(".", "case_id")

    def test_fresh_paper_profile_is_result_blind_and_excludes_smoke(self) -> None:
        cases = []
        ordinal = 0

        def add(phase: str, circuit: str, count: int, trigger_size: int,
                amount: int) -> None:
            nonlocal ordinal
            topology = (
                "shared_trigger_literals"
                if phase == "shared_trigger_challenge" else "disjoint"
            )
            for _ in range(amount):
                ordinal += 1
                cases.append({
                    "case_id": f"case_{ordinal:03d}",
                    "circuit": circuit,
                    "v4": {
                        "phase_id": phase,
                        "trojan_count": count,
                        "trigger_size": trigger_size,
                        "trigger_topology": topology,
                    },
                })

        # 48 core cells, with one extra alternative in each cell.
        for circuit in ("a", "b", "c", "d", "e", "f", "g", "h"):
            for count in (1, 2, 3):
                for trigger_size in (3, 5):
                    add("core_final", circuit, count, trigger_size, 2)
        # 6 OOD cells × two selected, plus one alternative each.
        for circuit in ("i", "j", "k"):
            for count in (2, 3):
                add("heldout_ood", circuit, count, 5, 3)
        # 12 shared cells.
        for circuit in ("l", "m", "n"):
            for count in (2, 3):
                for trigger_size in (3, 5):
                    add("shared_trigger_challenge", circuit, count, trigger_size, 2)
        # Ten stress cases; one is reserved for the diagnostic smoke.
        add("five_trojan_stress", "o", 5, 5, 10)
        smoke_case = cases[-1]["case_id"]
        profiles = {"smoke_extended": [smoke_case]}
        generator._add_fresh_paper_profile(cases, profiles, "matrix-sha")
        selected = profiles["paper_fresh_stratified_81"]
        self.assertEqual(len(selected), 81)
        self.assertEqual(len(set(selected)), 81)
        self.assertNotIn(smoke_case, selected)

        replay = {"smoke_extended": [smoke_case]}
        generator._add_fresh_paper_profile(
            list(reversed(cases)), replay, "matrix-sha"
        )
        self.assertEqual(selected, replay["paper_fresh_stratified_81"])


if __name__ == "__main__":
    unittest.main()
