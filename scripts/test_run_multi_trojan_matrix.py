#!/usr/bin/env python3
"""Focused regression tests for run_multi_trojan_matrix.py safety guards."""

from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import run_multi_trojan_matrix as runner


class AggregateScopeGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_manifest(self, phases: list[str]) -> bytes:
        payload = {
            "schema_version": runner.RUNNER_SCHEMA_VERSION,
            "matrix": {"selected_phases": phases},
        }
        path = self.root / "dataset_manifest.json"
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        return path.read_bytes()

    def test_empty_root_allows_filtered_scope(self) -> None:
        runner._guard_existing_aggregate_scope(
            self.root, ["pilot_dev"], phase_filter_active=True
        )

    def test_same_filtered_scope_is_resumable(self) -> None:
        self._write_manifest(["pilot_dev"])
        runner._guard_existing_aggregate_scope(
            self.root, ["pilot_dev"], phase_filter_active=True
        )

    def test_different_filtered_scope_is_rejected_without_mutation(self) -> None:
        before = self._write_manifest(["pilot_dev", "core_final"])
        index_path = self.root / "dataset_index.jsonl"
        index_path.write_text('{"case_id":"sentinel"}\n', encoding="utf-8")
        index_before = index_path.read_bytes()

        with self.assertRaisesRegex(runner.MatrixError, "would shrink"):
            runner._guard_existing_aggregate_scope(
                self.root,
                ["pilot_dev"],
                phase_filter_active=True,
            )

        self.assertEqual(
            (self.root / "dataset_manifest.json").read_bytes(), before
        )
        self.assertEqual(index_path.read_bytes(), index_before)

    def test_unfiltered_run_can_rebuild_canonical_aggregate(self) -> None:
        self._write_manifest(["pilot_dev"])
        runner._guard_existing_aggregate_scope(
            self.root,
            ["pilot_dev", "core_final"],
            phase_filter_active=False,
        )

    def test_orphaned_aggregate_is_rejected_for_filtered_run(self) -> None:
        (self.root / "dataset_index.jsonl").write_text("", encoding="utf-8")
        with self.assertRaisesRegex(runner.MatrixError, "no readable"):
            runner._guard_existing_aggregate_scope(
                self.root, ["pilot_dev"], phase_filter_active=True
            )


class ExistingCaseManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        contents = {
            "golden.bench": b"INPUT(a)\nOUTPUT(a)\n",
            "combined.bench": b"INPUT(a)\nOUTPUT(a)\n# combined\n",
            "individual/HT0.bench": b"INPUT(a)\nOUTPUT(a)\n# HT0\n",
            "individual/HT1.bench": b"INPUT(a)\nOUTPUT(a)\n# HT1\n",
        }
        for relative, data in contents.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        source_hash = hashlib.sha256(contents["golden.bench"]).hexdigest()
        self.spec = runner.CaseSpec(
            ordinal=0,
            phase_id="fixture",
            split="fixture",
            groundtruth_profile="pilot",
            benchmark="fixture",
            source_path=self.root / "source.bench",
            source_sha256=source_hash,
            size_class="small",
            trojan_count=2,
            trigger_size=3,
            trigger_topology="shared_trigger_literals",
            trigger_overlap=0.5,
            victim_placement="random",
            seed=42,
        )
        files = {
            relative: {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
            for relative, data in contents.items()
        }
        self.manifest = {
            "schema_version": runner.CASE_SCHEMA_VERSION,
            "case_id": self.spec.case_id,
            "benchmark": self.spec.benchmark,
            "golden_path": "golden.bench",
            "combined_path": "combined.bench",
            "paths": {
                "golden": "golden.bench",
                "combined": "combined.bench",
                "individual": {
                    "HT0": "individual/HT0.bench",
                    "HT1": "individual/HT1.bench",
                },
            },
            "generation": {
                "seed": self.spec.seed,
                "trojan_count": self.spec.trojan_count,
                "trigger_size": self.spec.trigger_size,
                "trigger_topology": self.spec.trigger_topology,
                "requested_trigger_overlap": self.spec.trigger_overlap,
                "actual_trigger_overlap": 2 / 3,
                "shared_literal_count": 2,
                "source_golden_sha256": self.spec.source_sha256,
                "payload_placement": {"requested": self.spec.victim_placement},
            },
            "files": files,
            "instances": [
                {
                    "instance_id": "HT0",
                    "individual_path": "individual/HT0.bench",
                },
                {
                    "instance_id": "HT1",
                    "individual_path": "individual/HT1.bench",
                },
            ],
        }
        self.manifest_path = self.root / "case_manifest.json"
        self._write_manifest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_manifest(self) -> None:
        self.manifest_path.write_text(
            json.dumps(self.manifest) + "\n", encoding="utf-8"
        )

    def test_matching_manifest_and_artifacts_pass(self) -> None:
        manifest, error = runner._read_case_manifest(
            self.manifest_path, self.spec
        )
        self.assertIsNotNone(manifest)
        self.assertIsNone(error)

    def test_schema_and_topology_mismatches_are_rejected(self) -> None:
        self.manifest["schema_version"] = "legacy"
        self._write_manifest()
        _, error = runner._read_case_manifest(self.manifest_path, self.spec)
        self.assertIn("schema_version", error or "")

        self.manifest["schema_version"] = runner.CASE_SCHEMA_VERSION
        self.manifest["generation"]["trigger_topology"] = "disjoint"
        self._write_manifest()
        _, error = runner._read_case_manifest(self.manifest_path, self.spec)
        self.assertIn("trigger_topology", error or "")

    def test_quantized_overlap_mismatch_is_rejected(self) -> None:
        self.manifest["generation"]["shared_literal_count"] = 1
        self._write_manifest()
        _, error = runner._read_case_manifest(self.manifest_path, self.spec)
        self.assertIn("shared_literal_count", error or "")

    def test_artifact_hash_mismatch_is_rejected(self) -> None:
        path = self.root / "combined.bench"
        original = path.read_bytes()
        path.write_bytes(original[:-2] + b"X\n")
        self.assertEqual(path.stat().st_size, len(original))
        _, error = runner._read_case_manifest(self.manifest_path, self.spec)
        self.assertIn("SHA-256", error or "")

    def test_unsafe_artifact_path_is_rejected(self) -> None:
        metadata = self.manifest["files"].pop("combined.bench")
        self.manifest["files"]["../combined.bench"] = metadata
        self.manifest["combined_path"] = "../combined.bench"
        self.manifest["paths"]["combined"] = "../combined.bench"
        self._write_manifest()
        _, error = runner._read_case_manifest(self.manifest_path, self.spec)
        self.assertIn("unsafe path", error or "")


if __name__ == "__main__":
    unittest.main()
