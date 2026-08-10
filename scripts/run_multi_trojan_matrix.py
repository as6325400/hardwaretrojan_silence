#!/usr/bin/env python3
"""Run the reproducible multi-Trojan generation matrix.

The matrix runner intentionally invokes ``generate_multi_trojan_dataset.py``
once per case.  A case therefore has exactly one writer even when small
benchmarks are generated concurrently.  Medium and large benchmarks are run
serially to avoid excessive memory and I/O pressure.

Successful runs create three aggregate files in ``--output-root``:

* ``dataset_manifest.json`` -- run metadata and per-phase summaries;
* ``dataset_index.jsonl`` -- one deterministic, portable record per case; and
* ``generation_failures.jsonl`` -- one record per failed scheduled case.
"""

from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


RUNNER_SCHEMA_VERSION = "v4-multi-trojan-matrix-run/1"
INDEX_SCHEMA_VERSION = "v4-multi-trojan-dataset-index/1"
FAILURE_SCHEMA_VERSION = "v4-multi-trojan-generation-failure/1"
CASE_SCHEMA_VERSION = "v4-multi-independent-trojan/1"
DEFAULT_CONFIG = Path("configs/multi_trojan_experiment_matrix.json")
DEFAULT_OUTPUT_ROOT = Path("generated_datasets/V4_multiIndependentTrojan")
AGGREGATE_FILENAMES = (
    "dataset_manifest.json",
    "dataset_index.jsonl",
    "generation_failures.jsonl",
    "groundtruth_failures.jsonl",
)


class MatrixError(RuntimeError):
    """Raised when the experiment matrix is malformed or inconsistent."""


@dataclass(frozen=True)
class CaseSpec:
    ordinal: int
    phase_id: str
    split: str
    groundtruth_profile: str
    benchmark: str
    source_path: Path
    source_sha256: str
    size_class: str
    trojan_count: int
    trigger_size: int
    trigger_topology: str
    trigger_overlap: float
    victim_placement: str
    seed: int

    @property
    def overlap_tag(self) -> int:
        return int(round(self.trigger_overlap * 1000))

    @property
    def case_id(self) -> str:
        return (
            f"{self.benchmark}_n{self.trojan_count}_t{self.trigger_size}_"
            f"o{self.overlap_tag:03d}_s{self.seed}_{self.source_sha256[:8]}"
        )

    @property
    def collision_key(self) -> Tuple[str, int, int, int, int]:
        # This mirrors every parameter used by the generator to name a case.
        return (
            str(self.source_path),
            self.trojan_count,
            self.trigger_size,
            self.overlap_tag,
            self.seed,
        )

    def manifest_path(self, output_root: Path) -> Path:
        return output_root / self.benchmark / self.case_id / "case_manifest.json"


@dataclass(frozen=True)
class CaseResult:
    spec: CaseSpec
    status: str
    manifest_path: Optional[Path]
    command: Tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    error: Optional[str] = None
    groundtruth: Optional["GroundTruthResult"] = None


@dataclass(frozen=True)
class GroundTruthProfile:
    profile_id: str
    witnesses_per_mask: int
    witnesses_per_singleton: Optional[int]
    witnesses_per_pair: Optional[int]
    witnesses_per_all: Optional[int]
    hard_negatives: int


@dataclass(frozen=True)
class GroundTruthResult:
    status: str
    profile_id: str
    groundtruth_path: Path
    negative_patterns_path: Path
    command: Tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    error: Optional[str] = None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise MatrixError(f"cannot read JSON config {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MatrixError(f"matrix root must be a JSON object: {path}")
    return value


def _require_list(mapping: Mapping[str, Any], key: str, context: str) -> List[Any]:
    value = mapping.get(key)
    if not isinstance(value, list) or not value:
        raise MatrixError(f"{context}.{key} must be a non-empty array")
    return value


def _require_string(mapping: Mapping[str, Any], key: str, context: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise MatrixError(f"{context}.{key} must be a non-empty string")
    return value


def _topology_overlap(matrix: Mapping[str, Any], topology: str) -> float:
    if topology in {"disjoint", "disjoint_trigger_literals"}:
        return 0.0
    if topology != "shared_trigger_literals":
        raise MatrixError(f"unsupported trigger topology {topology!r}")

    parameters = matrix.get("trigger_topology_parameters", {})
    if parameters is None:
        parameters = {}
    if not isinstance(parameters, dict):
        raise MatrixError("trigger_topology_parameters must be an object")
    topology_parameters = parameters.get(topology, {})
    if topology_parameters is None:
        topology_parameters = {}
    if not isinstance(topology_parameters, dict):
        raise MatrixError(
            f"trigger_topology_parameters.{topology} must be an object"
        )
    raw_overlap = topology_parameters.get("generator_trigger_overlap", 0.5)
    if isinstance(raw_overlap, bool) or not isinstance(raw_overlap, (int, float)):
        raise MatrixError(
            f"trigger_topology_parameters.{topology}.generator_trigger_overlap "
            "must be numeric"
        )
    overlap = float(raw_overlap)
    if not 0.0 < overlap < 1.0:
        raise MatrixError(
            f"shared-trigger overlap must be in (0, 1), got {overlap}"
        )
    return overlap


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise MatrixError(f"{label} must be a positive integer")
    return value


def _optional_positive_integer(value: Any, label: str) -> Optional[int]:
    if value is None:
        return None
    return _positive_integer(value, label)


def _groundtruth_profile(
    matrix: Mapping[str, Any], profile_id: str
) -> GroundTruthProfile:
    raw_profiles = matrix.get("groundtruth_profiles")
    if not isinstance(raw_profiles, dict):
        raise MatrixError("groundtruth_profiles must be an object")
    raw_profile = raw_profiles.get(profile_id)
    if not isinstance(raw_profile, dict):
        raise MatrixError(f"groundtruth profile {profile_id!r} is not defined")
    context = f"groundtruth_profiles[{profile_id}]"

    # The release matrix uses class-specific names.  Its pair target is also
    # the fallback for any intermediate subset (e.g. a 3-of-5 activation mask).
    raw_per_mask = raw_profile.get("witnesses_per_requested_mask")
    if raw_per_mask is None:
        raw_per_mask = raw_profile.get("witnesses_per_mask")
    if raw_per_mask is None:
        raw_per_mask = raw_profile.get("pair_witnesses_per_pair", 1)

    raw_hard_negatives = raw_profile.get("hard_negatives_per_case", 0)
    if (
        isinstance(raw_hard_negatives, bool)
        or not isinstance(raw_hard_negatives, int)
        or raw_hard_negatives < 0
    ):
        raise MatrixError(f"{context}.hard_negatives_per_case must be non-negative")

    return GroundTruthProfile(
        profile_id=profile_id,
        witnesses_per_mask=_positive_integer(
            raw_per_mask, f"{context}.witnesses_per_requested_mask"
        ),
        witnesses_per_singleton=_optional_positive_integer(
            raw_profile.get("singleton_witnesses_per_instance"),
            f"{context}.singleton_witnesses_per_instance",
        ),
        witnesses_per_pair=_optional_positive_integer(
            raw_profile.get("pair_witnesses_per_pair"),
            f"{context}.pair_witnesses_per_pair",
        ),
        witnesses_per_all=_optional_positive_integer(
            raw_profile.get("all_on_witnesses_per_case"),
            f"{context}.all_on_witnesses_per_case",
        ),
        hard_negatives=raw_hard_negatives,
    )


def _selected_groundtruth_profiles(
    specs: Sequence[CaseSpec], matrix: Mapping[str, Any]
) -> Dict[str, GroundTruthProfile]:
    return {
        profile_id: _groundtruth_profile(matrix, profile_id)
        for profile_id in sorted({spec.groundtruth_profile for spec in specs})
    }


def _selected_phases(
    matrix: Mapping[str, Any], requested: Optional[Sequence[str]]
) -> List[Mapping[str, Any]]:
    raw_phases = matrix.get("phases")
    if not isinstance(raw_phases, list):
        raise MatrixError("phases must be an array")

    phases: List[Mapping[str, Any]] = []
    by_id: Dict[str, Mapping[str, Any]] = {}
    for index, raw_phase in enumerate(raw_phases):
        if not isinstance(raw_phase, dict):
            raise MatrixError(f"phases[{index}] must be an object")
        phase_id = _require_string(raw_phase, "id", f"phases[{index}]")
        if phase_id in by_id:
            raise MatrixError(f"duplicate phase id {phase_id!r}")
        by_id[phase_id] = raw_phase

    if requested:
        requested_unique = list(dict.fromkeys(requested))
        unknown = [phase_id for phase_id in requested_unique if phase_id not in by_id]
        if unknown:
            raise MatrixError("unknown phase(s): " + ", ".join(unknown))
        for phase_id in requested_unique:
            phase = by_id[phase_id]
            if phase.get("enabled") is not True:
                raise MatrixError(
                    f"phase {phase_id!r} is disabled in the matrix and cannot be run"
                )
            phases.append(phase)
    else:
        phases = [phase for phase in by_id.values() if phase.get("enabled") is True]

    if not phases:
        raise MatrixError("no enabled phases selected")
    return phases


def expand_matrix(
    matrix: Mapping[str, Any],
    repo_root: Path,
    requested_phases: Optional[Sequence[str]],
) -> Tuple[List[CaseSpec], Dict[str, int]]:
    catalog = matrix.get("benchmark_catalog")
    if not isinstance(catalog, dict):
        raise MatrixError("benchmark_catalog must be an object")

    phases = _selected_phases(matrix, requested_phases)
    defaults = matrix.get("defaults", {})
    if defaults is None:
        defaults = {}
    if not isinstance(defaults, dict):
        raise MatrixError("defaults must be an object")
    default_victim_placement = defaults.get("victim_placement", "random")
    if default_victim_placement not in {"random", "output-near"}:
        raise MatrixError("defaults.victim_placement must be 'random' or 'output-near'")
    specs: List[CaseSpec] = []
    expected_by_phase: Dict[str, int] = {}
    seen: Dict[Tuple[str, int, int, int, int], CaseSpec] = {}

    for phase in phases:
        phase_id = _require_string(phase, "id", "phase")
        context = f"phase[{phase_id}]"
        split = _require_string(phase, "split", context)
        gt_profile = _require_string(phase, "groundtruth_profile", context)
        circuits = _require_list(phase, "circuits", context)
        counts = _require_list(phase, "trojan_counts", context)
        trigger_sizes = _require_list(phase, "trigger_sizes", context)
        topologies = _require_list(phase, "trigger_topologies", context)
        seeds = _require_list(phase, "seeds", context)
        victim_placement = phase.get("victim_placement", default_victim_placement)
        if victim_placement not in {"random", "output-near"}:
            raise MatrixError(
                f"{context}.victim_placement must be 'random' or 'output-near'"
            )

        phase_start = len(specs)
        for benchmark_value in circuits:
            if not isinstance(benchmark_value, str) or not benchmark_value:
                raise MatrixError(f"{context}.circuits contains an invalid name")
            benchmark = benchmark_value
            record = catalog.get(benchmark)
            if not isinstance(record, dict):
                raise MatrixError(f"{context}: benchmark {benchmark!r} is not catalogued")
            relative_path = _require_string(
                record, "path", f"benchmark_catalog[{benchmark}]"
            )
            source_path = (repo_root / relative_path).resolve()
            source_sha256 = _require_string(
                record, "sha256", f"benchmark_catalog[{benchmark}]"
            ).lower()
            if len(source_sha256) != 64 or any(
                character not in "0123456789abcdef" for character in source_sha256
            ):
                raise MatrixError(
                    f"benchmark_catalog[{benchmark}].sha256 is not a SHA-256 digest"
                )
            size_class_value = record.get("size_class", "small")
            if not isinstance(size_class_value, str) or not size_class_value:
                raise MatrixError(
                    f"benchmark_catalog[{benchmark}].size_class must be a string"
                )

            for count_value in counts:
                if isinstance(count_value, bool) or not isinstance(count_value, int):
                    raise MatrixError(f"{context}.trojan_counts must contain integers")
                for trigger_size_value in trigger_sizes:
                    if isinstance(trigger_size_value, bool) or not isinstance(
                        trigger_size_value, int
                    ):
                        raise MatrixError(
                            f"{context}.trigger_sizes must contain integers"
                        )
                    for topology_value in topologies:
                        if not isinstance(topology_value, str):
                            raise MatrixError(
                                f"{context}.trigger_topologies must contain strings"
                            )
                        overlap = _topology_overlap(matrix, topology_value)
                        if count_value == 1 and overlap != 0.0:
                            raise MatrixError(
                                f"{context}: shared trigger literals are undefined for "
                                "trojan_count=1"
                            )
                        for seed_value in seeds:
                            if isinstance(seed_value, bool) or not isinstance(
                                seed_value, int
                            ):
                                raise MatrixError(
                                    f"{context}.seeds must contain integers"
                                )
                            spec = CaseSpec(
                                ordinal=len(specs),
                                phase_id=phase_id,
                                split=split,
                                groundtruth_profile=gt_profile,
                                benchmark=benchmark,
                                source_path=source_path,
                                source_sha256=source_sha256,
                                size_class=size_class_value,
                                trojan_count=count_value,
                                trigger_size=trigger_size_value,
                                trigger_topology=topology_value,
                                trigger_overlap=overlap,
                                victim_placement=victim_placement,
                                seed=seed_value,
                            )
                            previous = seen.get(spec.collision_key)
                            if previous is not None:
                                raise MatrixError(
                                    "two matrix entries would write the same case "
                                    f"{spec.case_id}: phases {previous.phase_id!r} and "
                                    f"{spec.phase_id!r}"
                                )
                            seen[spec.collision_key] = spec
                            specs.append(spec)

        actual_count = len(specs) - phase_start
        expected_by_phase[phase_id] = actual_count
        configured_expected = phase.get("expected_case_count")
        if configured_expected is not None and configured_expected != actual_count:
            raise MatrixError(
                f"{context}.expected_case_count={configured_expected}, but its "
                f"Cartesian product contains {actual_count} cases"
            )

    return specs, expected_by_phase


def _verify_selected_benchmarks(specs: Sequence[CaseSpec]) -> None:
    verified: set[Path] = set()
    for spec in specs:
        if spec.source_path in verified:
            continue
        if not spec.source_path.is_file():
            raise MatrixError(f"benchmark file does not exist: {spec.source_path}")
        actual_sha256 = _sha256_file(spec.source_path)
        if actual_sha256 != spec.source_sha256:
            raise MatrixError(
                f"benchmark hash mismatch for {spec.benchmark}: matrix has "
                f"{spec.source_sha256}, file has {actual_sha256}"
            )
        verified.add(spec.source_path)


def _guard_existing_aggregate_scope(
    output_root: Path,
    selected_phase_ids: Sequence[str],
    *,
    phase_filter_active: bool,
) -> None:
    """Prevent a filtered run from silently replacing a wider aggregate.

    Case directories are independent, but the four dataset-level aggregate
    files are snapshots of only the current run.  Replacing a full-matrix
    snapshot with a one-phase snapshot would hide otherwise intact cases and
    discard failure history.  An unfiltered run is deliberately allowed so it
    can rebuild the canonical all-enabled-phases aggregate.
    """
    if not phase_filter_active:
        return

    existing_artifacts = [
        output_root / name
        for name in AGGREGATE_FILENAMES
        if (output_root / name).exists()
    ]
    if not existing_artifacts:
        return

    manifest_path = output_root / "dataset_manifest.json"
    if not manifest_path.is_file():
        names = ", ".join(path.name for path in existing_artifacts)
        raise MatrixError(
            "refusing a phase-filtered run because the output root contains "
            f"aggregate artifact(s) but no readable dataset_manifest.json: {names}. "
            "Use a separate staging --output-root, or rebuild the canonical "
            "aggregate without --phase and with --skip-existing."
        )

    aggregate = _load_json(manifest_path)
    matrix_record = aggregate.get("matrix")
    existing_phases = (
        matrix_record.get("selected_phases")
        if isinstance(matrix_record, dict)
        else None
    )
    if (
        not isinstance(existing_phases, list)
        or not all(isinstance(item, str) and item for item in existing_phases)
        or len(existing_phases) != len(set(existing_phases))
    ):
        raise MatrixError(
            "refusing a phase-filtered run because the existing "
            "dataset_manifest.json has no valid matrix.selected_phases array. "
            "Use a separate staging --output-root, or rebuild the canonical "
            "aggregate without --phase and with --skip-existing."
        )

    requested = list(dict.fromkeys(selected_phase_ids))
    if set(existing_phases) != set(requested):
        raise MatrixError(
            "refusing to replace an aggregate built for phases "
            f"{existing_phases!r} with the phase-filtered scope {requested!r}; "
            "this would shrink dataset_index.jsonl and clear unrelated failure "
            "history. Use a separate staging --output-root, or rebuild the "
            "canonical aggregate without --phase and with --skip-existing."
        )


def _case_command(
    spec: CaseSpec,
    repo_root: Path,
    output_root: Path,
    skip_existing: bool,
    matrix: Mapping[str, Any],
) -> Tuple[str, ...]:
    defaults = matrix.get("defaults", {})
    if defaults is None:
        defaults = {}
    if not isinstance(defaults, dict):
        raise MatrixError("defaults must be an object")

    command = [
        sys.executable,
        str(repo_root / "generate_multi_trojan_dataset.py"),
        "--input",
        str(spec.source_path),
        "--output-root",
        str(output_root),
        "--trojan-count",
        str(spec.trojan_count),
        "--trigger-size",
        str(spec.trigger_size),
        "--seed",
        str(spec.seed),
        "--trigger-overlap",
        format(spec.trigger_overlap, ".17g"),
        "--victim-placement",
        spec.victim_placement,
    ]
    if defaults.get("allow_victim_fallback") is True:
        command.append("--allow-victim-fallback")
    if skip_existing:
        command.append("--skip-existing")
    return tuple(command)


def _manifest_matches_spec(manifest: Mapping[str, Any], spec: CaseSpec) -> Optional[str]:
    if manifest.get("schema_version") != CASE_SCHEMA_VERSION:
        return (
            f"schema_version is {manifest.get('schema_version')!r}, expected "
            f"{CASE_SCHEMA_VERSION!r}"
        )
    if manifest.get("case_id") != spec.case_id:
        return f"case_id is {manifest.get('case_id')!r}, expected {spec.case_id!r}"
    if manifest.get("benchmark") != spec.benchmark:
        return (
            f"benchmark is {manifest.get('benchmark')!r}, expected "
            f"{spec.benchmark!r}"
        )
    generation = manifest.get("generation")
    if not isinstance(generation, dict):
        return "generation record is missing"
    checks = {
        "seed": spec.seed,
        "trojan_count": spec.trojan_count,
        "trigger_size": spec.trigger_size,
        "source_golden_sha256": spec.source_sha256,
    }
    for key, expected in checks.items():
        if generation.get(key) != expected:
            return f"generation.{key} is {generation.get(key)!r}, expected {expected!r}"
    if generation.get("trigger_topology") != spec.trigger_topology:
        return (
            "generation.trigger_topology is "
            f"{generation.get('trigger_topology')!r}, expected "
            f"{spec.trigger_topology!r}"
        )
    actual_overlap = generation.get("requested_trigger_overlap")
    if isinstance(actual_overlap, bool) or not isinstance(actual_overlap, (int, float)):
        return "generation.requested_trigger_overlap is missing or non-numeric"
    if abs(float(actual_overlap) - spec.trigger_overlap) > 1e-12:
        return (
            f"generation.requested_trigger_overlap is {actual_overlap!r}, expected "
            f"{spec.trigger_overlap!r}"
        )
    expected_shared_literals = int(round(spec.trigger_size * spec.trigger_overlap))
    expected_shared_literals = max(
        0, min(spec.trigger_size - 1, expected_shared_literals)
    )
    expected_actual_overlap = expected_shared_literals / spec.trigger_size
    if generation.get("shared_literal_count") != expected_shared_literals:
        return (
            "generation.shared_literal_count is "
            f"{generation.get('shared_literal_count')!r}, expected "
            f"{expected_shared_literals!r}"
        )
    actual_quantized_overlap = generation.get("actual_trigger_overlap")
    if (
        isinstance(actual_quantized_overlap, bool)
        or not isinstance(actual_quantized_overlap, (int, float))
        or abs(float(actual_quantized_overlap) - expected_actual_overlap) > 1e-12
    ):
        return (
            "generation.actual_trigger_overlap is "
            f"{actual_quantized_overlap!r}, expected "
            f"{expected_actual_overlap!r}"
        )
    payload_placement = generation.get("payload_placement")
    if not isinstance(payload_placement, dict):
        return "generation.payload_placement is missing"
    if payload_placement.get("requested") != spec.victim_placement:
        return (
            "generation.payload_placement.requested is "
            f"{payload_placement.get('requested')!r}, expected "
            f"{spec.victim_placement!r}"
        )
    return None


def _manifest_artifacts_match(
    manifest: Mapping[str, Any], manifest_path: Path, spec: CaseSpec
) -> Optional[str]:
    case_root = manifest_path.parent.resolve()

    golden_path = manifest.get("golden_path")
    combined_path = manifest.get("combined_path")
    if not isinstance(golden_path, str) or not golden_path:
        return "golden_path is missing"
    if not isinstance(combined_path, str) or not combined_path:
        return "combined_path is missing"

    paths_record = manifest.get("paths")
    if not isinstance(paths_record, dict):
        return "paths record is missing"
    if paths_record.get("golden") != golden_path:
        return "paths.golden does not match golden_path"
    if paths_record.get("combined") != combined_path:
        return "paths.combined does not match combined_path"

    instances = manifest.get("instances")
    if not isinstance(instances, list) or len(instances) != spec.trojan_count:
        return (
            f"instances has length {len(instances) if isinstance(instances, list) else None!r}, "
            f"expected {spec.trojan_count}"
        )
    individual_paths: List[str] = []
    for index, instance in enumerate(instances):
        if not isinstance(instance, dict):
            return f"instances[{index}] is not an object"
        expected_id = f"HT{index}"
        if instance.get("instance_id") != expected_id:
            return (
                f"instances[{index}].instance_id is "
                f"{instance.get('instance_id')!r}, expected {expected_id!r}"
            )
        individual_path = instance.get("individual_path")
        if not isinstance(individual_path, str) or not individual_path:
            return f"instances[{index}].individual_path is missing"
        individual_paths.append(individual_path)

    declared_individual = paths_record.get("individual")
    if not isinstance(declared_individual, dict):
        return "paths.individual is missing"
    for index, individual_path in enumerate(individual_paths):
        instance_id = f"HT{index}"
        if declared_individual.get(instance_id) != individual_path:
            return (
                f"paths.individual[{instance_id!r}] does not match "
                f"instances[{index}].individual_path"
            )

    required_paths = [golden_path, combined_path, *individual_paths]
    if len(required_paths) != len(set(required_paths)):
        return "golden, combined, and individual artifact paths must be distinct"

    files = manifest.get("files")
    if not isinstance(files, dict):
        return "files record is missing"
    missing_records = [relative for relative in required_paths if relative not in files]
    if missing_records:
        return f"files record is missing required artifact(s): {missing_records!r}"

    for relative, metadata in files.items():
        if not isinstance(relative, str) or not relative:
            return "files contains an invalid relative path"
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            return f"files contains unsafe path {relative!r}"
        resolved = (case_root / relative_path).resolve()
        if not resolved.is_relative_to(case_root):
            return f"files path escapes the case directory: {relative!r}"
        if not isinstance(metadata, dict):
            return f"files[{relative!r}] is not an object"
        expected_hash = metadata.get("sha256")
        expected_size = metadata.get("size_bytes")
        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(character not in "0123456789abcdef" for character in expected_hash)
        ):
            return f"files[{relative!r}].sha256 is not a lowercase SHA-256 digest"
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
        ):
            return f"files[{relative!r}].size_bytes is invalid"
        if not resolved.is_file():
            return f"declared artifact does not exist: {relative!r}"
        actual_size = resolved.stat().st_size
        if actual_size != expected_size:
            return (
                f"artifact {relative!r} size is {actual_size}, expected "
                f"{expected_size}"
            )
        actual_hash = _sha256_file(resolved)
        if actual_hash != expected_hash:
            return (
                f"artifact {relative!r} SHA-256 is {actual_hash}, expected "
                f"{expected_hash}"
            )

    golden_metadata = files.get(golden_path)
    assert isinstance(golden_metadata, dict)
    if golden_metadata.get("sha256") != spec.source_sha256:
        return (
            f"golden artifact SHA-256 is {golden_metadata.get('sha256')!r}, "
            f"expected source hash {spec.source_sha256!r}"
        )
    return None


def _read_case_manifest(path: Path, spec: CaseSpec) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        with path.open("r", encoding="utf-8") as source:
            manifest = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"cannot read generated manifest {path}: {exc}"
    if not isinstance(manifest, dict):
        return None, f"generated manifest is not an object: {path}"
    mismatch = _manifest_matches_spec(manifest, spec)
    if mismatch is not None:
        return None, f"generated manifest does not match matrix: {mismatch}"
    artifact_mismatch = _manifest_artifacts_match(manifest, path, spec)
    if artifact_mismatch is not None:
        return None, f"generated manifest artifacts are invalid: {artifact_mismatch}"
    return manifest, None


def _requested_groundtruth_masks(trojan_count: int) -> List[str]:
    def bits(value: int) -> str:
        return format(value, f"0{trojan_count}b")

    if trojan_count <= 3:
        return [bits(value) for value in range(1, 1 << trojan_count)]

    masks: List[int] = []
    seen: set[int] = set()

    def add(value: int) -> None:
        if value and value not in seen:
            seen.add(value)
            masks.append(value)

    for first in range(trojan_count):
        add(1 << (trojan_count - 1 - first))
    for first in range(trojan_count):
        for second in range(first + 1, trojan_count):
            add(
                (1 << (trojan_count - 1 - first))
                | (1 << (trojan_count - 1 - second))
            )
    add((1 << trojan_count) - 1)
    return [bits(value) for value in masks]


def _groundtruth_witness_target(
    profile: GroundTruthProfile, mask: str
) -> int:
    active = mask.count("1")
    # This order mirrors generate_multi_gt's WitnessTarget exactly.  It matters
    # for N=1 (singleton is also all) and N=2 (pair is also all).
    if active == 1 and profile.witnesses_per_singleton is not None:
        return profile.witnesses_per_singleton
    if active == len(mask) and profile.witnesses_per_all is not None:
        return profile.witnesses_per_all
    if active == 2 and profile.witnesses_per_pair is not None:
        return profile.witnesses_per_pair
    return profile.witnesses_per_mask


def _read_json_artifact(path: Path, label: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        with path.open("r", encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"cannot read {label} {path}: {exc}"
    if not isinstance(value, dict):
        return None, f"{label} must contain a JSON object: {path}"
    return value, None


def _groundtruth_artifacts_complete(
    spec: CaseSpec,
    profile: GroundTruthProfile,
    groundtruth_path: Path,
    negative_patterns_path: Path,
) -> Optional[str]:
    groundtruth, error = _read_json_artifact(groundtruth_path, "ground truth")
    if error is not None:
        return error
    assert groundtruth is not None
    if groundtruth.get("schema_version") != "v4-groundtruth-1":
        return (
            f"ground truth schema is {groundtruth.get('schema_version')!r}, "
            "expected 'v4-groundtruth-1'"
        )
    if groundtruth.get("case_id") != spec.case_id:
        return (
            f"ground truth case_id is {groundtruth.get('case_id')!r}, expected "
            f"{spec.case_id!r}"
        )
    if groundtruth.get("complete") is not True:
        return "ground truth complete is not true"

    solver = groundtruth.get("solver")
    if not isinstance(solver, dict):
        return "ground truth solver record is missing"
    expected_solver_values = {
        "witnesses_per_mask": profile.witnesses_per_mask,
        "witnesses_per_singleton": profile.witnesses_per_singleton,
        "witnesses_per_pair": profile.witnesses_per_pair,
        "witnesses_per_all": profile.witnesses_per_all,
    }
    for key, expected in expected_solver_values.items():
        if expected is None:
            if key in solver:
                return f"ground truth solver.{key} is unexpectedly present"
        elif solver.get(key) != expected:
            return (
                f"ground truth solver.{key} is {solver.get(key)!r}, expected "
                f"{expected!r}"
            )

    expected_masks = _requested_groundtruth_masks(spec.trojan_count)
    raw_mask_results = groundtruth.get("mask_results")
    if not isinstance(raw_mask_results, list):
        return "ground truth mask_results is missing"
    mask_results: Dict[str, Mapping[str, Any]] = {}
    for index, raw_result in enumerate(raw_mask_results):
        if not isinstance(raw_result, dict):
            return f"ground truth mask_results[{index}] is not an object"
        mask = raw_result.get("mask")
        if not isinstance(mask, str):
            return f"ground truth mask_results[{index}].mask is missing"
        if mask in mask_results:
            return f"ground truth has duplicate mask result {mask!r}"
        mask_results[mask] = raw_result
    if set(mask_results) != set(expected_masks):
        missing = sorted(set(expected_masks) - set(mask_results))
        extra = sorted(set(mask_results) - set(expected_masks))
        return f"ground truth mask set mismatch; missing={missing}, extra={extra}"

    expected_pattern_count = 0
    for mask in expected_masks:
        result = mask_results[mask]
        target = _groundtruth_witness_target(profile, mask)
        expected_pattern_count += target
        if result.get("status") != "sat":
            return f"ground truth mask {mask} status is {result.get('status')!r}"
        if result.get("requested_witnesses") != target:
            return (
                f"ground truth mask {mask} requested_witnesses is "
                f"{result.get('requested_witnesses')!r}, expected {target}"
            )
        if result.get("witness_count") != target:
            return (
                f"ground truth mask {mask} witness_count is "
                f"{result.get('witness_count')!r}, expected {target}"
            )
    patterns = groundtruth.get("patterns")
    if not isinstance(patterns, list) or len(patterns) != expected_pattern_count:
        return (
            "ground truth patterns length is "
            f"{len(patterns) if isinstance(patterns, list) else None!r}, expected "
            f"{expected_pattern_count}"
        )
    if groundtruth.get("pattern_count") != expected_pattern_count:
        return (
            f"ground truth pattern_count is {groundtruth.get('pattern_count')!r}, "
            f"expected {expected_pattern_count}"
        )

    if profile.hard_negatives == 0:
        return None
    negatives, error = _read_json_artifact(
        negative_patterns_path, "hard-negative ground truth"
    )
    if error is not None:
        return error
    assert negatives is not None
    if negatives.get("schema_version") != "v4-hard-negatives-1":
        return (
            f"hard-negative schema is {negatives.get('schema_version')!r}, "
            "expected 'v4-hard-negatives-1'"
        )
    if negatives.get("case_id") != spec.case_id:
        return (
            f"hard-negative case_id is {negatives.get('case_id')!r}, expected "
            f"{spec.case_id!r}"
        )
    negative_generation = negatives.get("generation")
    if not isinstance(negative_generation, dict):
        return "hard-negative generation record is missing"
    expected_negative_count = profile.hard_negatives
    if negative_generation.get("complete") is not True:
        return "hard-negative generation.complete is not true"
    for key in ("requested", "generated"):
        if negative_generation.get(key) != expected_negative_count:
            return (
                f"hard-negative generation.{key} is "
                f"{negative_generation.get(key)!r}, expected {expected_negative_count}"
            )
    negative_patterns = negatives.get("patterns")
    if not isinstance(negative_patterns, list) or len(negative_patterns) != expected_negative_count:
        return (
            "hard-negative patterns length is "
            f"{len(negative_patterns) if isinstance(negative_patterns, list) else None!r}, "
            f"expected {expected_negative_count}"
        )
    if negatives.get("pattern_count") != expected_negative_count:
        return (
            f"hard-negative pattern_count is {negatives.get('pattern_count')!r}, "
            f"expected {expected_negative_count}"
        )
    return None


def _groundtruth_command(
    spec: CaseSpec,
    profile: GroundTruthProfile,
    manifest_path: Path,
    gt_tool: Path,
    force: bool,
) -> Tuple[str, ...]:
    prefix = [sys.executable, str(gt_tool)] if gt_tool.suffix == ".py" else [str(gt_tool)]
    case_dir = manifest_path.parent
    command = prefix + [
        str(manifest_path),
        "--output",
        str(case_dir / "groundtruth.json"),
        "--negative-output",
        str(case_dir / "negative_patterns.json"),
        "--per-mask",
        str(profile.witnesses_per_mask),
    ]
    if profile.witnesses_per_singleton is not None:
        command.extend(["--per-singleton", str(profile.witnesses_per_singleton)])
    if profile.witnesses_per_pair is not None:
        command.extend(["--per-pair", str(profile.witnesses_per_pair)])
    if profile.witnesses_per_all is not None:
        command.extend(["--per-all", str(profile.witnesses_per_all)])
    command.extend(
        [
            "--hard-negatives",
            str(profile.hard_negatives),
            "--mask-set",
            "auto",
        ]
    )
    if force:
        command.append("--force")
    return tuple(command)


def run_groundtruth(
    spec: CaseSpec,
    manifest_path: Path,
    profile: GroundTruthProfile,
    gt_tool: Path,
    force: bool,
    repo_root: Path,
) -> GroundTruthResult:
    groundtruth_path = manifest_path.parent / "groundtruth.json"
    negative_patterns_path = manifest_path.parent / "negative_patterns.json"
    command = _groundtruth_command(
        spec, profile, manifest_path, gt_tool, force=force
    )

    positive_exists = groundtruth_path.exists()
    negative_exists = negative_patterns_path.exists()
    if not force and (positive_exists or negative_exists):
        completeness_error = _groundtruth_artifacts_complete(
            spec, profile, groundtruth_path, negative_patterns_path
        )
        if completeness_error is None:
            return GroundTruthResult(
                status="existing",
                profile_id=profile.profile_id,
                groundtruth_path=groundtruth_path,
                negative_patterns_path=negative_patterns_path,
                command=command,
                returncode=0,
                stdout="",
                stderr="",
            )
        return GroundTruthResult(
            status="failed",
            profile_id=profile.profile_id,
            groundtruth_path=groundtruth_path,
            negative_patterns_path=negative_patterns_path,
            command=command,
            returncode=2,
            stdout="",
            stderr="",
            error=(
                f"existing ground-truth artifacts are incomplete or use a different "
                f"profile: {completeness_error}; use --force-groundtruth to replace them"
            ),
        )

    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        return GroundTruthResult(
            status="failed",
            profile_id=profile.profile_id,
            groundtruth_path=groundtruth_path,
            negative_patterns_path=negative_patterns_path,
            command=command,
            returncode=127,
            stdout="",
            stderr="",
            error=f"cannot start ground-truth tool: {exc}",
        )

    completeness_error = _groundtruth_artifacts_complete(
        spec, profile, groundtruth_path, negative_patterns_path
    )
    if completed.returncode != 0 or completeness_error is not None:
        details: List[str] = []
        if completed.returncode != 0:
            details.append(
                f"ground-truth tool returned exit status {completed.returncode}"
            )
        if completeness_error is not None:
            details.append(completeness_error)
        return GroundTruthResult(
            status="failed",
            profile_id=profile.profile_id,
            groundtruth_path=groundtruth_path,
            negative_patterns_path=negative_patterns_path,
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            error="; ".join(details),
        )
    return GroundTruthResult(
        status="generated",
        profile_id=profile.profile_id,
        groundtruth_path=groundtruth_path,
        negative_patterns_path=negative_patterns_path,
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_case(
    spec: CaseSpec,
    repo_root: Path,
    output_root: Path,
    skip_existing: bool,
    matrix: Mapping[str, Any],
) -> CaseResult:
    command = _case_command(spec, repo_root, output_root, skip_existing, matrix)
    manifest_path = spec.manifest_path(output_root)

    if manifest_path.parent.exists():
        if not skip_existing:
            return CaseResult(
                spec=spec,
                status="failed",
                manifest_path=None,
                command=command,
                returncode=2,
                stdout="",
                stderr="",
                error=(
                    f"case directory already exists: {manifest_path.parent}; rerun "
                    "with --skip-existing after verifying it"
                ),
            )
        _, error = _read_case_manifest(manifest_path, spec)
        if error is not None:
            return CaseResult(
                spec=spec,
                status="failed",
                manifest_path=None,
                command=command,
                returncode=2,
                stdout="",
                stderr="",
                error=error,
            )
        return CaseResult(
            spec=spec,
            status="existing",
            manifest_path=manifest_path,
            command=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        return CaseResult(
            spec=spec,
            status="failed",
            manifest_path=None,
            command=command,
            returncode=127,
            stdout="",
            stderr="",
            error=f"cannot start generator: {exc}",
        )

    if completed.returncode != 0:
        return CaseResult(
            spec=spec,
            status="failed",
            manifest_path=None,
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            error="generator returned a non-zero exit status",
        )

    _, error = _read_case_manifest(manifest_path, spec)
    if error is not None:
        return CaseResult(
            spec=spec,
            status="failed",
            manifest_path=None,
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            error=error,
        )
    return CaseResult(
        spec=spec,
        status="generated",
        manifest_path=manifest_path,
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _run_specs(
    specs: Sequence[CaseSpec],
    repo_root: Path,
    output_root: Path,
    skip_existing: bool,
    jobs: int,
    matrix: Mapping[str, Any],
    generate_groundtruth: bool = False,
    groundtruth_profiles: Optional[Mapping[str, GroundTruthProfile]] = None,
    gt_tool: Optional[Path] = None,
    force_groundtruth: bool = False,
) -> List[CaseResult]:
    results: List[Optional[CaseResult]] = [None] * len(specs)
    small_specs = [spec for spec in specs if spec.size_class == "small"]
    serial_specs = [spec for spec in specs if spec.size_class != "small"]

    if generate_groundtruth and (groundtruth_profiles is None or gt_tool is None):
        raise MatrixError(
            "ground-truth generation requires resolved profiles and a GT tool"
        )

    def run_one(spec: CaseSpec) -> CaseResult:
        result = run_case(spec, repo_root, output_root, skip_existing, matrix)
        if not generate_groundtruth or result.status == "failed":
            return result
        assert result.manifest_path is not None
        assert groundtruth_profiles is not None
        assert gt_tool is not None
        profile = groundtruth_profiles[spec.groundtruth_profile]
        gt_result = run_groundtruth(
            spec=spec,
            manifest_path=result.manifest_path,
            profile=profile,
            gt_tool=gt_tool,
            force=force_groundtruth,
            repo_root=repo_root,
        )
        return replace(result, groundtruth=gt_result)

    def report(result: CaseResult) -> None:
        results[result.spec.ordinal] = result
        if result.status == "failed":
            print(
                f"FAIL      [{result.spec.ordinal + 1}/{len(specs)}] "
                f"{result.spec.phase_id}/{result.spec.case_id}: {result.error}",
                file=sys.stderr,
                flush=True,
            )
        else:
            gt_suffix = ""
            if result.groundtruth is not None:
                gt_suffix = f" / GT_{result.groundtruth.status.upper()}"
            print(
                f"{result.status.upper():9s} [{result.spec.ordinal + 1}/{len(specs)}] "
                f"{result.spec.phase_id}/{result.spec.case_id}{gt_suffix}",
                flush=True,
            )
            if (
                result.groundtruth is not None
                and result.groundtruth.status == "failed"
            ):
                print(
                    f"GT FAIL   [{result.spec.ordinal + 1}/{len(specs)}] "
                    f"{result.spec.phase_id}/{result.spec.case_id}: "
                    f"{result.groundtruth.error}",
                    file=sys.stderr,
                    flush=True,
                )

    if small_specs:
        if jobs == 1:
            for spec in small_specs:
                report(run_one(spec))
        else:
            with ThreadPoolExecutor(max_workers=jobs) as executor:
                futures: Dict[Future[CaseResult], CaseSpec] = {
                    executor.submit(
                        run_one,
                        spec,
                    ): spec
                    for spec in small_specs
                }
                for future in as_completed(futures):
                    spec = futures[future]
                    try:
                        result = future.result()
                    except BaseException as exc:  # preserve every scheduled outcome
                        result = CaseResult(
                            spec=spec,
                            status="failed",
                            manifest_path=None,
                            command=(),
                            returncode=1,
                            stdout="",
                            stderr="",
                            error=f"runner worker failed unexpectedly: {exc}",
                        )
                    report(result)

    # Large designs can consume substantial memory while being parsed and
    # rewritten, so these are deliberately excluded from the worker pool.
    for spec in serial_specs:
        report(run_one(spec))

    missing = [index for index, result in enumerate(results) if result is None]
    if missing:
        raise AssertionError(f"runner lost result(s) for ordinal(s): {missing}")
    return [result for result in results if result is not None]


def _relative_posix(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _index_record(result: CaseResult, output_root: Path) -> Dict[str, Any]:
    assert result.manifest_path is not None
    spec = result.spec
    record: Dict[str, Any] = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "case_id": spec.case_id,
        "case_manifest": _relative_posix(result.manifest_path, output_root),
        "case_manifest_sha256": _sha256_file(result.manifest_path),
        "case_manifest_size_bytes": result.manifest_path.stat().st_size,
        "phase_id": spec.phase_id,
        "split": spec.split,
        "groundtruth_profile": spec.groundtruth_profile,
        "benchmark": spec.benchmark,
        "size_class": spec.size_class,
        "generation": {
            "trojan_count": spec.trojan_count,
            "trigger_size": spec.trigger_size,
            "trigger_topology": spec.trigger_topology,
            "trigger_overlap": spec.trigger_overlap,
            "victim_placement": spec.victim_placement,
            "seed": spec.seed,
            "source_golden_sha256": spec.source_sha256,
        },
        "matrix_run_status": result.status,
    }
    if result.groundtruth is not None:
        gt_result = result.groundtruth
        gt_record: Dict[str, Any] = {
            "status": gt_result.status,
            "profile_id": gt_result.profile_id,
        }
        if gt_result.groundtruth_path.is_file():
            gt_record.update(
                {
                    "path": _relative_posix(
                        gt_result.groundtruth_path, output_root
                    ),
                    "sha256": _sha256_file(gt_result.groundtruth_path),
                    "size_bytes": gt_result.groundtruth_path.stat().st_size,
                }
            )
        if gt_result.negative_patterns_path.is_file():
            gt_record["negative_patterns"] = {
                "path": _relative_posix(
                    gt_result.negative_patterns_path, output_root
                ),
                "sha256": _sha256_file(gt_result.negative_patterns_path),
                "size_bytes": gt_result.negative_patterns_path.stat().st_size,
            }
        record["groundtruth"] = gt_record
    return record


def _failure_record(result: CaseResult) -> Dict[str, Any]:
    spec = result.spec
    return {
        "schema_version": FAILURE_SCHEMA_VERSION,
        "case_id": spec.case_id,
        "phase_id": spec.phase_id,
        "split": spec.split,
        "benchmark": spec.benchmark,
        "generation": {
            "trojan_count": spec.trojan_count,
            "trigger_size": spec.trigger_size,
            "trigger_topology": spec.trigger_topology,
            "trigger_overlap": spec.trigger_overlap,
            "victim_placement": spec.victim_placement,
            "seed": spec.seed,
        },
        "failure_category": "generator_failure",
        "error": result.error,
        "returncode": result.returncode,
        "command": list(result.command),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _groundtruth_failure_record(result: CaseResult) -> Dict[str, Any]:
    assert result.groundtruth is not None
    groundtruth = result.groundtruth
    spec = result.spec
    return {
        "schema_version": FAILURE_SCHEMA_VERSION,
        "case_id": spec.case_id,
        "phase_id": spec.phase_id,
        "split": spec.split,
        "benchmark": spec.benchmark,
        "generation": {
            "trojan_count": spec.trojan_count,
            "trigger_size": spec.trigger_size,
            "trigger_topology": spec.trigger_topology,
            "trigger_overlap": spec.trigger_overlap,
            "victim_placement": spec.victim_placement,
            "seed": spec.seed,
        },
        "groundtruth_profile": groundtruth.profile_id,
        "failure_category": "groundtruth_failure",
        "error": groundtruth.error,
        "returncode": groundtruth.returncode,
        "command": list(groundtruth.command),
        "stdout": groundtruth.stdout,
        "stderr": groundtruth.stderr,
    }


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temp_path = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temp_path = Path(raw_temp_path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temp_path, path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def _atomic_write_jsonl(path: Path, records: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temp_path = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temp_path = Path(raw_temp_path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            for record in records:
                json.dump(record, output, sort_keys=True, separators=(",", ":"))
                output.write("\n")
        os.replace(temp_path, path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def _write_aggregate_files(
    results: Sequence[CaseResult],
    matrix: Mapping[str, Any],
    config_path: Path,
    repo_root: Path,
    output_root: Path,
    jobs: int,
    skip_existing: bool,
    groundtruth_requested: bool = False,
    gt_tool: Optional[Path] = None,
    force_groundtruth: bool = False,
) -> Tuple[Path, Path, Path, Path]:
    successful = [result for result in results if result.status != "failed"]
    failures = [result for result in results if result.status == "failed"]
    groundtruth_failures = [
        result
        for result in results
        if result.groundtruth is not None and result.groundtruth.status == "failed"
    ]
    index_records = [_index_record(result, output_root) for result in successful]
    failure_records = [_failure_record(result) for result in failures]
    groundtruth_failure_records = [
        _groundtruth_failure_record(result) for result in groundtruth_failures
    ]

    phase_summaries: Dict[str, Dict[str, int]] = {}
    for result in results:
        summary = phase_summaries.setdefault(
            result.spec.phase_id,
            {"scheduled": 0, "generated": 0, "existing": 0, "failed": 0},
        )
        summary["scheduled"] += 1
        summary[result.status] += 1
        if groundtruth_requested:
            if result.groundtruth is None:
                summary["groundtruth_not_attempted"] = (
                    summary.get("groundtruth_not_attempted", 0) + 1
                )
            else:
                key = f"groundtruth_{result.groundtruth.status}"
                summary[key] = summary.get(key, 0) + 1

    index_path = output_root / "dataset_index.jsonl"
    failure_path = output_root / "generation_failures.jsonl"
    groundtruth_failure_path = output_root / "groundtruth_failures.jsonl"
    manifest_path = output_root / "dataset_manifest.json"
    _atomic_write_jsonl(index_path, index_records)
    _atomic_write_jsonl(failure_path, failure_records)
    _atomic_write_jsonl(groundtruth_failure_path, groundtruth_failure_records)

    selected_phase_ids = list(dict.fromkeys(result.spec.phase_id for result in results))
    generator_path = repo_root / "generate_multi_trojan_dataset.py"
    summary_record: Dict[str, Any] = {
        "scheduled": len(results),
        "generated": sum(result.status == "generated" for result in results),
        "existing": sum(result.status == "existing" for result in results),
        "failed": len(failures),
        "indexed": len(index_records),
    }
    if groundtruth_requested:
        summary_record["groundtruth"] = {
            "requested": len(results),
            "generated": sum(
                result.groundtruth is not None
                and result.groundtruth.status == "generated"
                for result in results
            ),
            "existing": sum(
                result.groundtruth is not None
                and result.groundtruth.status == "existing"
                for result in results
            ),
            "failed": len(groundtruth_failures),
            "not_attempted_due_to_generation_failure": sum(
                result.groundtruth is None for result in results
            ),
        }

    execution_record: Dict[str, Any] = {
        "jobs_for_small_circuits": jobs,
        "non_small_circuits_run_serially": True,
        "skip_existing": skip_existing,
        "generate_groundtruth": groundtruth_requested,
    }
    if groundtruth_requested:
        execution_record["force_groundtruth"] = force_groundtruth

    aggregate: Dict[str, Any] = {
        "schema_version": RUNNER_SCHEMA_VERSION,
        "dataset_schema_version": matrix.get("dataset_schema_version"),
        "matrix_schema_version": matrix.get("schema_version"),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "matrix": {
            "path": config_path.resolve().relative_to(repo_root.resolve()).as_posix()
            if config_path.resolve().is_relative_to(repo_root.resolve())
            else str(config_path.resolve()),
            "sha256": _sha256_file(config_path),
            "selected_phases": selected_phase_ids,
        },
        "generator": {
            "path": generator_path.relative_to(repo_root).as_posix(),
            "sha256": _sha256_file(generator_path),
        },
        "execution": execution_record,
        "summary": summary_record,
        "phases": phase_summaries,
        "files": {
            "index": index_path.name,
            "failures": failure_path.name,
            "groundtruth_failures": groundtruth_failure_path.name,
        },
        "cases": index_records,
    }
    if groundtruth_requested and gt_tool is not None:
        aggregate["groundtruth_tool"] = {
            "path": gt_tool.resolve().relative_to(repo_root.resolve()).as_posix()
            if gt_tool.resolve().is_relative_to(repo_root.resolve())
            else str(gt_tool.resolve()),
            "sha256": _sha256_file(gt_tool),
        }
    _atomic_write_json(manifest_path, aggregate)
    return manifest_path, index_path, failure_path, groundtruth_failure_path


def _print_dry_run(
    specs: Sequence[CaseSpec],
    expected_by_phase: Mapping[str, int],
    jobs: int,
    groundtruth_profiles: Optional[Mapping[str, GroundTruthProfile]] = None,
) -> None:
    print("DRY RUN: no generator processes will be started and no files will be written.")
    print(f"Scheduled cases: {len(specs)}")
    for phase_id, count in expected_by_phase.items():
        print(f"  {phase_id}: {count}")
    small_count = sum(spec.size_class == "small" for spec in specs)
    print(f"Small cases (up to {jobs} concurrent): {small_count}")
    print(f"Non-small cases (serial): {len(specs) - small_count}")
    if groundtruth_profiles is not None:
        print("Ground-truth stage: enabled")
        for profile_id, profile in groundtruth_profiles.items():
            case_count = sum(
                spec.groundtruth_profile == profile_id for spec in specs
            )
            overrides = []
            if profile.witnesses_per_singleton is not None:
                overrides.append(
                    f"singleton={profile.witnesses_per_singleton}"
                )
            if profile.witnesses_per_pair is not None:
                overrides.append(f"pair={profile.witnesses_per_pair}")
            if profile.witnesses_per_all is not None:
                overrides.append(f"all={profile.witnesses_per_all}")
            override_text = f", {', '.join(overrides)}" if overrides else ""
            print(
                f"  {profile_id}: cases={case_count}, per-mask="
                f"{profile.witnesses_per_mask}{override_text}, hard-negatives="
                f"{profile.hard_negatives}"
            )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate cases from configs/multi_trojan_experiment_matrix.json and "
            "build an aggregate dataset index. Repeat --phase to select more than "
            "one enabled phase; all enabled phases are selected by default."
        )
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="experiment matrix JSON relative to the repository root",
    )
    parser.add_argument(
        "--phase",
        action="append",
        metavar="ID",
        help="enabled phase to run; may be repeated (default: all enabled phases)",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="dataset output root relative to the repository root",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and count selected matrix cells without writing files",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="validate and index matching existing cases instead of failing",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        metavar="N",
        help="parallel generator processes for size_class=small (default: 1)",
    )
    parser.add_argument(
        "--generate-groundtruth",
        action="store_true",
        help=(
            "after each case manifest succeeds, generate profile-specific SAT "
            "ground truth in the same worker slot"
        ),
    )
    parser.add_argument(
        "--gt-tool",
        type=Path,
        default=Path("bin/script/generate_multi_gt"),
        help=(
            "ground-truth executable or Python script relative to the repository "
            "root (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--force-groundtruth",
        action="store_true",
        help=(
            "regenerate groundtruth.json and negative_patterns.json even when "
            "complete profile-matching artifacts already exist"
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error("--jobs must be at least 1")
    if args.force_groundtruth and not args.generate_groundtruth:
        parser.error("--force-groundtruth requires --generate-groundtruth")

    repo_root = Path(__file__).resolve().parent.parent
    config_path = args.config.expanduser()
    if not config_path.is_absolute():
        config_path = repo_root / config_path
    output_root = args.output_root.expanduser()
    if not output_root.is_absolute():
        output_root = repo_root / output_root
    config_path = config_path.resolve()
    output_root = output_root.resolve()
    gt_tool = args.gt_tool.expanduser()
    if not gt_tool.is_absolute():
        gt_tool = repo_root / gt_tool
    gt_tool = gt_tool.resolve()

    try:
        matrix = _load_json(config_path)
        specs, expected_by_phase = expand_matrix(matrix, repo_root, args.phase)
        groundtruth_profiles = (
            _selected_groundtruth_profiles(specs, matrix)
            if args.generate_groundtruth
            else None
        )
        if args.dry_run:
            _print_dry_run(
                specs,
                expected_by_phase,
                args.jobs,
                groundtruth_profiles=groundtruth_profiles,
            )
            return 0

        selected_phase_ids = list(
            dict.fromkeys(spec.phase_id for spec in specs)
        )
        _guard_existing_aggregate_scope(
            output_root,
            selected_phase_ids,
            phase_filter_active=bool(args.phase),
        )

        generator_path = repo_root / "generate_multi_trojan_dataset.py"
        if not generator_path.is_file():
            raise MatrixError(f"generator does not exist: {generator_path}")
        if args.generate_groundtruth:
            if not gt_tool.is_file():
                raise MatrixError(f"ground-truth tool does not exist: {gt_tool}")
            if gt_tool.suffix != ".py" and not os.access(gt_tool, os.X_OK):
                raise MatrixError(f"ground-truth tool is not executable: {gt_tool}")
        _verify_selected_benchmarks(specs)
        output_root.mkdir(parents=True, exist_ok=True)
        results = _run_specs(
            specs=specs,
            repo_root=repo_root,
            output_root=output_root,
            skip_existing=args.skip_existing,
            jobs=args.jobs,
            matrix=matrix,
            generate_groundtruth=args.generate_groundtruth,
            groundtruth_profiles=groundtruth_profiles,
            gt_tool=gt_tool if args.generate_groundtruth else None,
            force_groundtruth=args.force_groundtruth,
        )
        (
            manifest_path,
            index_path,
            failure_path,
            groundtruth_failure_path,
        ) = _write_aggregate_files(
            results=results,
            matrix=matrix,
            config_path=config_path,
            repo_root=repo_root,
            output_root=output_root,
            jobs=args.jobs,
            skip_existing=args.skip_existing,
            groundtruth_requested=args.generate_groundtruth,
            gt_tool=gt_tool if args.generate_groundtruth else None,
            force_groundtruth=args.force_groundtruth,
        )
    except MatrixError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    failure_count = sum(result.status == "failed" for result in results)
    generated_count = sum(result.status == "generated" for result in results)
    existing_count = sum(result.status == "existing" for result in results)
    groundtruth_failure_count = sum(
        result.groundtruth is not None and result.groundtruth.status == "failed"
        for result in results
    )
    print(
        f"Done: scheduled={len(results)}, generated={generated_count}, "
        f"existing={existing_count}, failed={failure_count}"
    )
    print(f"Manifest: {manifest_path}")
    print(f"Index: {index_path}")
    print(f"Failures: {failure_path}")
    if args.generate_groundtruth:
        groundtruth_generated_count = sum(
            result.groundtruth is not None
            and result.groundtruth.status == "generated"
            for result in results
        )
        groundtruth_existing_count = sum(
            result.groundtruth is not None
            and result.groundtruth.status == "existing"
            for result in results
        )
        print(
            "Ground truth: "
            f"generated={groundtruth_generated_count}, "
            f"existing={groundtruth_existing_count}, "
            f"failed={groundtruth_failure_count}"
        )
        print(f"Ground-truth failures: {groundtruth_failure_path}")
    return 1 if failure_count or groundtruth_failure_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
