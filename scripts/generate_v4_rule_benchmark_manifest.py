#!/usr/bin/env python3
"""Generate a deterministic rule-repair manifest for the V4 dataset.

The V4 dataset stores every generated case in its own directory, while the
existing rule-method runner intentionally uses the older V0 path convention.
This script projects the validated V4 index into that stable runner schema.
Use ``materialize_v4_benchmark_inputs.py`` afterwards to hardlink only the
immutable golden, combined, and ground-truth artifacts into the projected
layout.

Only cases in ``final_gt_ready_index.jsonl`` are runnable.  Rejected cases are
kept in manifest inventory metadata, so the dataset-generation denominator is
not silently changed into a repair success denominator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Sequence


READY_SCHEMA = "v4-gt-ready-case-index/1"
MANIFEST_SCHEMA = "rule-method-ab-cases/1"
SAFE_COMPONENT_RE = re.compile(r"[A-Za-z0-9_.-]+")
DEFAULT_COMMON_ARGS = [
    "--depth", "10", "--neg-ratio", "50",
    "--mine-rounds", "15", "--mine-max", "5000",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"{label} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise RuntimeError(f"unsafe {label}: {value!r}")
    return path


def _safe_component(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or value in {".", ".."}
        or SAFE_COMPONENT_RE.fullmatch(value) is None
    ):
        raise RuntimeError(f"unsafe {label}: {value!r}")
    return value


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, raw in enumerate(stream, start=1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"cannot parse {path}:{line_number}: {exc}"
                ) from exc
            if not isinstance(row, dict):
                raise RuntimeError(f"{path}:{line_number} is not an object")
            rows.append(row)
    return rows


def _read_matrix_size_classes(matrix_path: Path | None) -> Dict[str, str]:
    if matrix_path is None:
        return {}
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    catalog = matrix.get("benchmark_catalog")
    if not isinstance(catalog, dict):
        raise RuntimeError("experiment matrix lacks benchmark_catalog")
    result: Dict[str, str] = {}
    for benchmark, metadata in catalog.items():
        if not isinstance(metadata, dict):
            raise RuntimeError(f"invalid benchmark metadata for {benchmark}")
        result[_safe_component(benchmark, "benchmark name")] = _safe_component(
            metadata.get("size_class"), f"size class for {benchmark}"
        )
    return result


def _require_file(root: Path, relative: Path, label: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeError(f"{label} escapes V4 root: {relative}") from exc
    if not path.is_file():
        raise RuntimeError(f"missing {label}: {path}")
    return path


def _profile_add(profiles: Dict[str, List[str]], name: str, case_id: str) -> None:
    profiles.setdefault(name, []).append(case_id)


def _select_smallest(
    cases: Sequence[Mapping[str, Any]],
    *,
    phase: str,
    trojan_count: int,
    trigger_size: int | None = None,
    size_class: str | None = None,
    topology: str | None = None,
) -> str | None:
    eligible = []
    for case in cases:
        metadata = case["v4"]
        if metadata["phase_id"] != phase:
            continue
        if metadata["trojan_count"] != trojan_count:
            continue
        if trigger_size is not None and metadata["trigger_size"] != trigger_size:
            continue
        if size_class is not None and metadata["size_class"] != size_class:
            continue
        if topology is not None and metadata["trigger_topology"] != topology:
            continue
        eligible.append(case)
    if not eligible:
        return None
    return min(
        eligible,
        key=lambda case: (case["v4"]["source_total_bytes"], case["case_id"]),
    )["case_id"]


def _add_fresh_paper_profile(
    cases: Sequence[Mapping[str, Any]],
    profiles: Dict[str, List[str]],
    experiment_matrix_sha256: str | None,
) -> None:
    """Pre-register a result-blind, stratified multi-Trojan evaluation cohort.

    The profile deliberately excludes every diagnostic smoke case.  Selection
    uses only immutable dataset metadata and a declared matrix hash, never a
    repair result, runtime, or generated patch.
    """
    if not experiment_matrix_sha256:
        return
    smoke_ids = set(profiles.get("smoke_extended", []))
    eligible = [case for case in cases if case["case_id"] not in smoke_ids]
    required_phases = {
        "core_final", "heldout_ood", "shared_trigger_challenge",
        "five_trojan_stress",
    }
    present_phases = {case["v4"]["phase_id"] for case in eligible}
    # Small synthetic fixtures and partial manifests intentionally do not
    # expose a paper cohort.  A full-looking dataset must satisfy the exact
    # pre-registered cell count below, so real inventory drift still fails.
    if not required_phases.issubset(present_phases):
        return

    def rank(case: Mapping[str, Any]) -> tuple[str, str]:
        case_id = str(case["case_id"])
        digest = hashlib.sha256(
            (experiment_matrix_sha256 + "\0" + case_id).encode("utf-8")
        ).hexdigest()
        return digest, case_id

    def select_groups(
        phase: str, group_fields: Sequence[str], count: int
    ) -> List[str]:
        groups: Dict[tuple[Any, ...], List[Mapping[str, Any]]] = {}
        for case in eligible:
            metadata = case["v4"]
            if metadata["phase_id"] != phase:
                continue
            values = []
            for field in group_fields:
                values.append(case[field] if field in case else metadata[field])
            groups.setdefault(tuple(values), []).append(case)
        selected: List[str] = []
        for key in sorted(groups, key=lambda value: tuple(map(str, value))):
            selected.extend(
                str(case["case_id"])
                for case in sorted(groups[key], key=rank)[:count]
            )
        return selected

    selected = []
    selected.extend(
        select_groups(
            "core_final", ("circuit", "trojan_count", "trigger_size"), 1
        )
    )
    selected.extend(
        select_groups("heldout_ood", ("circuit", "trojan_count"), 2)
    )
    selected.extend(
        select_groups(
            "shared_trigger_challenge",
            ("circuit", "trojan_count", "trigger_size"),
            1,
        )
    )
    selected.extend(sorted(
        str(case["case_id"])
        for case in eligible
        if case["v4"]["phase_id"] == "five_trojan_stress"
    ))
    if len(selected) != 81 or len(set(selected)) != 81:
        raise RuntimeError(
            "fresh paper profile requires exactly 81 unique V4 cases"
        )
    if set(selected) & smoke_ids:
        raise RuntimeError("fresh paper profile overlaps diagnostic smoke cases")
    profiles["paper_fresh_stratified_81"] = selected


def build_manifest(
    source_root: Path,
    projected_root: Path,
    timeout_seconds: float,
    matrix_path: Path | None = None,
) -> Dict[str, Any]:
    source_root = source_root.resolve()
    projected_root = projected_root
    if projected_root.is_absolute() or ".." in projected_root.parts:
        raise RuntimeError("projected_root must be a safe repository-relative path")
    if timeout_seconds <= 0:
        raise RuntimeError("timeout_seconds must be positive")

    ready_index = source_root / "validation/final_gt_ready_index.jsonl"
    rejected_index = source_root / "validation/final_rejected_cases.jsonl"
    if not ready_index.is_file():
        raise RuntimeError(f"missing ready index: {ready_index}")
    if not rejected_index.is_file():
        raise RuntimeError(f"missing rejected index: {rejected_index}")
    size_classes = _read_matrix_size_classes(matrix_path)
    ready_rows = _load_jsonl(ready_index)
    rejected_rows = _load_jsonl(rejected_index)
    if not ready_rows:
        raise RuntimeError("V4 ready index is empty")

    cases: List[Dict[str, Any]] = []
    profiles: Dict[str, List[str]] = {"all_ready": []}
    seen_ids = set()
    source_golden_by_benchmark: Dict[str, str] = {}
    for ordinal, row in enumerate(sorted(ready_rows, key=lambda item: item["case_id"])):
        if row.get("schema_version") != READY_SCHEMA:
            raise RuntimeError(
                f"unsupported ready schema for {row.get('case_id')}: "
                f"{row.get('schema_version')!r}"
            )
        if row.get("status") != "gt_ready":
            raise RuntimeError(f"non-ready row in ready index: {row.get('case_id')}")
        case_id = _safe_component(row.get("case_id"), "case_id")
        benchmark = _safe_component(row.get("benchmark"), "benchmark")
        if case_id in seen_ids:
            raise RuntimeError(f"duplicate ready case_id: {case_id}")
        seen_ids.add(case_id)
        artifacts = row.get("artifacts")
        generation = row.get("generation")
        validation = row.get("validation")
        if not isinstance(artifacts, dict) or not isinstance(generation, dict):
            raise RuntimeError(f"missing artifact/generation metadata for {case_id}")
        if not isinstance(validation, dict):
            raise RuntimeError(f"missing validation metadata for {case_id}")

        gt_rel = _safe_relative(artifacts.get("groundtruth"), "groundtruth path")
        manifest_rel = _safe_relative(
            artifacts.get("case_manifest"), "case manifest path"
        )
        case_dir = gt_rel.parent
        if manifest_rel.parent != case_dir:
            raise RuntimeError(f"artifact directories disagree for {case_id}")
        gt_path = _require_file(source_root, gt_rel, "groundtruth")
        case_manifest_path = _require_file(source_root, manifest_rel, "case manifest")
        combined_path = _require_file(source_root, case_dir / "combined.bench", "combined")
        golden_path = _require_file(source_root, case_dir / "golden.bench", "golden")

        expected_gt_sha = artifacts.get("groundtruth_sha256")
        expected_manifest_sha = artifacts.get("case_manifest_sha256")
        if expected_gt_sha != _sha256(gt_path):
            raise RuntimeError(f"groundtruth SHA mismatch for {case_id}")
        if expected_manifest_sha != _sha256(case_manifest_path):
            raise RuntimeError(f"case-manifest SHA mismatch for {case_id}")
        groundtruth = json.loads(gt_path.read_text(encoding="utf-8"))
        pi_order = groundtruth.get("pi_order")
        patterns = groundtruth.get("patterns")
        if groundtruth.get("complete") is not True:
            raise RuntimeError(f"groundtruth is not complete for {case_id}")
        if not isinstance(pi_order, list) or not pi_order:
            raise RuntimeError(f"groundtruth lacks pi_order for {case_id}")
        if not isinstance(patterns, list) or not patterns:
            raise RuntimeError(f"groundtruth lacks positive patterns for {case_id}")
        if groundtruth.get("pattern_count") != len(patterns):
            raise RuntimeError(f"groundtruth pattern_count mismatch for {case_id}")
        for pattern_index, pattern in enumerate(patterns):
            bits = pattern.get("pattern_bits") if isinstance(pattern, dict) else None
            if (
                not isinstance(bits, str)
                or len(bits) != len(pi_order)
                or any(bit not in "01" for bit in bits)
            ):
                raise RuntimeError(
                    f"invalid pattern_bits for {case_id} pattern {pattern_index}"
                )
        case_manifest = json.loads(case_manifest_path.read_text(encoding="utf-8"))
        file_metadata = case_manifest.get("files")
        if not isinstance(file_metadata, dict):
            raise RuntimeError(f"case manifest lacks files metadata: {case_id}")
        combined_sha = file_metadata.get("combined.bench", {}).get("sha256")
        golden_sha = file_metadata.get("golden.bench", {}).get("sha256")
        if combined_sha != _sha256(combined_path):
            raise RuntimeError(f"combined SHA mismatch for {case_id}")
        if golden_sha != _sha256(golden_path):
            raise RuntimeError(f"golden SHA mismatch for {case_id}")
        prior_golden = source_golden_by_benchmark.setdefault(benchmark, golden_sha)
        if prior_golden != golden_sha:
            raise RuntimeError(f"benchmark {benchmark} has multiple golden netlists")

        phase = _safe_component(row.get("phase_id"), "phase_id")
        split = _safe_component(row.get("split"), "split")
        topology = _safe_component(
            generation.get("trigger_topology"), "trigger_topology"
        )
        trojan_count = generation.get("trojan_count")
        trigger_size = generation.get("trigger_size")
        seed = generation.get("seed")
        pattern_count = validation.get("positive_pattern_count")
        if not isinstance(trojan_count, int) or trojan_count <= 0:
            raise RuntimeError(f"invalid Trojan count for {case_id}")
        if not isinstance(trigger_size, int) or trigger_size <= 0:
            raise RuntimeError(f"invalid trigger size for {case_id}")
        if not isinstance(seed, int):
            raise RuntimeError(f"invalid seed for {case_id}")
        if not isinstance(pattern_count, int) or pattern_count <= 0:
            raise RuntimeError(f"invalid positive pattern count for {case_id}")
        if pattern_count != len(patterns):
            raise RuntimeError(f"index/groundtruth pattern count mismatch for {case_id}")
        size_class = size_classes.get(benchmark, "unclassified")
        _safe_component(size_class, f"size class for {case_id}")
        cohort = f"v4_{phase}_{size_class}"

        case = {
            "case_id": case_id,
            "circuit": benchmark,
            "trojan": case_id,
            "cohort": cohort,
            "timeout_seconds": timeout_seconds,
            "groundtruth_pattern_count": pattern_count,
            "scheduled_ordinal": ordinal,
            "legacy_v6": {},
            "v4": {
                "source_case_dir": str(case_dir),
                "source_groundtruth": str(gt_rel),
                "source_case_manifest": str(manifest_rel),
                "source_combined_sha256": combined_sha,
                "source_golden_sha256": golden_sha,
                "source_groundtruth_sha256": expected_gt_sha,
                "source_combined_size_bytes": combined_path.stat().st_size,
                "source_groundtruth_size_bytes": gt_path.stat().st_size,
                "source_total_bytes": combined_path.stat().st_size + gt_path.stat().st_size,
                "phase_id": phase,
                "split": split,
                "size_class": size_class,
                "trojan_count": trojan_count,
                "trigger_size": trigger_size,
                "trigger_topology": topology,
                "seed": seed,
                "positive_pattern_count": pattern_count,
                "hard_negative_count": validation.get("hard_negative_count"),
            },
        }
        cases.append(case)
        for profile in dict.fromkeys((
            "all_ready", phase, split, f"n{trojan_count}",
            f"trigger_t{trigger_size}", topology, size_class,
        )):
            _profile_add(profiles, profile, case_id)
        _profile_add(profiles, f"{phase}_n{trojan_count}", case_id)
        _profile_add(profiles, f"{phase}_t{trigger_size}", case_id)
        if phase == "core_final":
            _profile_add(profiles, f"core_{size_class}", case_id)

    smoke_specs = [
        # Fast smoke: all N/trigger-size boundaries plus shared and N=5.
        ("core_final", 1, 3, "small", "disjoint"),
        ("core_final", 1, 5, "small", "disjoint"),
        ("core_final", 2, 3, "small", "disjoint"),
        ("core_final", 2, 5, "small", "disjoint"),
        ("core_final", 3, 3, "small", "disjoint"),
        ("core_final", 3, 5, "small", "disjoint"),
        ("shared_trigger_challenge", 2, 3, "small", "shared_trigger_literals"),
        ("shared_trigger_challenge", 3, 5, "small", "shared_trigger_literals"),
        ("five_trojan_stress", 5, 5, "small", "disjoint"),
        # Extended smoke: medium-scale and held-out large OOD transfer.
        ("core_final", 2, 5, "medium", "disjoint"),
        ("core_final", 3, 5, "medium", "disjoint"),
        ("heldout_ood", 2, 5, "large_ood", "disjoint"),
        ("heldout_ood", 3, 5, "large_ood", "disjoint"),
    ]
    smoke_ids: List[str] = []
    for phase, count, trigger_size, size_class, topology in smoke_specs:
        selected = _select_smallest(
            cases,
            phase=phase,
            trojan_count=count,
            trigger_size=trigger_size,
            size_class=size_class,
            topology=topology,
        )
        if selected is not None and selected not in smoke_ids:
            smoke_ids.append(selected)
    if smoke_ids:
        profiles["smoke_fast"] = smoke_ids[:9]
        profiles["smoke_extended"] = smoke_ids

    matrix_sha256 = _sha256(matrix_path) if matrix_path else None
    _add_fresh_paper_profile(cases, profiles, matrix_sha256)

    rejected_ids = []
    rejected_categories: Dict[str, int] = {}
    for row in rejected_rows:
        case_id = _safe_component(row.get("case_id"), "rejected case_id")
        if case_id in seen_ids:
            raise RuntimeError(f"case appears in ready and rejected indices: {case_id}")
        rejected_ids.append(case_id)
        category = _safe_component(
            row.get("failure_category"), f"failure category for {case_id}"
        )
        rejected_categories[category] = rejected_categories.get(category, 0) + 1

    for values in profiles.values():
        values.sort()
    profile_metadata: Dict[str, Dict[str, Any]] = {}
    paper_profile = profiles.get("paper_fresh_stratified_81")
    if paper_profile:
        encoded_ids = "".join(f"{case_id}\n" for case_id in paper_profile).encode()
        profile_metadata["paper_fresh_stratified_81"] = {
            "case_count": len(paper_profile),
            "case_ids_sha256": hashlib.sha256(encoded_ids).hexdigest(),
            "excluded_profile": "smoke_extended",
            "selection_uses_outcomes": False,
            "selection_salt": matrix_sha256,
            "selection": (
                "core: rank-min 1 per (circuit,N,trigger_size); "
                "heldout OOD: rank-min 2 per (circuit,N); shared-trigger: "
                "rank-min 1 per (circuit,N,trigger_size); N=5 stress: all "
                "remaining ready cases; rank=SHA256(matrix_sha256,case_id)"
            ),
        }
    projected = str(projected_root)
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "description": (
            "Validated V4 multi-Trojan cases projected into the immutable "
            "input layout used by compare_rule_methods.py."
        ),
        "dataset": {
            "golden_root": f"{projected}/golden",
            "trojan_root": f"{projected}/trojan",
            "groundtruth_root": f"{projected}/groundtruth",
        },
        "common_args": list(DEFAULT_COMMON_ARGS),
        "source": {
            "dataset_root": str(source_root),
            "ready_index": str(ready_index.relative_to(source_root)),
            "ready_index_sha256": _sha256(ready_index),
            "rejected_index": str(rejected_index.relative_to(source_root)),
            "rejected_index_sha256": _sha256(rejected_index),
            "experiment_matrix": str(matrix_path.resolve()) if matrix_path else None,
            "experiment_matrix_sha256": matrix_sha256,
        },
        "inventory": {
            "scheduled_count": len(cases) + len(rejected_ids),
            "ready_count": len(cases),
            "rejected_count": len(rejected_ids),
            "rejected_case_ids": sorted(rejected_ids),
            "rejected_categories": dict(sorted(rejected_categories.items())),
        },
        "profiles": dict(sorted(profiles.items())),
        "profile_metadata": profile_metadata,
        "cases": cases,
    }
    return manifest


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--projected-root", type=Path,
        default=Path("validation/v4_rule_benchmark_inputs"),
    )
    parser.add_argument("--experiment-matrix", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    args = parser.parse_args()
    matrix = args.experiment_matrix.resolve() if args.experiment_matrix else None
    payload = build_manifest(
        args.source_root,
        args.projected_root,
        args.timeout_seconds,
        matrix,
    )
    output = args.output.resolve()
    _write_atomic(output, payload)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    inventory = payload["inventory"]
    print(
        f"manifest={output} sha256={digest} "
        f"scheduled={inventory['scheduled_count']} "
        f"ready={inventory['ready_count']} "
        f"rejected={inventory['rejected_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
