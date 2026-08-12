#!/usr/bin/env python3
"""Hardlink validated V4 inputs into the rule-runner's immutable layout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable


SAFE_COMPONENT_RE = re.compile(r"[A-Za-z0-9_.-]+")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _resolve_relative(root: Path, value: str, label: str) -> Path:
    if not value or value == ".":
        raise RuntimeError(f"{label} must be a non-empty relative path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError(f"unsafe {label}: {value!r}")
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeError(f"{label} escapes root: {value!r}") from exc
    return resolved


def _safe_component(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or value in {".", ".."}
        or SAFE_COMPONENT_RE.fullmatch(value) is None
    ):
        raise RuntimeError(f"unsafe {label}: {value!r}")
    return value


def _link_verified(
    source: Path,
    target: Path,
    expected_sha256: str,
    *,
    allow_equivalent_existing: bool = False,
) -> bool:
    if not source.is_file():
        raise RuntimeError(f"missing source artifact: {source}")
    if _sha256(source) != expected_sha256:
        raise RuntimeError(f"source SHA mismatch: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        source_stat = source.stat()
        target_stat = target.stat()
        if (
            target.is_file()
            and source_stat.st_dev == target_stat.st_dev
            and source_stat.st_ino == target_stat.st_ino
        ):
            return False
        # V4 stores one byte-identical golden file inside every case directory.
        # The projected layout intentionally keeps one canonical golden per
        # benchmark, so later cases may refer to an equivalent source inode.
        if allow_equivalent_existing and target.is_file():
            if _sha256(target) == expected_sha256:
                return False
        raise RuntimeError(
            f"existing target is not the declared source hardlink: {target}"
        )
    os.link(source, target)
    return True


def _selected_cases(manifest: Dict[str, Any], profile: str) -> Iterable[Dict[str, Any]]:
    profiles = manifest.get("profiles")
    cases = manifest.get("cases")
    if not isinstance(profiles, dict) or not isinstance(cases, list):
        raise RuntimeError("malformed manifest")
    selected = profiles.get(profile)
    if not isinstance(selected, list) or not selected:
        raise RuntimeError(f"missing or empty profile: {profile}")
    by_id = {case.get("case_id"): case for case in cases if isinstance(case, dict)}
    for case_id in selected:
        if case_id not in by_id:
            raise RuntimeError(f"profile references unknown case: {case_id}")
        yield by_id[case_id]


def materialize(
    source_root: Path,
    target_repo_root: Path,
    manifest: Dict[str, Any],
    profile: str,
) -> tuple[int, int]:
    source_root = source_root.resolve()
    target_repo_root = target_repo_root.resolve()
    dataset = manifest.get("dataset")
    if not isinstance(dataset, dict):
        raise RuntimeError("manifest lacks dataset roots")
    golden_root = _resolve_relative(
        target_repo_root, str(dataset.get("golden_root", "")), "golden_root"
    )
    trojan_root = _resolve_relative(
        target_repo_root, str(dataset.get("trojan_root", "")), "trojan_root"
    )
    gt_root = _resolve_relative(
        target_repo_root,
        str(dataset.get("groundtruth_root", "")),
        "groundtruth_root",
    )

    created = 0
    reused = 0
    for case in _selected_cases(manifest, profile):
        case_id = _safe_component(case.get("case_id"), "case_id")
        benchmark = _safe_component(case.get("circuit"), "circuit")
        metadata = case.get("v4")
        if not isinstance(metadata, dict):
            raise RuntimeError(f"case lacks V4 source metadata: {case_id}")
        case_dir = _resolve_relative(
            source_root, str(metadata.get("source_case_dir", "")), "source_case_dir"
        )
        sources = (
            (
                case_dir / "golden.bench",
                golden_root / f"{benchmark}.bench",
                str(metadata["source_golden_sha256"]),
                True,
            ),
            (
                case_dir / "combined.bench",
                trojan_root / benchmark / f"{case_id}.bench",
                str(metadata["source_combined_sha256"]),
                False,
            ),
            (
                case_dir / "groundtruth.json",
                gt_root / benchmark / f"{case_id}_error_patterns.json",
                str(metadata["source_groundtruth_sha256"]),
                False,
            ),
        )
        for source, target, digest, allow_equivalent in sources:
            if _link_verified(
                source,
                target,
                digest,
                allow_equivalent_existing=allow_equivalent,
            ):
                created += 1
            else:
                reused += 1
    return created, reused


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--target-repo-root", type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--profile", default="all_ready")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    created, reused = materialize(
        args.source_root, args.target_repo_root, manifest, args.profile
    )
    print(
        f"materialized={created} reused={reused} profile={args.profile} "
        f"source={args.source_root.resolve()} "
        f"target={args.target_repo_root.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
