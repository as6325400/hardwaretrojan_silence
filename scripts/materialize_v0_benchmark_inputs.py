#!/usr/bin/env python3
"""Hardlink only the declared V0 source artifacts into another worktree.

The repair flow may create ``*_rule_merged.bench`` beside a Trojan netlist, so
linking whole directories is unsafe.  This helper materializes only immutable
golden, Trojan, and ground-truth inputs listed by the experiment manifest.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Iterable


def _link(source: Path, target: Path) -> None:
    if not source.is_file():
        raise RuntimeError(f"missing source artifact: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        source_stat, target_stat = source.stat(), target.stat()
        if (
            source_stat.st_dev == target_stat.st_dev
            and source_stat.st_ino == target_stat.st_ino
        ):
            return
        raise RuntimeError(f"target exists but is not the source hardlink: {target}")
    os.link(source, target)


def _cases(manifest: dict, profile: str) -> Iterable[dict]:
    by_id = {case["case_id"]: case for case in manifest["cases"]}
    for case_id in manifest["profiles"][profile]:
        yield by_id[case_id]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--profile", default="runnable")
    args = parser.parse_args()
    source_root = args.source_root.resolve()
    target_root = args.target_root.resolve()
    manifest = json.loads(args.manifest.read_text())
    roots = manifest["dataset"]
    golden_root = Path(roots["golden_root"])
    trojan_root = Path(roots["trojan_root"])
    groundtruth_root = Path(roots["groundtruth_root"])
    linked = 0
    golden_seen = set()
    for case in _cases(manifest, args.profile):
        circuit, trojan = case["circuit"], case["trojan"]
        golden_rel = golden_root / f"{circuit}.bench"
        if golden_rel not in golden_seen:
            _link(source_root / golden_rel, target_root / golden_rel)
            golden_seen.add(golden_rel)
            linked += 1
        trojan_rel = trojan_root / circuit / f"{trojan}.bench"
        gt_rel = groundtruth_root / circuit / f"{trojan}_error_patterns.json"
        _link(source_root / trojan_rel, target_root / trojan_rel)
        _link(source_root / gt_rel, target_root / gt_rel)
        linked += 2
    print(
        f"materialized={linked} profile={args.profile} "
        f"source={source_root} target={target_root}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
