#!/usr/bin/env python3
"""Generate a deterministic full-V0 manifest for compare_rule_methods.py.

The historical V0 ground-truth JSON files can be very large and store
``pattern_count`` near the end.  This helper reads only a bounded tail window,
records every scheduled case, and places cases with non-empty GT in the
``runnable`` profile.  Empty-GT cases remain explicit manifest metadata rather
than being silently treated as algorithm failures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List


PATTERN_COUNT_RE = re.compile(rb'"pattern_count"\s*:\s*(\d+)')
GT_SUFFIX = "_error_patterns.json"


def _pattern_count(path: Path, tail_bytes: int = 1 << 20) -> int:
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - tail_bytes))
        tail = stream.read()
    matches = list(PATTERN_COUNT_RE.finditer(tail))
    if not matches:
        raise RuntimeError(f"pattern_count missing from JSON tail: {path}")
    return int(matches[-1].group(1))


def build_manifest(
    repo_root: Path,
    timeout_seconds: float,
    formal_refinement: bool = False,
    formal_timeout_ms: int = 10_000,
    formal_max_rounds: int = 5,
    formal_cex_batch: int = 5,
) -> Dict[str, Any]:
    groundtruth_root = repo_root / "groundtruth/V0_singleTrigger_singlePayload"
    trojan_root = repo_root / "trojaned_bench/V0_singleTrigger_singlePayload"
    golden_root = repo_root / "benchmarks"
    gt_paths = sorted(groundtruth_root.glob(f"*/*{GT_SUFFIX}"))
    if not gt_paths:
        raise RuntimeError(f"no V0 ground-truth files under {groundtruth_root}")

    cases: List[Dict[str, Any]] = []
    runnable: List[str] = []
    empty: List[str] = []
    for ordinal, gt_path in enumerate(gt_paths):
        circuit = gt_path.parent.name
        trojan = gt_path.name[: -len(GT_SUFFIX)]
        case_id = trojan
        golden = golden_root / f"{circuit}.bench"
        trojan_path = trojan_root / circuit / f"{trojan}.bench"
        for label, required in (("golden", golden), ("trojan", trojan_path)):
            if not required.is_file():
                raise RuntimeError(f"missing {label} for {case_id}: {required}")
        count = _pattern_count(gt_path)
        cases.append(
            {
                "case_id": case_id,
                "circuit": circuit,
                "trojan": trojan,
                "cohort": "v0_full_runnable" if count else "v0_empty_gt",
                "timeout_seconds": timeout_seconds,
                "groundtruth_pattern_count": count,
                "scheduled_ordinal": ordinal,
                "legacy_v6": {},
            }
        )
        (runnable if count else empty).append(case_id)

    common_args = [
        "--depth", "10", "--neg-ratio", "50",
        "--mine-rounds", "15", "--mine-max", "5000",
    ]
    if formal_refinement:
        common_args.extend(
            [
                "--rule-formal-refine",
                "--rule-formal-timeout-ms", str(formal_timeout_ms),
                "--rule-formal-max-rounds", str(formal_max_rounds),
                "--rule-formal-cex-batch", str(formal_cex_batch),
            ]
        )

    return {
        "schema_version": "rule-method-ab-cases/1",
        "description": (
            "Deterministic V0 inventory for a full z3-pb benchmark. "
            "Only non-empty GT cases belong to the runnable profile."
        ),
        "dataset": {
            "golden_root": "benchmarks",
            "trojan_root": "trojaned_bench/V0_singleTrigger_singlePayload",
            "groundtruth_root": "groundtruth/V0_singleTrigger_singlePayload",
        },
        "common_args": common_args,
        "formal_refinement": {
            "enabled": formal_refinement,
            "timeout_ms": formal_timeout_ms if formal_refinement else None,
            "max_rounds": formal_max_rounds if formal_refinement else None,
            "cex_batch": formal_cex_batch if formal_refinement else None,
        },
        "inventory": {
            "scheduled_count": len(cases),
            "runnable_count": len(runnable),
            "empty_groundtruth_count": len(empty),
            "empty_groundtruth_case_ids": empty,
        },
        "profiles": {"runnable": runnable},
        "cases": cases,
    }


def _write_atomic(path: Path, payload: Dict[str, Any]) -> None:
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
    parser.add_argument(
        "--repo-root", type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--formal-refinement", action="store_true")
    parser.add_argument("--formal-timeout-ms", type=int, default=10_000)
    parser.add_argument("--formal-max-rounds", type=int, default=5)
    parser.add_argument("--formal-cex-batch", type=int, default=5)
    args = parser.parse_args()
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    if args.formal_timeout_ms < 0:
        parser.error("--formal-timeout-ms must be non-negative")
    if args.formal_max_rounds <= 0:
        parser.error("--formal-max-rounds must be positive")
    if not 1 <= args.formal_cex_batch <= 5:
        parser.error("--formal-cex-batch must be between 1 and 5")
    repo_root = args.repo_root.resolve()
    output = args.output if args.output.is_absolute() else repo_root / args.output
    payload = build_manifest(
        repo_root,
        args.timeout_seconds,
        formal_refinement=args.formal_refinement,
        formal_timeout_ms=args.formal_timeout_ms,
        formal_max_rounds=args.formal_max_rounds,
        formal_cex_batch=args.formal_cex_batch,
    )
    _write_atomic(output, payload)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    inventory = payload["inventory"]
    print(
        f"manifest={output} sha256={digest} "
        f"scheduled={inventory['scheduled_count']} "
        f"runnable={inventory['runnable_count']} "
        f"empty_gt={inventory['empty_groundtruth_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
