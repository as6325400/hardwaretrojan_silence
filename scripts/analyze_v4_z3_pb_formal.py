#!/usr/bin/env python3
"""Create a paired V4 Z3-PB formal-OFF versus formal-ON report."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


PAIRED_FIELDS = [
    "case_id", "benchmark", "phase_id", "split", "size_class",
    "trojan_count", "trigger_size", "trigger_topology",
    "positive_pattern_count", "off_status", "on_status", "transition",
    "gain", "regression", "off_success", "on_success",
    "off_wall_ms", "on_wall_ms", "off_runtime_ms", "on_runtime_ms",
    "off_dt_builds", "on_dt_builds", "off_cec_rounds", "on_cec_rounds",
    "on_miter_added", "on_miter_fn", "on_miter_fp", "on_miter_checks",
    "on_miter_total_ms", "on_miter_last_status", "on_miter_last_proved",
    "off_effective_rules", "off_effective_literals", "off_effective_depth",
    "on_effective_rules", "on_effective_literals", "on_effective_depth",
    "off_actual_area_delta_trojan", "on_actual_area_delta_trojan",
    "off_actual_level_delta_trojan", "on_actual_level_delta_trojan",
    "binary_sha256", "abc_sha256",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_csvs(paths: Sequence[Path], arm: str) -> Dict[str, Dict[str, str]]:
    result: Dict[str, Dict[str, str]] = {}
    for path in paths:
        with path.open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                case_id = row.get("case_id", "")
                if not case_id:
                    raise RuntimeError(f"{path} contains a row without case_id")
                if case_id in result:
                    raise RuntimeError(f"duplicate {arm} case_id: {case_id}")
                if row.get("method") != "z3-pb":
                    raise RuntimeError(
                        f"{path} contains non-z3-pb row for {case_id}: "
                        f"{row.get('method')!r}"
                    )
                result[case_id] = dict(row)
    if not result:
        raise RuntimeError(f"no {arm} rows")
    return result


def _bool(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def _number(value: object) -> int | float | None:
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = float(text)
    except ValueError:
        return None
    if not math.isfinite(parsed):
        return None
    if parsed.is_integer() and all(marker not in text.lower() for marker in (".", "e")):
        return int(parsed)
    return parsed


def _manifest_cases(path: Path) -> Tuple[Dict[str, Dict[str, Any]], str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise RuntimeError("manifest lacks cases")
    by_id = {}
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("v4"), dict):
            raise RuntimeError("manifest case lacks V4 metadata")
        case_id = case.get("case_id")
        if case_id in by_id:
            raise RuntimeError(f"duplicate manifest case: {case_id}")
        by_id[case_id] = case
    return by_id, _sha256(path)


def _load_and_validate_contexts(
    result_paths: Sequence[Path],
    *,
    expected_enabled: bool,
    manifest_sha256: str,
) -> List[Dict[str, Any]]:
    contexts = []
    for result_path in result_paths:
        context_path = result_path.parent / "run_context.json"
        try:
            context = json.loads(context_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"cannot read run context {context_path}: {exc}") from exc
        if not isinstance(context, dict):
            raise RuntimeError(f"run context is not an object: {context_path}")
        if context.get("manifest_sha256") != manifest_sha256:
            raise RuntimeError(f"manifest SHA mismatch in {context_path}")
        if context.get("methods") != ["z3-pb"]:
            raise RuntimeError(f"unexpected methods in {context_path}")
        if context.get("rule_formal_refine") is not expected_enabled:
            raise RuntimeError(f"unexpected formal setting in {context_path}")
        if expected_enabled:
            expected = {"timeout_ms": 10000, "max_rounds": 5, "cex_batch": 5}
            actual = {
                "timeout_ms": context.get("rule_formal_timeout_ms"),
                "max_rounds": context.get("rule_formal_max_rounds"),
                "cex_batch": context.get("rule_formal_cex_batch"),
            }
            if actual != expected:
                raise RuntimeError(
                    f"unexpected formal configuration in {context_path}: {actual}"
                )
        contexts.append(
            {
                "path": str(context_path),
                "sha256": _sha256(context_path),
                "context_key": context.get("context_key"),
                "runner_sha256": context.get("runner_sha256"),
                "binary_sha256": context.get("binary_sha256"),
                "abc_sha256": context.get("abc_sha256"),
                "show_sha256": context.get("show_sha256"),
                "profile": context.get("profile"),
                "formal_refine": context.get("rule_formal_refine"),
            }
        )
    return contexts


def _metric(row: Mapping[str, str], key: str) -> int | float | None:
    return _number(row.get(key, ""))


def _formal_config(
    row: Mapping[str, str], *, expected_enabled: bool, case_id: str
) -> Dict[str, int] | None:
    try:
        command = json.loads(row.get("command_json", ""))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid command_json for {case_id}") from exc
    if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
        raise RuntimeError(f"command_json is not a string array for {case_id}")
    formal_flags = [arg for arg in command if arg.startswith("--rule-formal-")]
    enabled = "--rule-formal-refine" in command
    if enabled != expected_enabled:
        raise RuntimeError(
            f"unexpected formal enablement for {case_id}: enabled={enabled}"
        )
    if not expected_enabled:
        if formal_flags:
            raise RuntimeError(f"formal OFF command has formal flags for {case_id}")
        return None
    result: Dict[str, int] = {}
    for option, key in (
        ("--rule-formal-timeout-ms", "timeout_ms"),
        ("--rule-formal-max-rounds", "max_rounds"),
        ("--rule-formal-cex-batch", "cex_batch"),
    ):
        if command.count(option) != 1:
            raise RuntimeError(f"formal ON command lacks unique {option} for {case_id}")
        index = command.index(option)
        if index + 1 >= len(command):
            raise RuntimeError(f"formal option lacks value: {option} for {case_id}")
        try:
            result[key] = int(command[index + 1])
        except ValueError as exc:
            raise RuntimeError(f"invalid formal option value: {option} for {case_id}") from exc
    return result


def build_pairs(
    manifest_cases: Mapping[str, Mapping[str, Any]],
    off_rows: Mapping[str, Mapping[str, str]],
    on_rows: Mapping[str, Mapping[str, str]],
) -> List[Dict[str, Any]]:
    if set(off_rows) != set(on_rows):
        only_off = sorted(set(off_rows) - set(on_rows))
        only_on = sorted(set(on_rows) - set(off_rows))
        raise RuntimeError(f"unpaired cases: only_off={only_off}, only_on={only_on}")
    pairs = []
    for case_id in sorted(off_rows):
        if case_id not in manifest_cases:
            raise RuntimeError(f"case missing from manifest: {case_id}")
        off, on = off_rows[case_id], on_rows[case_id]
        _formal_config(off, expected_enabled=False, case_id=case_id)
        _formal_config(on, expected_enabled=True, case_id=case_id)
        for identity_key in ("binary_sha256", "abc_sha256"):
            if off.get(identity_key) != on.get(identity_key):
                raise RuntimeError(f"paired {identity_key} mismatch for {case_id}")
        metadata = manifest_cases[case_id]["v4"]
        off_success, on_success = _bool(off.get("success")), _bool(on.get("success"))
        pair = {
            "case_id": case_id,
            "benchmark": manifest_cases[case_id]["circuit"],
            "phase_id": metadata["phase_id"],
            "split": metadata["split"],
            "size_class": metadata["size_class"],
            "trojan_count": metadata["trojan_count"],
            "trigger_size": metadata["trigger_size"],
            "trigger_topology": metadata["trigger_topology"],
            "positive_pattern_count": metadata["positive_pattern_count"],
            "off_status": off.get("status"),
            "on_status": on.get("status"),
            "transition": f"{off.get('status')}->{on.get('status')}",
            "gain": int(not off_success and on_success),
            "regression": int(off_success and not on_success),
            "off_success": int(off_success),
            "on_success": int(on_success),
            "off_wall_ms": _metric(off, "wall_ms"),
            "on_wall_ms": _metric(on, "wall_ms"),
            "off_runtime_ms": _metric(off, "runtime_ms"),
            "on_runtime_ms": _metric(on, "runtime_ms"),
            "off_dt_builds": _metric(off, "summary_numeric_sum_dt_builds"),
            "on_dt_builds": _metric(on, "summary_numeric_sum_dt_builds"),
            "off_cec_rounds": _metric(off, "cec_rounds"),
            "on_cec_rounds": _metric(on, "cec_rounds"),
            "on_miter_added": _metric(on, "miter_numeric_sum_added"),
            "on_miter_fn": _metric(on, "miter_numeric_sum_returned_fn"),
            "on_miter_fp": _metric(on, "miter_numeric_sum_returned_fp"),
            "on_miter_checks": _metric(on, "miter_numeric_sum_checks"),
            "on_miter_total_ms": _metric(on, "miter_numeric_sum_total_ms"),
            "on_miter_last_status": on.get("miter_last_status"),
            "on_miter_last_proved": _metric(on, "miter_last_proved"),
            "off_effective_rules": _metric(off, "apply_last_effective_rules"),
            "off_effective_literals": _metric(off, "apply_last_effective_literals"),
            "off_effective_depth": _metric(off, "apply_last_effective_depth"),
            "on_effective_rules": _metric(on, "apply_last_effective_rules"),
            "on_effective_literals": _metric(on, "apply_last_effective_literals"),
            "on_effective_depth": _metric(on, "apply_last_effective_depth"),
            "off_actual_area_delta_trojan": _metric(off, "actual_area_delta_trojan"),
            "on_actual_area_delta_trojan": _metric(on, "actual_area_delta_trojan"),
            "off_actual_level_delta_trojan": _metric(off, "actual_level_delta_trojan"),
            "on_actual_level_delta_trojan": _metric(on, "actual_level_delta_trojan"),
            "binary_sha256": on.get("binary_sha256"),
            "abc_sha256": on.get("abc_sha256"),
        }
        pairs.append(pair)
    return pairs


def _sum(rows: Iterable[Mapping[str, Any]], key: str) -> float:
    return sum(float(row[key]) for row in rows if row.get(key) is not None)


def _aggregate(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    both_pass = [row for row in rows if row["off_success"] and row["on_success"]]
    ratios = [
        float(row["off_wall_ms"]) / float(row["on_wall_ms"])
        for row in both_pass
        if row.get("off_wall_ms") and row.get("on_wall_ms")
        and float(row["off_wall_ms"]) > 0 and float(row["on_wall_ms"]) > 0
    ]
    geo_ratio = math.exp(sum(math.log(value) for value in ratios) / len(ratios)) \
        if ratios else None
    return {
        "cases": len(rows),
        "off_pass": sum(int(row["off_success"]) for row in rows),
        "on_pass": sum(int(row["on_success"]) for row in rows),
        "gains": sum(int(row["gain"]) for row in rows),
        "regressions": sum(int(row["regression"]) for row in rows),
        "transitions": dict(sorted(Counter(row["transition"] for row in rows).items())),
        "off_statuses": dict(sorted(Counter(row["off_status"] for row in rows).items())),
        "on_statuses": dict(sorted(Counter(row["on_status"] for row in rows).items())),
        "both_pass_cases": len(both_pass),
        "both_pass_off_wall_ms": _sum(both_pass, "off_wall_ms"),
        "both_pass_on_wall_ms": _sum(both_pass, "on_wall_ms"),
        "both_pass_off_over_on_wall_geomean": geo_ratio,
        "on_formal_counterexamples_added": _sum(rows, "on_miter_added"),
        "on_formal_fn": _sum(rows, "on_miter_fn"),
        "on_formal_fp": _sum(rows, "on_miter_fp"),
        "on_formal_checks": _sum(rows, "on_miter_checks"),
        "on_formal_total_ms": _sum(rows, "on_miter_total_ms"),
    }


def build_strata(rows: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    output = []
    for dimension in (
        "phase_id", "size_class", "trojan_count", "trigger_size",
        "trigger_topology", "benchmark",
    ):
        values = sorted({str(row[dimension]) for row in rows})
        for value in values:
            selected = [row for row in rows if str(row[dimension]) == value]
            aggregate = _aggregate(selected)
            output.append({"dimension": dimension, "value": value, **aggregate})
    return output


def _atomic_csv(path: Path, fields: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", newline="", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    ) as stream:
        temporary = Path(stream.name)
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
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


def _atomic_copy(source: Path, target: Path) -> Dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = source.read_bytes()
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=target.parent, prefix=f".{target.name}.", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)
    return {
        "path": str(target),
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _write_checksums(output_dir: Path) -> None:
    entries = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        entries.append(f"{_sha256(path)}  {path.relative_to(output_dir)}\n")
    target = output_dir / "SHA256SUMS"
    payload = "".join(entries).encode("utf-8")
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=output_dir, prefix=".SHA256SUMS.", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--off-results", type=Path, action="append", required=True)
    parser.add_argument("--on-results", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--snapshot-sources", action="store_true",
        help="copy the manifest, result CSVs, and run contexts into output-dir/raw",
    )
    args = parser.parse_args()
    manifest_cases, manifest_sha = _manifest_cases(args.manifest)
    off_contexts = _load_and_validate_contexts(
        args.off_results, expected_enabled=False, manifest_sha256=manifest_sha
    )
    on_contexts = _load_and_validate_contexts(
        args.on_results, expected_enabled=True, manifest_sha256=manifest_sha
    )
    off_rows = _read_csvs(args.off_results, "OFF")
    on_rows = _read_csvs(args.on_results, "ON")
    pairs = build_pairs(manifest_cases, off_rows, on_rows)
    formal_configs = {
        json.dumps(
            _formal_config(row, expected_enabled=True, case_id=case_id),
            sort_keys=True,
        )
        for case_id, row in on_rows.items()
    }
    if len(formal_configs) != 1:
        raise RuntimeError("formal ON rows use multiple configurations")
    binary_hashes = sorted({str(row["binary_sha256"]) for row in pairs})
    abc_hashes = sorted({str(row["abc_sha256"]) for row in pairs})
    if len(binary_hashes) != 1 or len(abc_hashes) != 1:
        raise RuntimeError("experiment rows use multiple binary or ABC identities")
    strata = build_strata(pairs)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_csv(args.output_dir / "paired_results.csv", PAIRED_FIELDS, pairs)
    stratum_fields = list(strata[0]) if strata else ["dimension", "value"]
    _atomic_csv(args.output_dir / "strata.csv", stratum_fields, strata)
    snapshots: List[Dict[str, Any]] = []
    if args.snapshot_sources:
        raw_dir = args.output_dir / "raw"
        snapshots.append(
            _atomic_copy(args.manifest, raw_dir / "source_manifest.json")
        )
        for arm, paths in (("off", args.off_results), ("on", args.on_results)):
            for index, result_path in enumerate(paths, start=1):
                snapshot_dir = raw_dir / f"{arm}_{index:02d}"
                snapshots.append(
                    _atomic_copy(
                        result_path,
                        snapshot_dir / "results.csv",
                    )
                )
                snapshots.append(
                    _atomic_copy(
                        result_path.parent / "run_context.json",
                        snapshot_dir / "run_context.json",
                    )
                )
    summary = {
        "schema_version": "v4-z3-pb-formal-comparison/1",
        "manifest": str(args.manifest),
        "manifest_sha256": manifest_sha,
        "off_results": [
            {"path": str(path), "sha256": _sha256(path)}
            for path in args.off_results
        ],
        "on_results": [
            {"path": str(path), "sha256": _sha256(path)}
            for path in args.on_results
        ],
        "formal_config": json.loads(next(iter(formal_configs))),
        "off_run_contexts": off_contexts,
        "on_run_contexts": on_contexts,
        "source_snapshots": snapshots,
        "identities": {
            "binary_sha256": binary_hashes[0],
            "abc_sha256": abc_hashes[0],
        },
        "aggregate": _aggregate(pairs),
        "paired_results_sha256": _sha256(args.output_dir / "paired_results.csv"),
        "strata_sha256": _sha256(args.output_dir / "strata.csv"),
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    _write_checksums(args.output_dir)
    aggregate = summary["aggregate"]
    print(
        f"cases={aggregate['cases']} off_pass={aggregate['off_pass']} "
        f"on_pass={aggregate['on_pass']} gains={aggregate['gains']} "
        f"regressions={aggregate['regressions']} output={args.output_dir.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
