#!/usr/bin/env python3
"""Compare a full V0 Z3-PB run with historical results_v0 through v5.

The historical files do not share a fully reproducible provenance chain, and
v4/v5 are interrupted prefixes.  This script therefore uses exact case-key
pairing, excludes manifest-declared empty-GT cases, and keeps runtime/structure
comparisons to pairs that PASS in both snapshots.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import statistics
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


HISTORICAL = {
    "v0": "results_v0.csv",
    "v1": "results_v1_add_cec_round.csv",
    "v2": "results_v2_DP_add_cec_round.csv",
    "v3": "results_v3_DP_add_cec_round.csv",
    "v4": "results_v4_DP_add_cec_round.csv",
    "v5": "results_v5_DP_add_cec_round.csv",
}


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def _key(row: Mapping[str, str]) -> Tuple[str, str]:
    return row["circuit"], row["trojan"]


def _number(row: Mapping[str, str], name: str) -> Optional[float]:
    value = row.get(name, "").strip()
    if not value:
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def _pass(row: Mapping[str, str], field: str = "status") -> bool:
    return row.get(field, row.get("success", "")) == "PASS"


def _median(values: Sequence[float]) -> Optional[float]:
    return statistics.median(values) if values else None


def _geomean(values: Sequence[float]) -> Optional[float]:
    positive = [value for value in values if value > 0 and math.isfinite(value)]
    if not positive:
        return None
    return math.exp(sum(math.log(value) for value in positive) / len(positive))


def _mcnemar_exact(gains: int, regressions: int) -> Optional[float]:
    discordant = gains + regressions
    if not discordant:
        return None
    tail = sum(
        math.comb(discordant, index)
        for index in range(0, min(gains, regressions) + 1)
    ) / (2 ** discordant)
    return min(1.0, 2.0 * tail)


def _wilson(successes: int, total: int, z: float = 1.959963984540054) -> Tuple[float, float]:
    if total == 0:
        return math.nan, math.nan
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return center - radius, center + radius


def _fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        if not math.isfinite(value):
            return ""
        return f"{value:.{digits}f}"
    return str(value)


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", newline="", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    ) as stream:
        temporary = Path(stream.name)
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, prefix=f".{path.name}.", delete=False,
    ) as stream:
        temporary = Path(stream.name)
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _paired_summary(
    label: str,
    old_rows: Mapping[Tuple[str, str], Mapping[str, str]],
    new_rows: Mapping[Tuple[str, str], Mapping[str, str]],
    keys: Iterable[Tuple[str, str]],
) -> Dict[str, Any]:
    selected = sorted(set(keys) & old_rows.keys() & new_rows.keys())
    old_pass = sum(_pass(old_rows[key], "success") for key in selected)
    new_pass = sum(_pass(new_rows[key]) for key in selected)
    gains = sum(
        not _pass(old_rows[key], "success") and _pass(new_rows[key])
        for key in selected
    )
    regressions = sum(
        _pass(old_rows[key], "success") and not _pass(new_rows[key])
        for key in selected
    )
    both_pass = [
        key for key in selected
        if _pass(old_rows[key], "success") and _pass(new_rows[key])
    ]
    runtime_pairs: List[Tuple[float, float]] = []
    for key in both_pass:
        old_runtime = _number(old_rows[key], "runtime_ms")
        new_runtime = _number(new_rows[key], "runtime_ms")
        if old_runtime is not None and new_runtime is not None and new_runtime > 0:
            runtime_pairs.append((old_runtime, new_runtime))
    ratios = [old / new for old, new in runtime_pairs if old > 0]
    return {
        "comparison": label,
        "paired_cases": len(selected),
        "old_pass": old_pass,
        "new_pass": new_pass,
        "old_pass_rate": old_pass / len(selected) if selected else None,
        "new_pass_rate": new_pass / len(selected) if selected else None,
        "pass_rate_delta_pp": (
            100.0 * (new_pass - old_pass) / len(selected) if selected else None
        ),
        "gains": gains,
        "regressions": regressions,
        "both_pass": len(both_pass),
        "mcnemar_exact_p": _mcnemar_exact(gains, regressions),
        "runtime_both_pass_pairs": len(runtime_pairs),
        "old_runtime_sum_ms": sum(old for old, _ in runtime_pairs),
        "new_runtime_sum_ms": sum(new for _, new in runtime_pairs),
        "old_over_new_runtime_median": _median(ratios),
        "old_over_new_runtime_geomean": _geomean(ratios),
        "new_runtime_wins": sum(new < old for old, new in runtime_pairs),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--formal-results", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    manifest_path = args.manifest if args.manifest.is_absolute() else root / args.manifest
    results_path = args.results if args.results.is_absolute() else root / args.results
    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir

    manifest = json.loads(manifest_path.read_text())
    runnable_ids = manifest["profiles"]["runnable"]
    case_meta = {case["case_id"]: case for case in manifest["cases"]}
    runnable_keys = {
        (case_meta[case_id]["circuit"], case_meta[case_id]["trojan"])
        for case_id in runnable_ids
    }
    new_list = _read_csv(results_path)
    new_rows = {_key(row): row for row in new_list}
    if len(new_rows) != len(new_list):
        raise RuntimeError("new results contain duplicate circuit/trojan keys")
    if new_rows.keys() != runnable_keys:
        missing = sorted(runnable_keys - new_rows.keys())
        extra = sorted(new_rows.keys() - runnable_keys)
        raise RuntimeError(f"new results incomplete: missing={missing[:5]} extra={extra[:5]}")
    if any(row.get("method") != "z3-pb" for row in new_list):
        raise RuntimeError("new results contain a non-z3-pb method")

    legacy_fields = [
        "circuit", "trojan", "success", "gt_verify", "vn_rounds",
        "cec_rounds", "runtime_ms", "area_delta", "level_delta",
        "rule_method", "dt_builds", "optimizer_calls", "optimizer_solver_ms",
        "effective_rules", "effective_literals", "effective_depth",
        "actual_area_delta_trojan", "actual_level_delta_trojan",
    ]
    legacy_rows: List[Dict[str, Any]] = []
    for row in sorted(new_list, key=_key):
        legacy_rows.append(
            {
                "circuit": row["circuit"], "trojan": row["trojan"],
                "success": row["status"], "gt_verify": row["gt_verify"],
                "vn_rounds": row.get("legacy_vn_passes", "0"),
                "cec_rounds": row.get("cec_rounds", ""),
                "runtime_ms": row.get("runtime_ms", ""),
                "area_delta": row.get("reported_area_delta", ""),
                "level_delta": row.get("reported_level_delta", ""),
                "rule_method": row.get("method", ""),
                "dt_builds": row.get("summary_numeric_sum_dt_builds", ""),
                "optimizer_calls": row.get("summary_numeric_sum_optimizer_calls", ""),
                "optimizer_solver_ms": row.get("summary_numeric_sum_optimizer_solver_ms", ""),
                "effective_rules": row.get("apply_last_effective_rules", ""),
                "effective_literals": row.get("apply_last_effective_literals", ""),
                "effective_depth": row.get("apply_last_effective_depth", ""),
                "actual_area_delta_trojan": row.get("actual_area_delta_trojan", ""),
                "actual_level_delta_trojan": row.get("actual_level_delta_trojan", ""),
            }
        )
    legacy_path = output_dir / "results_z3_pb_v0_full.csv"
    _write_csv(legacy_path, legacy_rows, legacy_fields)

    historical: Dict[str, Dict[Tuple[str, str], Dict[str, str]]] = {}
    for version, relative in HISTORICAL.items():
        rows = _read_csv(root / relative)
        indexed = {_key(row): row for row in rows}
        if len(indexed) != len(rows):
            raise RuntimeError(f"{version} contains duplicate keys")
        historical[version] = indexed

    comparison_fields = [
        "version", "circuit", "trojan", "old_status", "new_status",
        "transition", "old_runtime_ms", "new_runtime_ms",
        "old_over_new_runtime", "old_area_delta", "new_reported_area_delta",
        "old_level_delta", "new_reported_level_delta",
    ]
    comparison_rows: List[Dict[str, Any]] = []
    summary_rows: List[Dict[str, Any]] = []
    by_circuit_rows: List[Dict[str, Any]] = []
    summary_fields = [
        "comparison", "paired_cases", "old_pass", "new_pass",
        "old_pass_rate", "new_pass_rate", "pass_rate_delta_pp", "gains",
        "regressions", "both_pass", "mcnemar_exact_p",
        "runtime_both_pass_pairs", "old_runtime_sum_ms", "new_runtime_sum_ms",
        "old_over_new_runtime_median", "old_over_new_runtime_geomean",
        "new_runtime_wins",
    ]
    for version, old in historical.items():
        paired = sorted(runnable_keys & old.keys())
        summary_rows.append(_paired_summary(version, old, new_rows, paired))
        circuits = sorted({circuit for circuit, _ in paired})
        for circuit in circuits:
            row = _paired_summary(
                f"{version}:{circuit}", old, new_rows,
                [key for key in paired if key[0] == circuit],
            )
            row["version"] = version
            row["circuit"] = circuit
            by_circuit_rows.append(row)
        for key in paired:
            old_row, new_row = old[key], new_rows[key]
            old_ok, new_ok = _pass(old_row, "success"), _pass(new_row)
            transition = "PASS_STABLE" if old_ok and new_ok else (
                "GAIN" if not old_ok and new_ok else
                "REGRESSION" if old_ok and not new_ok else "FAIL_STABLE"
            )
            old_runtime = _number(old_row, "runtime_ms")
            new_runtime = _number(new_row, "runtime_ms")
            ratio = (
                old_runtime / new_runtime
                if old_ok and new_ok and old_runtime and new_runtime else None
            )
            comparison_rows.append(
                {
                    "version": version, "circuit": key[0], "trojan": key[1],
                    "old_status": old_row.get("success", ""),
                    "new_status": new_row.get("status", ""),
                    "transition": transition,
                    "old_runtime_ms": _fmt(old_runtime),
                    "new_runtime_ms": _fmt(new_runtime),
                    "old_over_new_runtime": _fmt(ratio, 6),
                    "old_area_delta": old_row.get("area_delta", ""),
                    "new_reported_area_delta": new_row.get("reported_area_delta", ""),
                    "old_level_delta": old_row.get("level_delta", ""),
                    "new_reported_level_delta": new_row.get("reported_level_delta", ""),
                }
            )

    common_keys = set.intersection(
        set(runnable_keys), *(set(rows.keys()) for rows in historical.values())
    )
    common_rows: List[Dict[str, Any]] = []
    for version, rows in [*historical.items(), ("z3-pb", new_rows)]:
        status_field = "status" if version == "z3-pb" else "success"
        successes = sum(_pass(rows[key], status_field) for key in common_keys)
        common_rows.append(
            {
                "version": version, "common_cases": len(common_keys),
                "pass": successes, "pass_rate": successes / len(common_keys),
            }
        )

    _write_csv(output_dir / "z3_pb_vs_v0_v5_cases.csv", comparison_rows, comparison_fields)
    _write_csv(output_dir / "z3_pb_vs_v0_v5_summary.csv", summary_rows, summary_fields)
    by_fields = ["version", "circuit", *summary_fields[1:]]
    _write_csv(output_dir / "z3_pb_vs_v0_v5_by_circuit.csv", by_circuit_rows, by_fields)
    _write_csv(
        output_dir / "z3_pb_common_cohort_summary.csv", common_rows,
        ["version", "common_cases", "pass", "pass_rate"],
    )

    new_pass = sum(_pass(row) for row in new_list)
    low, high = _wilson(new_pass, len(new_list))
    lines = [
        "# Z3-PB V0 full benchmark\n",
        f"- Branch commit: `{manifest.get('source_commit', '4722754')}`",
        f"- Scheduled / runnable / empty GT: "
        f"{manifest['inventory']['scheduled_count']} / "
        f"{manifest['inventory']['runnable_count']} / "
        f"{manifest['inventory']['empty_groundtruth_count']}",
        f"- Z3-PB PASS: {new_pass}/{len(new_list)} "
        f"({100*new_pass/len(new_list):.2f}%, Wilson 95% "
        f"{100*low:.2f}–{100*high:.2f}%)",
        "- Formal refinement: "
        f"`{int(bool(manifest.get('formal_refinement', {}).get('enabled', False)))}`",
        "\n## Exact-key paired comparison\n",
        "| Version | N | old PASS | Z3-PB PASS | Δ pp | gains | regressions | runtime geo old/new |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary_rows:
        lines.append(
            f"| {row['comparison']} | {row['paired_cases']} | {row['old_pass']} | "
            f"{row['new_pass']} | {_fmt(row['pass_rate_delta_pp'], 2)} | "
            f"{row['gains']} | {row['regressions']} | "
            f"{_fmt(row['old_over_new_runtime_geomean'], 3)} |"
        )
    lines.extend(
        [
            "\nV4/V5 are interrupted prefixes, so their rows use only exact available keys. "
            "Runtime ratios use pairs that PASS in both snapshots. Historical area/level values "
            "are internal reported metrics rather than independently replayed final-netlist metrics.",
            "\n## Artifact hashes\n",
            f"- Input results: `{_sha256(results_path)}`",
            f"- Manifest: `{_sha256(manifest_path)}`",
            f"- Legacy projection: `{_sha256(legacy_path)}`",
        ]
    )
    _write_text(output_dir / "Z3_PB_V0_BENCHMARK_REPORT.md", "\n".join(lines) + "\n")
    print(f"analysis={output_dir} new_pass={new_pass}/{len(new_list)} common={len(common_keys)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
