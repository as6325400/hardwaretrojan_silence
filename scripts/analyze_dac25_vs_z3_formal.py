#!/usr/bin/env python3
"""Compare DAC25-inspired ECO repair with the frozen Z3-PB+formal run.

Success is taken from an independent ABC CEC replay.  Structural QoR is
measured only on cases for which both methods pass, after every Golden,
Trojan, and patched netlist is converted to the same strashed AIG view by the
same ABC executable.  The reported level is therefore a topological AIG logic
level, not a technology-mapped delay in seconds.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import statistics
import subprocess
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


Key = Tuple[str, str]
_AIG_STATS = re.compile(r"\band\s*=\s*([0-9]+)\s+lev\s*=\s*([0-9]+)\b")


@dataclass(frozen=True)
class AigStats:
    nodes: int
    levels: int


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def abc_quote(path: Path) -> str:
    value = str(path.resolve())
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def read_rows(path: Path) -> Dict[Key, Dict[str, str]]:
    with path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    indexed = {(row["circuit"], row["trojan"]): row for row in rows}
    if len(indexed) != len(rows):
        raise RuntimeError(f"duplicate circuit/Trojan keys in {path}")
    return indexed


def number(row: Mapping[str, str], field: str) -> Optional[float]:
    value = row.get(field, "").strip()
    if not value:
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def integer(row: Mapping[str, str], field: str) -> Optional[int]:
    value = number(row, field)
    return int(round(value)) if value is not None else None


def geomean(values: Iterable[float]) -> Optional[float]:
    kept = [value for value in values if value > 0 and math.isfinite(value)]
    return math.exp(sum(math.log(value) for value in kept) / len(kept)) if kept else None


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> Tuple[float, float]:
    if total <= 0:
        return math.nan, math.nan
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(
        p * (1 - p) / total + z * z / (4 * total * total)
    ) / denominator
    return center - radius, center + radius


def mcnemar_exact(gains: int, regressions: int) -> Optional[float]:
    discordant = gains + regressions
    if discordant == 0:
        return None
    tail = sum(
        math.comb(discordant, index)
        for index in range(min(gains, regressions) + 1)
    ) / (2 ** discordant)
    return min(1.0, 2 * tail)


def atomic_csv(path: Path, rows: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", newline="", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        temporary = Path(stream.name)
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fields} for row in rows)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def command_paths(row: Mapping[str, str]) -> Tuple[Path, Path]:
    try:
        command = json.loads(row["command_json"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise RuntimeError("record has invalid command_json") from exc
    if not isinstance(command, list) or len(command) < 5:
        raise RuntimeError("record command does not contain Golden/Trojan paths")
    return Path(command[1]).resolve(), Path(command[2]).resolve()


def artifact_path(root: Path, row: Mapping[str, str]) -> Optional[Path]:
    value = row.get("patched_bench", "").strip()
    if not value:
        return None
    candidate = Path(value)
    return candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()


def run_provenance(root: Path) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    context_path = root / "run_context.json"
    if context_path.is_file():
        try:
            context = json.loads(context_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid run context: {context_path}") from exc
        result.update(
            {
                "context_sha256": sha256(context_path),
                "context_key": context.get("context_key", ""),
                "manifest_sha256": context.get("manifest_sha256", ""),
                "runner_sha256": context.get("runner_sha256", ""),
            }
        )
    commits = set()
    dirtiness = set()
    for record_path in sorted((root / "records").glob("*.json")):
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid record: {record_path}") from exc
        git = record.get("environment", {}).get("git", {})
        if git.get("commit"):
            commits.add(str(git["commit"]))
        if "dirty" in git:
            dirtiness.add(bool(git["dirty"]))
    if len(commits) > 1 or len(dirtiness) > 1:
        raise RuntimeError(
            f"run contains mixed git provenance: commits={commits} dirty={dirtiness}"
        )
    result["git_commit"] = next(iter(commits), "")
    result["git_dirty"] = next(iter(dirtiness), "")
    return result


def audit_run_artifacts(
    root: Path, expected_rows: Mapping[Key, Mapping[str, str]]
) -> Dict[str, int]:
    record_paths = sorted((root / "records").glob("*.json"))
    if not record_paths:
        return {"records": 0, "artifact_refs": 0, "artifact_bytes": 0}
    records = []
    indexed: Dict[Key, Mapping[str, Any]] = {}
    artifact_refs = 0
    artifact_bytes = 0
    for record_path in record_paths:
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid record: {record_path}") from exc
        records.append(record)
        case = record.get("case", {})
        key = (str(case.get("circuit", "")), str(case.get("trojan", "")))
        if key in indexed:
            raise RuntimeError(f"duplicate run record for {key}")
        indexed[key] = record
        if record.get("post_run_identity_changes") != {}:
            raise RuntimeError(f"post-run identity mutation in {record_path}")
        artifacts = record.get("artifacts", {})
        for name, identity in record.get("artifact_identities", {}).items():
            if identity is None:
                continue
            raw_path = artifacts.get(name)
            if not raw_path:
                raise RuntimeError(f"artifact {name} lacks a path in {record_path}")
            artifact = Path(raw_path)
            if not artifact.is_absolute():
                artifact = root / artifact
            if not artifact.is_file():
                raise RuntimeError(f"missing recorded artifact: {artifact}")
            expected_size = int(identity["size_bytes"])
            actual_size = artifact.stat().st_size
            if actual_size != expected_size or sha256(artifact) != identity["sha256"]:
                raise RuntimeError(f"artifact identity mismatch: {artifact}")
            artifact_refs += 1
            artifact_bytes += actual_size
    if set(indexed) != set(expected_rows):
        raise RuntimeError(
            f"record/result case sets differ: records={len(indexed)} "
            f"results={len(expected_rows)}"
        )
    for key, record in indexed.items():
        if record.get("status") != expected_rows[key].get("status"):
            raise RuntimeError(f"record/result status mismatch for {key}")
    summary_path = root / "summary.json"
    if summary_path.is_file():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid summary: {summary_path}") from exc
        summary_records = {
            (
                str(record.get("case", {}).get("circuit", "")),
                str(record.get("case", {}).get("trojan", "")),
            ): record
            for record in summary.get("records", [])
        }
        if summary_records != indexed:
            raise RuntimeError(f"summary records differ from record files in {root}")
    return {
        "records": len(records),
        "artifact_refs": artifact_refs,
        "artifact_bytes": artifact_bytes,
    }


def same_input(left: Path, right: Path) -> bool:
    try:
        if left.samefile(right):
            return True
    except OSError:
        pass
    try:
        return left.stat().st_size == right.stat().st_size and sha256(left) == sha256(right)
    except OSError:
        return False


def run_abc(abc: Path, command: str, timeout: float) -> str:
    completed = subprocess.run(
        [str(abc), "-c", command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    combined = completed.stdout + "\n" + completed.stderr
    if completed.returncode != 0:
        raise RuntimeError(
            f"ABC exited {completed.returncode} for {command!r}: {combined[-1000:]}"
        )
    return combined


def measure_aig(abc: Path, netlist: Path, timeout: float) -> AigStats:
    if not netlist.is_file():
        raise RuntimeError(f"missing netlist: {netlist}")
    output = run_abc(
        abc, f"read {abc_quote(netlist)}; strash; print_stats", timeout
    )
    matches = _AIG_STATS.findall(output)
    if not matches:
        raise RuntimeError(f"could not parse AIG stats for {netlist}: {output[-1000:]}")
    nodes, levels = matches[-1]
    return AigStats(int(nodes), int(levels))


def replay_cec(abc: Path, golden: Path, patched: Path, timeout: float) -> bool:
    output = run_abc(
        abc, f"cec {abc_quote(golden)} {abc_quote(patched)}", timeout
    )
    equivalent = "Networks are equivalent" in output
    not_equivalent = "Networks are NOT EQUIVALENT" in output
    if equivalent == not_equivalent:
        raise RuntimeError(
            f"ambiguous ABC CEC output for {patched}: {output[-1000:]}"
        )
    return equivalent


def winner(z3_value: int, dac_value: int) -> str:
    if dac_value < z3_value:
        return "dac25-inspired"
    if z3_value < dac_value:
        return "z3-pb-formal"
    return "tie"


def format_optional(value: Optional[float], digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def safe_ratio(numerator: float, denominator: float) -> Optional[float]:
    if denominator <= 0:
        return None
    return numerator / denominator


def median_or_none(values: Sequence[float]) -> Optional[float]:
    return statistics.median(values) if values else None


def positive_metric_pairs(
    left: Mapping[Key, Mapping[str, str]],
    right: Mapping[Key, Mapping[str, str]],
    keys: Iterable[Key],
    field: str,
) -> List[Tuple[float, float]]:
    pairs: List[Tuple[float, float]] = []
    for key in keys:
        left_value = number(left[key], field)
        right_value = number(right[key], field)
        if (
            left_value is not None
            and right_value is not None
            and left_value > 0
            and right_value > 0
        ):
            pairs.append((left_value, right_value))
    return pairs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--z3-results", type=Path, required=True)
    parser.add_argument("--z3-root", type=Path, required=True)
    parser.add_argument("--dac-results", type=Path, required=True)
    parser.add_argument("--dac-root", type=Path, required=True)
    parser.add_argument("--abc", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--abc-timeout", type=float, default=60.0)
    parser.add_argument("--require-cases", type=int, default=482)
    parser.add_argument(
        "--cohort-label",
        default="selected benchmark cohort",
        help="human-readable cohort name used in the generated report",
    )
    args = parser.parse_args()
    if args.workers <= 0 or args.abc_timeout <= 0 or args.require_cases <= 0:
        raise RuntimeError("workers, ABC timeout, and required cases must be positive")
    if not args.cohort_label.strip():
        raise RuntimeError("cohort label must not be empty")
    abc = args.abc.resolve()
    if not abc.is_file():
        raise RuntimeError(f"ABC executable is missing: {abc}")

    z3 = read_rows(args.z3_results)
    dac = read_rows(args.dac_results)
    common = sorted(set(z3) & set(dac))
    if len(common) != args.require_cases or set(z3) != set(dac):
        raise RuntimeError(
            f"expected identical {args.require_cases}-case sets; "
            f"z3={len(z3)} dac={len(dac)} common={len(common)}"
        )
    if any(z3[key].get("method") != "z3-pb" for key in common):
        raise RuntimeError("Z3 input contains a method other than z3-pb")
    if any(dac[key].get("method") != "dac25-inspired" for key in common):
        raise RuntimeError("DAC input contains a method other than dac25-inspired")
    z3_binary_hashes = {z3[key].get("binary_sha256", "") for key in common}
    dac_binary_hashes = {dac[key].get("binary_sha256", "") for key in common}
    if len(z3_binary_hashes) != 1 or len(dac_binary_hashes) != 1:
        raise RuntimeError(
            f"each arm must use one binary: z3={z3_binary_hashes} dac={dac_binary_hashes}"
        )
    abc_hashes = {
        row.get("abc_sha256", "") for rows in (z3, dac) for row in rows.values()
    }
    expected_abc_hash = sha256(abc)
    if abc_hashes != {expected_abc_hash}:
        raise RuntimeError(
            f"result ABC identities {abc_hashes} differ from {expected_abc_hash}"
        )

    inputs: Dict[Key, Tuple[Path, Path]] = {}
    z3_patches: Dict[Key, Optional[Path]] = {}
    dac_patches: Dict[Key, Optional[Path]] = {}
    for key in common:
        z3_golden, z3_trojan = command_paths(z3[key])
        dac_golden, dac_trojan = command_paths(dac[key])
        if not same_input(z3_golden, dac_golden) or not same_input(z3_trojan, dac_trojan):
            raise RuntimeError(f"Z3/DAC inputs differ for {key}")
        inputs[key] = dac_golden, dac_trojan
        z3_patches[key] = artifact_path(args.z3_root, z3[key])
        dac_patches[key] = artifact_path(args.dac_root, dac[key])

    # Measure every distinct relevant path once.  PASS artifacts are also
    # independently replayed through the same ABC CEC executable.
    paths = {path for pair in inputs.values() for path in pair}
    for key in common:
        if z3[key]["status"] == "PASS" and z3_patches[key] is not None:
            paths.add(z3_patches[key])
        if dac[key]["status"] == "PASS" and dac_patches[key] is not None:
            paths.add(dac_patches[key])
    stats: Dict[Path, AigStats] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(measure_aig, abc, path, args.abc_timeout): path
            for path in sorted(paths)
        }
        for future in as_completed(futures):
            path = futures[future]
            stats[path] = future.result()

    cec_jobs: Dict[Any, Tuple[str, Key]] = {}
    cec_replay: Dict[Tuple[str, Key], bool] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for key in common:
            golden = inputs[key][0]
            for label, rows, patches in (
                ("z3", z3, z3_patches), ("dac", dac, dac_patches)
            ):
                if rows[key]["status"] != "PASS":
                    continue
                patch = patches[key]
                if patch is None or not patch.is_file():
                    raise RuntimeError(f"PASS {label}/{key} lacks a patch artifact")
                future = pool.submit(replay_cec, abc, golden, patch, args.abc_timeout)
                cec_jobs[future] = (label, key)
        for future in as_completed(cec_jobs):
            label_key = cec_jobs[future]
            cec_replay[label_key] = future.result()
    failed_replays = [label_key for label_key, passed in cec_replay.items() if not passed]
    if failed_replays:
        raise RuntimeError(f"recorded PASS failed independent CEC replay: {failed_replays}")

    case_fields = [
        "case_id", "circuit", "trojan", "z3_status", "dac_status", "transition",
        "both_pass", "z3_runtime_ms", "dac_runtime_ms", "z3_wall_ms", "dac_wall_ms",
        "golden_aig_nodes", "golden_aig_levels", "trojan_aig_nodes", "trojan_aig_levels",
        "z3_aig_nodes", "z3_aig_levels", "dac_aig_nodes", "dac_aig_levels",
        "z3_delta_nodes_vs_trojan", "dac_delta_nodes_vs_trojan",
        "z3_delta_levels_vs_trojan", "dac_delta_levels_vs_trojan",
        "z3_minus_dac_nodes", "z3_minus_dac_levels", "node_winner", "level_winner",
        "dac_target_count", "dac_patch_inputs", "dac_runeco_added_gates",
        "z3_effective_rules", "z3_effective_literals", "z3_effective_depth",
        "z3_cec_replay", "dac_cec_replay",
    ]
    case_rows: List[Dict[str, Any]] = []
    paired_keys: List[Key] = []
    for key in common:
        zrow, drow = z3[key], dac[key]
        golden_path, trojan_path = inputs[key]
        golden_stats, trojan_stats = stats[golden_path], stats[trojan_path]
        both_pass = zrow["status"] == drow["status"] == "PASS"
        transition = (
            "both_pass" if both_pass else
            "gain" if zrow["status"] != "PASS" and drow["status"] == "PASS" else
            "regression" if zrow["status"] == "PASS" and drow["status"] != "PASS" else
            "both_nonpass"
        )
        output: Dict[str, Any] = {
            "case_id": zrow["case_id"], "circuit": key[0], "trojan": key[1],
            "z3_status": zrow["status"], "dac_status": drow["status"],
            "transition": transition, "both_pass": int(both_pass),
            "z3_runtime_ms": zrow.get("runtime_ms", ""),
            "dac_runtime_ms": drow.get("runtime_ms", ""),
            "z3_wall_ms": zrow.get("wall_ms", ""), "dac_wall_ms": drow.get("wall_ms", ""),
            "golden_aig_nodes": golden_stats.nodes, "golden_aig_levels": golden_stats.levels,
            "trojan_aig_nodes": trojan_stats.nodes, "trojan_aig_levels": trojan_stats.levels,
            "z3_effective_rules": zrow.get("apply_last_effective_rules", ""),
            "z3_effective_literals": zrow.get("apply_last_effective_literals", ""),
            "z3_effective_depth": zrow.get("apply_last_effective_depth", ""),
            "dac_target_count": drow.get("rectification_selected_last_target_count", ""),
            "dac_patch_inputs": drow.get("rectification_selected_last_patch_inputs", ""),
            "dac_runeco_added_gates": drow.get(
                "rectification_selected_last_patch_added_gates", ""
            ),
            "z3_cec_replay": int(cec_replay.get(("z3", key), False))
                if zrow["status"] == "PASS" else "",
            "dac_cec_replay": int(cec_replay.get(("dac", key), False))
                if drow["status"] == "PASS" else "",
        }
        if zrow["status"] == "PASS":
            zstats = stats[z3_patches[key]]
            output.update({
                "z3_aig_nodes": zstats.nodes, "z3_aig_levels": zstats.levels,
                "z3_delta_nodes_vs_trojan": zstats.nodes - trojan_stats.nodes,
                "z3_delta_levels_vs_trojan": zstats.levels - trojan_stats.levels,
            })
        if drow["status"] == "PASS":
            dstats = stats[dac_patches[key]]
            output.update({
                "dac_aig_nodes": dstats.nodes, "dac_aig_levels": dstats.levels,
                "dac_delta_nodes_vs_trojan": dstats.nodes - trojan_stats.nodes,
                "dac_delta_levels_vs_trojan": dstats.levels - trojan_stats.levels,
            })
        if both_pass:
            paired_keys.append(key)
            zstats, dstats = stats[z3_patches[key]], stats[dac_patches[key]]
            output.update({
                "z3_minus_dac_nodes": zstats.nodes - dstats.nodes,
                "z3_minus_dac_levels": zstats.levels - dstats.levels,
                "node_winner": winner(zstats.nodes, dstats.nodes),
                "level_winner": winner(zstats.levels, dstats.levels),
            })
        case_rows.append(output)

    atomic_csv(args.output_dir / "dac25_vs_z3_formal_cases.csv", case_rows, case_fields)

    z3_pass = sum(z3[key]["status"] == "PASS" for key in common)
    dac_pass = sum(dac[key]["status"] == "PASS" for key in common)
    gains = sum(
        z3[key]["status"] != "PASS" and dac[key]["status"] == "PASS" for key in common
    )
    regressions = sum(
        z3[key]["status"] == "PASS" and dac[key]["status"] != "PASS" for key in common
    )
    z3_low, z3_high = wilson(z3_pass, len(common))
    dac_low, dac_high = wilson(dac_pass, len(common))

    wall_pairs = positive_metric_pairs(z3, dac, paired_keys, "wall_ms")
    runtime_pairs = positive_metric_pairs(z3, dac, paired_keys, "runtime_ms")
    z3_wall_f = [left for left, _ in wall_pairs]
    dac_wall_f = [right for _, right in wall_pairs]
    z3_runtime_f = [left for left, _ in runtime_pairs]
    dac_runtime_f = [right for _, right in runtime_pairs]

    paired_case_rows = [row for row in case_rows if row["both_pass"] == 1]
    node_counts = Counter(row["node_winner"] for row in paired_case_rows)
    level_counts = Counter(row["level_winner"] for row in paired_case_rows)
    z3_delta_nodes = [int(row["z3_delta_nodes_vs_trojan"]) for row in paired_case_rows]
    dac_delta_nodes = [int(row["dac_delta_nodes_vs_trojan"]) for row in paired_case_rows]
    z3_delta_levels = [int(row["z3_delta_levels_vs_trojan"]) for row in paired_case_rows]
    dac_delta_levels = [int(row["dac_delta_levels_vs_trojan"]) for row in paired_case_rows]
    z3_nodes = [int(row["z3_aig_nodes"]) for row in paired_case_rows]
    dac_nodes = [int(row["dac_aig_nodes"]) for row in paired_case_rows]

    summary = {
        "cases": len(common), "z3_pass": z3_pass, "dac_pass": dac_pass,
        "z3_pass_rate": z3_pass / len(common), "dac_pass_rate": dac_pass / len(common),
        "z3_wilson_low": z3_low, "z3_wilson_high": z3_high,
        "dac_wilson_low": dac_low, "dac_wilson_high": dac_high,
        "dac_gains": gains, "dac_regressions": regressions,
        "mcnemar_exact_p": mcnemar_exact(gains, regressions),
        "both_pass": len(paired_keys),
        "paired_wall_samples": len(wall_pairs),
        "z3_wall_sum_ms": sum(z3_wall_f), "dac_wall_sum_ms": sum(dac_wall_f),
        "z3_over_dac_wall_sum_ratio": safe_ratio(sum(z3_wall_f), sum(dac_wall_f)),
        "z3_over_dac_wall_median_ratio": median_or_none(
            [left / right for left, right in wall_pairs]
        ),
        "z3_over_dac_wall_geomean_ratio": geomean(
            left / right for left, right in wall_pairs
        ),
        "dac_wall_wins": sum(right < left for left, right in wall_pairs),
        "paired_runtime_samples": len(runtime_pairs),
        "z3_runtime_sum_ms": sum(z3_runtime_f), "dac_runtime_sum_ms": sum(dac_runtime_f),
        "z3_over_dac_runtime_sum_ratio": safe_ratio(
            sum(z3_runtime_f), sum(dac_runtime_f)
        ),
        "z3_over_dac_runtime_median_ratio": median_or_none(
            [left / right for left, right in runtime_pairs]
        ),
        "z3_over_dac_runtime_geomean_ratio": geomean(
            left / right for left, right in runtime_pairs
        ),
        "dac_runtime_wins": sum(right < left for left, right in runtime_pairs),
        "dac_node_wins": node_counts["dac25-inspired"],
        "node_ties": node_counts["tie"], "z3_node_wins": node_counts["z3-pb-formal"],
        "dac_level_wins": level_counts["dac25-inspired"],
        "level_ties": level_counts["tie"], "z3_level_wins": level_counts["z3-pb-formal"],
        "z3_aig_nodes_sum": sum(z3_nodes), "dac_aig_nodes_sum": sum(dac_nodes),
        "z3_over_dac_aig_nodes_ratio": safe_ratio(sum(z3_nodes), sum(dac_nodes)),
        "z3_delta_nodes_sum": sum(z3_delta_nodes),
        "dac_delta_nodes_sum": sum(dac_delta_nodes),
        "z3_delta_nodes_median": median_or_none(z3_delta_nodes),
        "dac_delta_nodes_median": median_or_none(dac_delta_nodes),
        "z3_delta_levels_sum": sum(z3_delta_levels),
        "dac_delta_levels_sum": sum(dac_delta_levels),
        "z3_delta_levels_median": median_or_none(z3_delta_levels),
        "dac_delta_levels_median": median_or_none(dac_delta_levels),
        "z3_cec_replayed": sum(label == "z3" for label, _ in cec_replay),
        "dac_cec_replayed": sum(label == "dac" for label, _ in cec_replay),
        "abc_sha256": expected_abc_hash,
        "z3_binary_sha256": next(iter(z3_binary_hashes)),
        "dac_binary_sha256": next(iter(dac_binary_hashes)),
        "z3_results_sha256": sha256(args.z3_results),
        "dac_results_sha256": sha256(args.dac_results),
        "cohort_label": args.cohort_label.strip(),
    }
    z3_provenance = run_provenance(args.z3_root)
    dac_provenance = run_provenance(args.dac_root)
    for label, provenance in (("z3", z3_provenance), ("dac", dac_provenance)):
        for key, value in provenance.items():
            summary[f"{label}_{key}"] = value
    z3_audit = audit_run_artifacts(args.z3_root, z3)
    dac_audit = audit_run_artifacts(args.dac_root, dac)
    for label, audit in (("z3", z3_audit), ("dac", dac_audit)):
        for key, value in audit.items():
            summary[f"{label}_{key}"] = value
    summary_fields = list(summary)
    atomic_csv(args.output_dir / "dac25_vs_z3_formal_summary.csv", [summary], summary_fields)

    by_circuit_rows: List[Dict[str, Any]] = []
    for circuit in sorted({key[0] for key in common}):
        selected = [row for row in case_rows if row["circuit"] == circuit]
        paired_selected = [row for row in selected if row["both_pass"] == 1]
        z_pass = sum(row["z3_status"] == "PASS" for row in selected)
        d_pass = sum(row["dac_status"] == "PASS" for row in selected)
        by_circuit_rows.append({
            "circuit": circuit, "cases": len(selected), "z3_pass": z_pass,
            "dac_pass": d_pass,
            "gains": sum(row["transition"] == "gain" for row in selected),
            "regressions": sum(row["transition"] == "regression" for row in selected),
            "both_pass": len(paired_selected),
            "dac_node_wins": sum(
                row.get("node_winner") == "dac25-inspired" for row in paired_selected
            ),
            "node_ties": sum(row.get("node_winner") == "tie" for row in paired_selected),
            "z3_node_wins": sum(
                row.get("node_winner") == "z3-pb-formal" for row in paired_selected
            ),
            "dac_level_wins": sum(
                row.get("level_winner") == "dac25-inspired" for row in paired_selected
            ),
            "level_ties": sum(row.get("level_winner") == "tie" for row in paired_selected),
            "z3_level_wins": sum(
                row.get("level_winner") == "z3-pb-formal" for row in paired_selected
            ),
        })
    by_fields = list(by_circuit_rows[0])
    atomic_csv(args.output_dir / "dac25_vs_z3_formal_by_circuit.csv", by_circuit_rows, by_fields)

    gains_cases = [row["case_id"] for row in case_rows if row["transition"] == "gain"]
    regression_cases = [
        f"{row['case_id']} ({row['dac_status']})"
        for row in case_rows if row["transition"] == "regression"
    ]
    gains_text = ", ".join(f"`{case}`" for case in gains_cases) or "none"
    regressions_text = ", ".join(
        f"`{case}`" for case in regression_cases
    ) or "none"
    dac_statuses = Counter(row["dac_status"] for row in case_rows)
    z3_statuses = Counter(row["z3_status"] for row in case_rows)
    mcnemar_text = (
        "n/a (no discordant outcomes)"
        if summary["mcnemar_exact_p"] is None
        else f"{summary['mcnemar_exact_p']:.6g}"
    )
    if wall_pairs:
        wall_runtime_text = (
            f"Of these, {len(wall_pairs)} have positive finite wall-time values for "
            f"both methods. Their sums are {sum(z3_wall_f)/1000:.3f}s (Z3) and "
            f"{sum(dac_wall_f)/1000:.3f}s (DAC), "
            f"Z3/DAC={format_optional(summary['z3_over_dac_wall_sum_ratio'])}. "
            f"The per-case median and geometric-mean Z3/DAC ratios are "
            f"{format_optional(summary['z3_over_dac_wall_median_ratio'])} and "
            f"{format_optional(summary['z3_over_dac_wall_geomean_ratio'])}; DAC is "
            f"faster on {summary['dac_wall_wins']}/{len(wall_pairs)} comparable cases."
        )
    else:
        wall_runtime_text = (
            "No paired-PASS case has positive finite wall-time values for both "
            "methods, so wall-time ratios are n/a."
        )
    if runtime_pairs:
        internal_runtime_text = (
            f"Tool-reported runtime is comparable on {len(runtime_pairs)} paired-PASS "
            f"cases; the aggregate Z3/DAC ratio is "
            f"{format_optional(summary['z3_over_dac_runtime_sum_ratio'])}."
        )
    else:
        internal_runtime_text = (
            "No paired-PASS case has positive finite tool-reported runtime for both "
            "methods; those runtime ratios are n/a."
        )
    report = [
        "# DAC25-inspired rectification vs Z3-PB + formal refinement\n",
        f"This is an end-to-end comparison on {len(common)} Golden/Trojan pairs "
        f"({args.cohort_label.strip()}). "
        "The DAC arm is a public-information, **DAC'25-inspired** "
        "reimplementation, not the authors' unavailable implementation. Z3-PB starts "
        "from error-pattern supervision and then queries the complete circuit pair "
        "through its formal miter; DAC selects ECO cuts directly from the complete "
        "pair and does not read the ground-truth pattern file. This remains an "
        "end-to-end comparison, not a same-oracle selector-only ablation.\n",
        "## Correctness\n",
        "| Method | PASS | Rate | Wilson 95% | Other statuses |",
        "|---|---:|---:|---:|---|",
        f"| Z3-PB + formal | {z3_pass}/{len(common)} | {100*z3_pass/len(common):.2f}% | "
        f"{100*z3_low:.2f}–{100*z3_high:.2f}% | `{dict(sorted(z3_statuses.items()))}` |",
        f"| DAC25-inspired | {dac_pass}/{len(common)} | {100*dac_pass/len(common):.2f}% | "
        f"{100*dac_low:.2f}–{100*dac_high:.2f}% | `{dict(sorted(dac_statuses.items()))}` |",
        "",
        "Wilson intervals describe the observed cohort only; no population-level "
        "inference is made unless the cohort's sampling design supports it.",
        "",
        f"DAC has {gains} {'gain' if gains == 1 else 'gains'} and {regressions} "
        f"{'regression' if regressions == 1 else 'regressions'} relative to Z3-PB "
        f"(McNemar exact two-sided p={mcnemar_text}).",
        f"Gains: {gains_text}.",
        f"Regressions: {regressions_text}.",
        f"Independent replay with the pinned ABC proved all {z3_pass} recorded Z3 PASS "
        f"artifacts and all {dac_pass} recorded DAC PASS artifacts equivalent.\n",
        "## Paired end-to-end runtime\n",
        f"The paired cohort contains {len(paired_keys)} cases that PASS in both methods. "
        f"{wall_runtime_text} {internal_runtime_text}\n",
        "## Common AIG structural QoR\n",
        "Every input and patch was independently read and strashed by the same pinned "
        "ABC. `and` is the AIG AND-node count and `lev` is topological AIG logic level. "
        "It is **not** mapped cell area or physical delay in ns. Only the paired CEC-PASS "
        "cohort is compared.\n",
        "| Metric | DAC wins | Ties | Z3 wins | Z3 aggregate | DAC aggregate |",
        "|---|---:|---:|---:|---:|---:|",
        f"| Patched AIG nodes | {summary['dac_node_wins']} | {summary['node_ties']} | "
        f"{summary['z3_node_wins']} | {summary['z3_aig_nodes_sum']} | "
        f"{summary['dac_aig_nodes_sum']} |",
        f"| Patched AIG levels | {summary['dac_level_wins']} | {summary['level_ties']} | "
        f"{summary['z3_level_wins']} | ΔvsTrojan sum {summary['z3_delta_levels_sum']} | "
        f"ΔvsTrojan sum {summary['dac_delta_levels_sum']} |",
        "",
        f"AIG-node deltas versus the common Trojan sum to {summary['z3_delta_nodes_sum']} "
        f"for Z3 and {summary['dac_delta_nodes_sum']} for DAC; medians are "
        f"{format_optional(summary['z3_delta_nodes_median'])} and "
        f"{format_optional(summary['dac_delta_nodes_median'])}. "
        f"The aggregate patched-node ratio Z3/DAC is "
        f"{format_optional(summary['z3_over_dac_aig_nodes_ratio'], 6)}.\n",
        "## Reproducibility\n",
        f"- ABC SHA-256: `{expected_abc_hash}`",
        f"- Z3 binary SHA-256: `{summary['z3_binary_sha256']}`",
        f"- DAC binary SHA-256: `{summary['dac_binary_sha256']}`",
        f"- Z3 recorded source commit: `{z3_provenance.get('git_commit', '')}` "
        f"(dirty={z3_provenance.get('git_dirty', '')})",
        f"- DAC source commit: `{dac_provenance.get('git_commit', '')}` "
        f"(dirty={dac_provenance.get('git_dirty', '')})",
        f"- Manifest SHA-256: `{dac_provenance.get('manifest_sha256', '')}`",
        f"- DAC run-context SHA-256: `{dac_provenance.get('context_sha256', '')}`",
        f"- Z3 result CSV SHA-256: `{summary['z3_results_sha256']}`",
        f"- DAC result CSV SHA-256: `{summary['dac_results_sha256']}`",
        f"- Artifact identity audit: Z3 {z3_audit['artifact_refs']} refs / "
        f"{z3_audit['artifact_bytes']} bytes; DAC {dac_audit['artifact_refs']} refs / "
        f"{dac_audit['artifact_bytes']} bytes; zero mismatches",
        "- Detailed cases: `dac25_vs_z3_formal_cases.csv`",
        "- Per-circuit table: `dac25_vs_z3_formal_by_circuit.csv`",
        "- Machine-readable summary: `dac25_vs_z3_formal_summary.csv`",
    ]
    atomic_text(args.output_dir / "DAC25_VS_Z3_FORMAL_REPORT.md", "\n".join(report) + "\n")
    print(
        f"cases={len(common)} z3_pass={z3_pass} dac_pass={dac_pass} "
        f"paired={len(paired_keys)} replayed={len(cec_replay)} output={args.output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
