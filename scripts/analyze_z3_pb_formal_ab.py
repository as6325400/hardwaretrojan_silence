#!/usr/bin/env python3
"""Create paired A/B/C CSVs for Z3-PB formal-refinement experiments.

A is the original 4722754 binary, B is the backport binary with formal
refinement disabled, and C is the exact same backport binary with refinement
enabled.  Consequently B versus C is the clean formal-feedback ablation.
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
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


Key = Tuple[str, str]


def read_rows(path: Path) -> Dict[Key, Dict[str, str]]:
    with path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    indexed = {(row["circuit"], row["trojan"]): row for row in rows}
    if len(indexed) != len(rows):
        raise RuntimeError(f"duplicate case keys in {path}")
    return indexed


def number(row: Mapping[str, str], name: str) -> Optional[float]:
    value = row.get(name, "").strip()
    if not value:
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def integer(row: Mapping[str, str], name: str) -> int:
    value = number(row, name)
    return int(round(value)) if value is not None else 0


def geomean(values: Sequence[float]) -> Optional[float]:
    positive = [value for value in values if value > 0 and math.isfinite(value)]
    return math.exp(sum(map(math.log, positive)) / len(positive)) if positive else None


def mcnemar(gains: int, regressions: int) -> Optional[float]:
    n = gains + regressions
    if not n:
        return None
    tail = sum(math.comb(n, i) for i in range(min(gains, regressions) + 1)) / 2**n
    return min(1.0, 2 * tail)


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> Tuple[float, float]:
    if total == 0:
        return math.nan, math.nan
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(
        proportion * (1 - proportion) / total + z * z / (4 * total * total)
    ) / denominator
    return center - radius, center + radius


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


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def command_has_formal(row: Mapping[str, str]) -> bool:
    try:
        return "--rule-formal-refine" in json.loads(row["command_json"])
    except (KeyError, json.JSONDecodeError):
        return False


def paired(label: str, old: Mapping[Key, Mapping[str, str]], new: Mapping[Key, Mapping[str, str]], keys: Sequence[Key]) -> Dict[str, Any]:
    old_pass = sum(old[key]["status"] == "PASS" for key in keys)
    new_pass = sum(new[key]["status"] == "PASS" for key in keys)
    gains = sum(old[key]["status"] != "PASS" and new[key]["status"] == "PASS" for key in keys)
    regressions = sum(old[key]["status"] == "PASS" and new[key]["status"] != "PASS" for key in keys)
    both = [key for key in keys if old[key]["status"] == new[key]["status"] == "PASS"]
    runtime_pairs = []
    wall_pairs = []
    for key in both:
        old_runtime, new_runtime = number(old[key], "runtime_ms"), number(new[key], "runtime_ms")
        old_wall, new_wall = number(old[key], "wall_ms"), number(new[key], "wall_ms")
        if old_runtime and new_runtime:
            runtime_pairs.append((old_runtime, new_runtime))
        if old_wall and new_wall:
            wall_pairs.append((old_wall, new_wall))
    runtime_ratios = [old_value / new_value for old_value, new_value in runtime_pairs]
    wall_ratios = [old_value / new_value for old_value, new_value in wall_pairs]
    return {
        "comparison": label, "cases": len(keys), "old_pass": old_pass,
        "new_pass": new_pass, "pass_delta_pp": 100 * (new_pass - old_pass) / len(keys),
        "gains": gains, "regressions": regressions, "both_pass": len(both),
        "mcnemar_exact_p": mcnemar(gains, regressions),
        "runtime_pairs": len(runtime_pairs),
        "old_runtime_sum_ms": sum(pair[0] for pair in runtime_pairs),
        "new_runtime_sum_ms": sum(pair[1] for pair in runtime_pairs),
        "old_over_new_runtime_median": statistics.median(runtime_ratios) if runtime_ratios else None,
        "old_over_new_runtime_geomean": geomean(runtime_ratios),
        "new_runtime_wins": sum(new_value < old_value for old_value, new_value in runtime_pairs),
        "old_over_new_wall_geomean": geomean(wall_ratios),
        "old_dt_builds": sum(integer(old[key], "summary_numeric_sum_dt_builds") for key in keys),
        "new_dt_builds": sum(integer(new[key], "summary_numeric_sum_dt_builds") for key in keys),
        "old_cec_rounds": sum(integer(old[key], "cec_rounds") for key in keys),
        "new_cec_rounds": sum(integer(new[key], "cec_rounds") for key in keys),
        "both_pass_old_dt_builds": sum(
            integer(old[key], "summary_numeric_sum_dt_builds") for key in both
        ),
        "both_pass_new_dt_builds": sum(
            integer(new[key], "summary_numeric_sum_dt_builds") for key in both
        ),
        "both_pass_old_cec_rounds": sum(integer(old[key], "cec_rounds") for key in both),
        "both_pass_new_cec_rounds": sum(integer(new[key], "cec_rounds") for key in both),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-results", type=Path, required=True)
    parser.add_argument("--backport-results", type=Path, required=True)
    parser.add_argument("--formal-results", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--require-cases", type=int)
    args = parser.parse_args()
    arms = {
        "A_original": read_rows(args.baseline_results),
        "B_backport_off": read_rows(args.backport_results),
        "C_formal_on": read_rows(args.formal_results),
    }
    common = sorted(set.intersection(*(set(rows) for rows in arms.values())))
    if args.require_cases is not None and len(common) != args.require_cases:
        raise RuntimeError(f"expected {args.require_cases} common cases, found {len(common)}")
    if not common:
        raise RuntimeError("no common cases")
    if any(set(rows) != set(common) for rows in arms.values()):
        sizes = {label: len(rows) for label, rows in arms.items()}
        raise RuntimeError(f"A/B/C case sets differ: common={len(common)} sizes={sizes}")
    for label, rows in arms.items():
        for key in common:
            if rows[key].get("method") != "z3-pb":
                raise RuntimeError(f"{label}/{key} is not z3-pb")
    b_hashes = {arms["B_backport_off"][key]["binary_sha256"] for key in common}
    c_hashes = {arms["C_formal_on"][key]["binary_sha256"] for key in common}
    if len(b_hashes) != 1 or b_hashes != c_hashes:
        raise RuntimeError(f"B/C binary mismatch: B={b_hashes} C={c_hashes}")
    if any(command_has_formal(arms["B_backport_off"][key]) for key in common):
        raise RuntimeError("B contains a formal-refinement command")
    if not all(command_has_formal(arms["C_formal_on"][key]) for key in common):
        raise RuntimeError("C is missing a formal-refinement command")
    abc_hashes = {
        rows[key]["abc_sha256"] for rows in arms.values() for key in common
    }
    if len(abc_hashes) != 1:
        raise RuntimeError(f"ABC identity mismatch: {abc_hashes}")

    case_fields = [
        "circuit", "trojan", "a_status", "b_status", "c_status",
        "a_runtime_ms", "b_runtime_ms", "c_runtime_ms", "b_over_c_runtime",
        "a_cec_rounds", "b_cec_rounds", "c_cec_rounds",
        "a_dt_builds", "b_dt_builds", "c_dt_builds",
        "b_effective_rules", "b_effective_literals", "b_effective_depth",
        "c_effective_rules", "c_effective_literals", "c_effective_depth",
        "formal_miter_status", "formal_miter_added", "formal_miter_fn",
        "formal_miter_fp", "formal_miter_retries", "formal_miter_proved",
        "formal_miter_total_ms",
    ]
    case_rows: List[Dict[str, Any]] = []
    for key in common:
        a, b, c = (arms[name][key] for name in arms)
        b_runtime, c_runtime = number(b, "runtime_ms"), number(c, "runtime_ms")
        case_rows.append(
            {
                "circuit": key[0], "trojan": key[1],
                "a_status": a["status"], "b_status": b["status"], "c_status": c["status"],
                "a_runtime_ms": a.get("runtime_ms", ""), "b_runtime_ms": b.get("runtime_ms", ""),
                "c_runtime_ms": c.get("runtime_ms", ""),
                "b_over_c_runtime": b_runtime / c_runtime if b_runtime and c_runtime else "",
                "a_cec_rounds": a.get("cec_rounds", ""), "b_cec_rounds": b.get("cec_rounds", ""),
                "c_cec_rounds": c.get("cec_rounds", ""),
                "a_dt_builds": a.get("summary_numeric_sum_dt_builds", ""),
                "b_dt_builds": b.get("summary_numeric_sum_dt_builds", ""),
                "c_dt_builds": c.get("summary_numeric_sum_dt_builds", ""),
                "b_effective_rules": b.get("apply_last_effective_rules", ""),
                "b_effective_literals": b.get("apply_last_effective_literals", ""),
                "b_effective_depth": b.get("apply_last_effective_depth", ""),
                "c_effective_rules": c.get("apply_last_effective_rules", ""),
                "c_effective_literals": c.get("apply_last_effective_literals", ""),
                "c_effective_depth": c.get("apply_last_effective_depth", ""),
                "formal_miter_status": c.get("miter_last_status", ""),
                "formal_miter_added": c.get("miter_numeric_sum_added", ""),
                "formal_miter_fn": c.get("miter_numeric_sum_returned_fn", ""),
                "formal_miter_fp": c.get("miter_numeric_sum_returned_fp", ""),
                "formal_miter_retries": c.get("miter_numeric_sum_retry", ""),
                "formal_miter_proved": c.get("miter_numeric_sum_proved", ""),
                "formal_miter_total_ms": c.get("miter_numeric_sum_total_ms", ""),
            }
        )
    summary = [
        paired("A_original_to_B_backport_off", arms["A_original"], arms["B_backport_off"], common),
        paired("B_backport_off_to_C_formal_on", arms["B_backport_off"], arms["C_formal_on"], common),
        paired("A_original_to_C_formal_on", arms["A_original"], arms["C_formal_on"], common),
    ]
    summary_fields = list(summary[0])
    output = args.output_dir
    atomic_csv(output / "z3_pb_formal_ab_cases.csv", case_rows, case_fields)
    atomic_csv(output / "z3_pb_formal_ab_summary.csv", summary, summary_fields)

    by_circuit_rows: List[Dict[str, Any]] = []
    for circuit in sorted({key[0] for key in common}):
        circuit_keys = [key for key in common if key[0] == circuit]
        row = paired(
            "B_backport_off_to_C_formal_on",
            arms["B_backport_off"], arms["C_formal_on"], circuit_keys,
        )
        row["circuit"] = circuit
        by_circuit_rows.append(row)
    atomic_csv(
        output / "z3_pb_formal_ab_by_circuit.csv",
        by_circuit_rows,
        ["circuit", *summary_fields],
    )

    c_rows = arms["C_formal_on"]
    final_miter = Counter(c_rows[key].get("miter_last_status", "unparsed") for key in common)
    total_cex = sum(integer(c_rows[key], "miter_numeric_sum_added") for key in common)
    total_fn = sum(integer(c_rows[key], "miter_numeric_sum_returned_fn") for key in common)
    total_fp = sum(integer(c_rows[key], "miter_numeric_sum_returned_fp") for key in common)
    cases_with_cex = sum(integer(c_rows[key], "miter_numeric_sum_added") > 0 for key in common)
    total_retries = sum(integer(c_rows[key], "miter_numeric_sum_retry") for key in common)
    arm_stats = []
    for label, rows in arms.items():
        passed = sum(rows[key]["status"] == "PASS" for key in common)
        low, high = wilson(passed, len(common))
        arm_stats.append((label, passed, low, high, Counter(rows[key]["status"] for key in common)))
    bc_gains = [
        key for key in common
        if arms["B_backport_off"][key]["status"] != "PASS"
        and arms["C_formal_on"][key]["status"] == "PASS"
    ]
    bc_regressions = [
        key for key in common
        if arms["B_backport_off"][key]["status"] == "PASS"
        and arms["C_formal_on"][key]["status"] != "PASS"
    ]
    lines = [
        "# Z3-PB formal-refinement A/B/C\n",
        f"- Common cases: {len(common)}",
        f"- B/C binary SHA-256: `{next(iter(b_hashes))}`",
        f"- ABC SHA-256: `{next(iter(abc_hashes))}`",
        f"- Formal CEX added: {total_cex} (FN {total_fn}, FP {total_fp}) across "
        f"{cases_with_cex} cases and {total_retries} refinement retries",
        f"- Final miter status: `{dict(sorted(final_miter.items()))}`",
        "\n## Arm outcomes\n",
        "| Arm | PASS | rate | Wilson 95% | status counts |",
        "|---|---:|---:|---:|---|",
    ]
    for label, passed, low, high, statuses in arm_stats:
        lines.append(
            f"| {label} | {passed}/{len(common)} | {100*passed/len(common):.2f}% | "
            f"{100*low:.2f}–{100*high:.2f}% | `{dict(sorted(statuses.items()))}` |"
        )
    lines.extend(
        [
            "\n## Paired comparisons\n",
            "| Comparison | old PASS | new PASS | gains | regressions | runtime geo old/new "
            "(both PASS) | DT all | CEC all |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in summary:
        ratio = row["old_over_new_runtime_geomean"]
        ratio_text = f"{ratio:.3f}" if ratio is not None else ""
        lines.append(
            f"| {row['comparison']} | {row['old_pass']} | {row['new_pass']} | "
            f"{row['gains']} | {row['regressions']} | {ratio_text} | "
            f"{row['old_dt_builds']}→{row['new_dt_builds']} | "
            f"{row['old_cec_rounds']}→{row['new_cec_rounds']} |"
        )
    lines.extend(
        [
            "\n## Clean B→C status changes\n",
            "Gains: " + (", ".join(f"`{c}/{t}`" for c, t in bc_gains) or "none") + ".",
            "Regressions: " + (", ".join(f"`{c}/{t}`" for c, t in bc_regressions) or "none") + ".",
            "\nB versus C isolates the formal flag on the same binary. External ABC CEC is the "
            "success authority; a skipped rule miter is not an E↔R proof. Runtime ratios and "
            "runtime sums use only cases that PASS in both arms; the DT/CEC columns explicitly "
            "sum the full 482-case cohort.",
            "\n## Input identities\n",
            f"- A results: `{sha256(args.baseline_results)}`",
            f"- B results: `{sha256(args.backport_results)}`",
            f"- C results: `{sha256(args.formal_results)}`",
        ]
    )
    atomic_text(output / "Z3_PB_FORMAL_AB_REPORT.md", "\n".join(lines) + "\n")
    print(f"formal_ab={output} common={len(common)} C_status={dict(final_miter)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
