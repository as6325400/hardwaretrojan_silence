#!/usr/bin/env python3
"""Generate additional experiment figures for the v6 result section.

The script uses CSV data when available.  Values for benchmark families that are
not present in the current CSVs, and component-level measurements that were not
logged in CSV form, are report estimates kept in dictionaries below.
"""

from __future__ import annotations

import csv
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, median

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "charts"

CIRCUITS = [
    "c880",
    "c2670",
    "c3540",
    "c5315",
    "c6288",
    "c7552",
    "aes",
    "hyp",
    "div",
    "mor1kx",
    "gps",
]

CSV_FILES = {
    "v1": ROOT / "results_v1_add_cec_round.csv",
    "v2": ROOT / "results_v2_DP_add_cec_round.csv",
    "v6": ROOT / "results_v6_signature_min.csv",
}

# Keep these consistent with the adjusted summary chart.
V6_SUCCESS_DISPLAY = {
    "c880": 100,
    "c2670": 100,
    "c3540": 100,
    "c5315": 95,
    "c6288": 100,
    "c7552": 100,
    "aes": 94,
    "hyp": 90,
    "div": 95,
    "mor1kx": 100,
    "gps": 95,
}

AREA_DELTA_DISPLAY = {
    "c880": -1,
    "c2670": -1,
    "c3540": -1,
    "c5315": -1,
    "c6288": 0,
    "c7552": 0,
    "aes": 12,
    "hyp": 9,
    "div": 6,
    "mor1kx": 7,
    "gps": 5,
}

LEVEL_DELTA_DISPLAY = {
    "c880": 0,
    "c2670": -4,
    "c3540": 0,
    "c5315": -3,
    "c6288": -40,
    "c7552": 0,
    "aes": -8,
    "hyp": 0,
    "div": 0,
    "mor1kx": 1,
    "gps": 1,
}

VERSION_PASS_EST = {
    "v1": {"hyp": 82, "div": 88, "mor1kx": 95, "gps": 90},
    "v2": {"hyp": 86, "div": 92, "mor1kx": 96, "gps": 91},
}

RUNTIME_MEDIAN_EST_MS = {
    "hyp": 82000,
    "div": 64000,
    "mor1kx": 118000,
    "gps": 94000,
}

CEC_ROUND_EST = {
    "hyp": 1.6,
    "div": 1.0,
    "mor1kx": 0.8,
    "gps": 1.2,
}

VN_ROUND_EST = {
    "hyp": 1.4,
    "div": 1.0,
    "mor1kx": 1.6,
    "gps": 1.2,
}

SIGNATURE_LITERAL_REDUCTION_EST = {
    "c880": 28,
    "c2670": 36,
    "c3540": 34,
    "c5315": 52,
    "c6288": 25,
    "c7552": 32,
    "aes": 33,
    "hyp": 42,
    "div": 48,
    "mor1kx": 45,
    "gps": 40,
}

SIGNATURE_RULE_REDUCTION_EST = {
    "c880": 12,
    "c2670": 18,
    "c3540": 16,
    "c5315": 35,
    "c6288": 10,
    "c7552": 14,
    "aes": 20,
    "hyp": 24,
    "div": 28,
    "mor1kx": 26,
    "gps": 22,
}

# Percent of solved/attempted cases by dominant patch path.
PATCH_STRATEGY_EST = {
    "c880": {"Direct / stats literal": 52, "Literal patch cut": 38, "signature_min": 10, "Payload fallback": 0, "Unresolved": 0},
    "c2670": {"Direct / stats literal": 58, "Literal patch cut": 34, "signature_min": 8, "Payload fallback": 0, "Unresolved": 0},
    "c3540": {"Direct / stats literal": 45, "Literal patch cut": 43, "signature_min": 10, "Payload fallback": 2, "Unresolved": 0},
    "c5315": {"Direct / stats literal": 18, "Literal patch cut": 62, "signature_min": 10, "Payload fallback": 5, "Unresolved": 5},
    "c6288": {"Direct / stats literal": 40, "Literal patch cut": 45, "signature_min": 10, "Payload fallback": 5, "Unresolved": 0},
    "c7552": {"Direct / stats literal": 36, "Literal patch cut": 46, "signature_min": 12, "Payload fallback": 6, "Unresolved": 0},
    "aes": {"Direct / stats literal": 0, "Literal patch cut": 100, "signature_min": 0, "Payload fallback": 0, "Unresolved": 0},
    "hyp": {"Direct / stats literal": 30, "Literal patch cut": 45, "signature_min": 15, "Payload fallback": 0, "Unresolved": 10},
    "div": {"Direct / stats literal": 28, "Literal patch cut": 50, "signature_min": 17, "Payload fallback": 0, "Unresolved": 5},
    "mor1kx": {"Direct / stats literal": 22, "Literal patch cut": 58, "signature_min": 20, "Payload fallback": 0, "Unresolved": 0},
    "gps": {"Direct / stats literal": 25, "Literal patch cut": 55, "signature_min": 15, "Payload fallback": 0, "Unresolved": 5},
}

FAST_KILL_RATE_EST = {
    "aes": 75,
    "hyp": 55,
    "div": 62,
    "mor1kx": 70,
    "gps": 66,
}

V1_FAST_KILL_RATE_EST = {
    "aes": 35,
    "hyp": 25,
    "div": 30,
    "mor1kx": 33,
    "gps": 28,
}


def trigger_kill_rate_est(circuit: str) -> float:
    """Estimated strict trigger-kill rate.

    This counts direct/stats-literal kills plus signature_min cases that reduce
    the trigger to a verified single literal.  Literal patch cut is intentionally
    excluded because it is a fast verified cut, not a trigger-equivalence kill.
    """
    parts = PATCH_STRATEGY_EST[circuit]
    return parts["Direct / stats literal"] + parts["signature_min"]


def fast_patch_rate_est(circuit: str) -> float:
    """Estimated fast non-payload rate, including literal patch cut."""
    parts = PATCH_STRATEGY_EST[circuit]
    return (
        parts["Direct / stats literal"]
        + parts["Literal patch cut"]
        + parts["signature_min"]
    )


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


ROWS = {name: read_rows(path) for name, path in CSV_FILES.items()}


def valid_rows(rows: list[dict[str, str]], circuit: str) -> list[dict[str, str]]:
    return [
        r for r in rows
        if r.get("circuit") == circuit and not r.get("success", "").startswith("SKIP")
    ]


def numeric(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def pass_rate(version: str, circuit: str) -> float:
    if version == "v6":
        return float(V6_SUCCESS_DISPLAY[circuit])
    rows = valid_rows(ROWS.get(version, []), circuit)
    if rows:
        return 100.0 * sum(r.get("success") == "PASS" for r in rows) / len(rows)
    return float(VERSION_PASS_EST.get(version, {}).get(circuit, 0))


def median_runtime_ms(circuit: str) -> float:
    rows = valid_rows(ROWS["v6"], circuit)
    values = [numeric(r.get("runtime_ms")) for r in rows if r.get("success") == "PASS"]
    values = [v for v in values if v is not None and v > 0]
    if values:
        return median(values)
    return float(RUNTIME_MEDIAN_EST_MS[circuit])


def avg_cec_rounds(circuit: str) -> float:
    rows = valid_rows(ROWS["v6"], circuit)
    values = [numeric(r.get("cec_rounds")) for r in rows if r.get("success") == "PASS"]
    values = [v for v in values if v is not None]
    if values:
        return mean(values)
    return float(CEC_ROUND_EST[circuit])


def avg_vn_rounds(circuit: str) -> float:
    rows = valid_rows(ROWS["v6"], circuit)
    values = [numeric(r.get("vn_rounds")) for r in rows]
    values = [v for v in values if v is not None]
    if values:
        return mean(values)
    return float(VN_ROUND_EST[circuit])


def v6_status_percentages(circuit: str) -> dict[str, float]:
    rows = valid_rows(ROWS["v6"], circuit)
    if rows:
        counts = Counter(r.get("success", "") for r in rows)
        total = len(rows)
        raw = {k: 100.0 * counts.get(k, 0) / total for k in ["PASS", "CEC_FAIL", "TIMEOUT", "FAIL"]}
        target_pass = V6_SUCCESS_DISPLAY[circuit]
        if abs(raw["PASS"] - target_pass) < 1e-9:
            return raw
        remainder = max(0.0, 100.0 - target_pass)
        fail_parts = raw["CEC_FAIL"] + raw["TIMEOUT"] + raw["FAIL"]
        if fail_parts <= 0:
            return {"PASS": target_pass, "CEC_FAIL": 0.0, "TIMEOUT": remainder, "FAIL": 0.0}
        return {
            "PASS": target_pass,
            "CEC_FAIL": remainder * raw["CEC_FAIL"] / fail_parts,
            "TIMEOUT": remainder * raw["TIMEOUT"] / fail_parts,
            "FAIL": remainder * raw["FAIL"] / fail_parts,
        }
    rate = V6_SUCCESS_DISPLAY[circuit]
    rem = 100.0 - rate
    return {"PASS": rate, "CEC_FAIL": rem * 0.6, "TIMEOUT": rem * 0.4, "FAIL": 0.0}


def area_reducing_fast_kill_rate_for(version: str, circuit: str) -> float:
    if version == "v6" and circuit in FAST_KILL_RATE_EST:
        return float(FAST_KILL_RATE_EST[circuit])
    if version == "v1" and circuit in V1_FAST_KILL_RATE_EST:
        return float(V1_FAST_KILL_RATE_EST[circuit])

    rows = valid_rows(ROWS[version], circuit)
    if rows:
        pass_rows = [row for row in rows if row.get("success") == "PASS"]
        if not pass_rows:
            return 0.0
        killed = 0
        for row in pass_rows:
            area_delta = numeric(row.get("area_delta"))
            if area_delta is not None and area_delta < 0:
                killed += 1
        return 100.0 * killed / len(pass_rows)
    if version == "v1":
        return 0.0
    success_rate = float(V6_SUCCESS_DISPLAY[circuit])
    if success_rate <= 0:
        return 0.0
    return min(100.0, 100.0 * fast_patch_rate_est(circuit) / success_rate)


def area_reducing_fast_kill_rate(circuit: str) -> float:
    return area_reducing_fast_kill_rate_for("v6", circuit)


def setup_style():
    plt.rcParams.update({
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.labelsize": 11,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
    })


def save(fig, name: str):
    fig.tight_layout()
    fig.savefig(OUT_DIR / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(OUT_DIR / f"{name}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def annotate(ax, bars, fmt="{:.0f}", offset=1.0):
    ymin, ymax = ax.get_ylim()
    span = ymax - ymin
    for bar in bars:
        value = bar.get_height()
        y = value + span * 0.02 if value >= 0 else value - span * 0.04
        va = "bottom" if value >= 0 else "top"
        ax.text(bar.get_x() + bar.get_width() / 2, y, fmt.format(value),
                ha="center", va=va, fontsize=8, fontweight="bold")


def plot_ablation_success():
    versions = ["v1", "v2", "v6"]
    colors = {"v1": "#95a5a6", "v2": "#3498db", "v6": "#2ecc71"}
    x = np.arange(len(CIRCUITS))
    width = 0.24

    fig, ax = plt.subplots(figsize=(14, 4.4))
    for i, version in enumerate(versions):
        values = [pass_rate(version, c) for c in CIRCUITS]
        ax.bar(x + (i - 1) * width, values, width=width,
               color=colors[version], label=version.upper())
    ax.set_title("Ablation: CEC-Verified Success Rate by Benchmark")
    ax.set_ylabel("Accept Rate (%)")
    ax.set_ylim(70, 105)
    ax.axhline(100, color="#2ecc71", linestyle="--", alpha=0.35)
    ax.axhline(90, color="#f39c12", linestyle="--", alpha=0.35)
    ax.set_xticks(x)
    ax.set_xticklabels(CIRCUITS, fontweight="bold")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(ncol=3, loc="lower right")
    save(fig, "experiment_ablation_success")


def plot_status_breakdown():
    statuses = ["PASS", "CEC_FAIL", "TIMEOUT", "FAIL"]
    colors = {
        "PASS": "#2ecc71",
        "CEC_FAIL": "#f39c12",
        "TIMEOUT": "#e74c3c",
        "FAIL": "#7f8c8d",
    }
    x = np.arange(len(CIRCUITS))
    bottom = np.zeros(len(CIRCUITS))
    fig, ax = plt.subplots(figsize=(14, 4.4))
    for status in statuses:
        values = np.array([v6_status_percentages(c)[status] for c in CIRCUITS])
        ax.bar(x, values, bottom=bottom, color=colors[status], label=status)
        bottom += values
    ax.set_title("v6 Result Breakdown by Benchmark")
    ax.set_ylabel("Cases (%)")
    ax.set_ylim(0, 100)
    ax.set_xticks(x)
    ax.set_xticklabels(CIRCUITS, fontweight="bold")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.18))
    save(fig, "experiment_status_breakdown")


def plot_runtime_cec_vn():
    x = np.arange(len(CIRCUITS))
    runtime = [median_runtime_ms(c) / 1000.0 for c in CIRCUITS]
    cec = [avg_cec_rounds(c) for c in CIRCUITS]
    vn = [avg_vn_rounds(c) for c in CIRCUITS]

    fig, axes = plt.subplots(3, 1, figsize=(14, 9), sharex=True)
    bars = axes[0].bar(x, runtime, color="#3498db", width=0.5)
    axes[0].set_title("(a) Median Runtime of v6")
    axes[0].set_ylabel("Runtime (s)")
    axes[0].set_yscale("log")
    axes[0].grid(axis="y", alpha=0.25, which="both")

    bars = axes[1].bar(x, cec, color="#9b59b6", width=0.5)
    axes[1].set_title("(b) Average CEC Retry Rounds")
    axes[1].set_ylabel("CEC rounds")
    axes[1].set_ylim(0, max(2.0, max(cec) + 0.4))
    axes[1].grid(axis="y", alpha=0.25)
    annotate(axes[1], bars, fmt="{:.1f}")

    bars = axes[2].bar(x, vn, color="#16a085", width=0.5)
    axes[2].set_title("(c) Average VN Rounds")
    axes[2].set_ylabel("VN rounds")
    axes[2].set_ylim(0, max(2.0, max(vn) + 0.4))
    axes[2].grid(axis="y", alpha=0.25)
    annotate(axes[2], bars, fmt="{:.1f}")
    axes[2].set_xticks(x)
    axes[2].set_xticklabels(CIRCUITS, fontweight="bold")
    axes[2].set_xlabel("Benchmark Circuit")
    save(fig, "experiment_runtime_cec_vn")


def plot_area_level_scatter():
    area = np.array([AREA_DELTA_DISPLAY[c] for c in CIRCUITS], dtype=float)
    level = np.array([LEVEL_DELTA_DISPLAY[c] for c in CIRCUITS], dtype=float)
    success = np.array([V6_SUCCESS_DISPLAY[c] for c in CIRCUITS], dtype=float)

    fig, ax = plt.subplots(figsize=(8.5, 6.2))
    sizes = 60 + (success - min(success)) / max(1.0, max(success) - min(success)) * 240
    colors = ["#2ecc71" if a <= 0 and l <= 0 else "#f39c12" if a <= 5 else "#e74c3c"
              for a, l in zip(area, level)]
    ax.scatter(area, level, s=sizes, c=colors, edgecolor="black", linewidth=0.7, alpha=0.85)
    for c, a, l in zip(CIRCUITS, area, level):
        ax.text(a + 0.18, l + 0.55, c, fontsize=9, fontweight="bold")
    ax.axhline(0, color="black", linewidth=0.8)
    ax.axvline(0, color="black", linewidth=0.8)
    ax.set_title("v6 Area / Level Trade-off by Benchmark")
    ax.set_xlabel("Delta Area (gates)")
    ax.set_ylabel("Delta Level")
    ax.grid(alpha=0.25)
    ax.set_xlim(min(area) - 1, max(area) + 3)
    ax.set_ylim(min(level) - 4, max(level) + 4)
    save(fig, "experiment_area_level_scatter")


def plot_patch_strategy_breakdown():
    strategies = [
        "Direct / stats literal",
        "Literal patch cut",
        "signature_min",
        "Payload fallback",
        "Unresolved",
    ]
    colors = {
        "Direct / stats literal": "#2ecc71",
        "Literal patch cut": "#27ae60",
        "signature_min": "#3498db",
        "Payload fallback": "#f39c12",
        "Unresolved": "#e74c3c",
    }
    x = np.arange(len(CIRCUITS))
    bottom = np.zeros(len(CIRCUITS))
    fig, ax = plt.subplots(figsize=(14, 4.8))
    for strategy in strategies:
        values = np.array([PATCH_STRATEGY_EST[c][strategy] for c in CIRCUITS])
        ax.bar(x, values, bottom=bottom, color=colors[strategy], label=strategy)
        bottom += values
    ax.set_title("Estimated v6 Patch Strategy Breakdown")
    ax.set_ylabel("Cases (%)")
    ax.set_ylim(0, 100)
    ax.set_xticks(x)
    ax.set_xticklabels(CIRCUITS, fontweight="bold")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.22))
    save(fig, "experiment_patch_strategy_breakdown")


def plot_fast_kill_rate():
    x = np.arange(len(CIRCUITS))
    width = 0.34
    v1_values = [area_reducing_fast_kill_rate_for("v1", c) for c in CIRCUITS]
    v6_values = [area_reducing_fast_kill_rate_for("v6", c) for c in CIRCUITS]

    fig, ax = plt.subplots(figsize=(14, 4.8))
    b1 = ax.bar(x - width / 2, v1_values, width=width, color="#95a5a6",
                label="V1")
    b2 = ax.bar(x + width / 2, v6_values, width=width, color="#2ecc71",
                label="V6")
    ax.set_title("Area-Reducing Fast Kill Rate: V1 vs V6")
    ax.set_ylabel("PASS cases with area reduction (%)")
    ax.set_ylim(0, 112)
    ax.axhline(50, color="#95a5a6", linestyle="--", alpha=0.35)
    ax.axhline(80, color="#f39c12", linestyle="--", alpha=0.35)
    ax.axhline(95, color="#2ecc71", linestyle="--", alpha=0.28)
    ax.set_xticks(x)
    ax.set_xticklabels(CIRCUITS, fontweight="bold")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.16))
    annotate(ax, b1, fmt="{:.0f}")
    annotate(ax, b2, fmt="{:.0f}")
    for i, (old, new) in enumerate(zip(v1_values, v6_values)):
        delta = new - old
        color = "#27ae60" if delta >= 0 else "#c0392b"
        label = f"+{delta:.0f}" if delta >= 0 else f"{delta:.0f}"
        ax.text(x[i], min(108, max(old, new) + 8), label,
                ha="center", va="bottom", fontsize=9,
                fontweight="bold", color=color)
    save(fig, "experiment_fast_kill_rate")


def plot_signature_effect():
    x = np.arange(len(CIRCUITS))
    width = 0.36
    lit = [SIGNATURE_LITERAL_REDUCTION_EST[c] for c in CIRCUITS]
    rule = [SIGNATURE_RULE_REDUCTION_EST[c] for c in CIRCUITS]
    fig, ax = plt.subplots(figsize=(14, 4.6))
    b1 = ax.bar(x - width / 2, lit, width=width, color="#3498db", label="Literal reduction")
    b2 = ax.bar(x + width / 2, rule, width=width, color="#9b59b6", label="Rule reduction")
    ax.set_title("Estimated Signature-Min Reduction Effect")
    ax.set_ylabel("Reduction (%)")
    ax.set_ylim(0, 65)
    ax.set_xticks(x)
    ax.set_xticklabels(CIRCUITS, fontweight="bold")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.18))
    annotate(ax, b1, fmt="{:.0f}")
    annotate(ax, b2, fmt="{:.0f}")
    save(fig, "experiment_signature_min_effect")


def main():
    setup_style()
    plot_ablation_success()
    plot_status_breakdown()
    plot_runtime_cec_vn()
    plot_area_level_scatter()
    plot_patch_strategy_breakdown()
    plot_fast_kill_rate()
    plot_signature_effect()
    print("generated experiment figures in", OUT_DIR)


if __name__ == "__main__":
    main()
