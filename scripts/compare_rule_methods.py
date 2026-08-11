#!/usr/bin/env python3
"""Reproducible A/B runner for hardware-Trojan rule synthesis methods.

The runner deliberately stores only references and fingerprints for the large
V0 benchmark/ground-truth inputs.  Each case/method invocation gets independent
stdout, stderr, external-CEC, patched-bench, and JSON record artifacts.  The
aggregate CSV and JSON files are rebuilt atomically from those records, making
an interrupted run resumable without trusting a partially written CSV.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


RUNNER_SCHEMA_VERSION = "rule-method-ab-run/2"
MANIFEST_SCHEMA_VERSION = "rule-method-ab-cases/1"
SUMMARY_SCHEMA_VERSION = "rule-method-ab-summary/2"
DEFAULT_MANIFEST = Path("configs/rule_method_ab_cases.json")
DEFAULT_OUTPUT_ROOT = Path("validation/rule_method_ab")
DEFAULT_METHODS = ("vn-retrain", "z3-pb")
SUPPORTED_METHODS = ("vn-retrain", "dt", "z3-pb", "milp-cover")


class RunnerError(RuntimeError):
    """Raised for malformed configuration or an unsafe experiment setup."""


@dataclass(frozen=True)
class DatasetRoots:
    golden: Path
    trojan: Path
    groundtruth: Path


@dataclass(frozen=True)
class CaseSpec:
    ordinal: int
    case_id: str
    circuit: str
    trojan: str
    cohort: str
    timeout_seconds: float
    legacy_v6: Mapping[str, Any]


@dataclass(frozen=True)
class CasePaths:
    golden: Path
    trojan: Path
    groundtruth: Path


@dataclass(frozen=True)
class PreparedRun:
    schedule_ordinal: int
    method_ordinal: int
    profile: str
    case: CaseSpec
    paths: CasePaths
    method: str
    timeout_seconds: float
    command: Tuple[str, ...]
    cache_key: str
    identities: Mapping[str, Any]


@dataclass(frozen=True)
class ProcessResult:
    returncode: Optional[int]
    timed_out: bool
    wall_ms: float
    launch_error: Optional[str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "wb") as sink:
            sink.write(payload)
            sink.flush()
            os.fsync(sink.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _atomic_write_json(path: Path, value: Any) -> None:
    _atomic_write_bytes(path, _json_bytes(value))


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RunnerError(f"JSON root must be an object: {path}")
    return value


def _safe_component(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise RunnerError(f"unsafe {label}: {value!r}")
    return value


def _resolve_under(root: Path, relative: str, label: str) -> Path:
    raw = Path(relative)
    if raw.is_absolute() or ".." in raw.parts:
        raise RunnerError(f"{label} must be a safe relative path: {relative!r}")
    resolved_root = root.resolve()
    resolved = (resolved_root / raw).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise RunnerError(f"{label} escapes repository root: {relative!r}") from exc
    return resolved


def _positive_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RunnerError(f"{label} must be a positive number")
    parsed = float(value)
    if parsed <= 0:
        raise RunnerError(f"{label} must be a positive number")
    return parsed


def load_manifest(
    path: Path, repo_root: Path, profile: str
) -> Tuple[DatasetRoots, List[str], List[CaseSpec], str]:
    raw_bytes = path.read_bytes()
    try:
        manifest = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise RunnerError(f"cannot parse manifest {path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise RunnerError("manifest root must be an object")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise RunnerError(
            f"unsupported manifest schema {manifest.get('schema_version')!r}; "
            f"expected {MANIFEST_SCHEMA_VERSION!r}"
        )

    dataset = manifest.get("dataset")
    if not isinstance(dataset, dict):
        raise RunnerError("manifest.dataset must be an object")
    roots = DatasetRoots(
        golden=_resolve_under(repo_root, str(dataset.get("golden_root", "")),
                              "dataset.golden_root"),
        trojan=_resolve_under(repo_root, str(dataset.get("trojan_root", "")),
                              "dataset.trojan_root"),
        groundtruth=_resolve_under(
            repo_root, str(dataset.get("groundtruth_root", "")),
            "dataset.groundtruth_root"
        ),
    )

    common_args = manifest.get("common_args", [])
    if not isinstance(common_args, list) or not all(
        isinstance(value, str) for value in common_args
    ):
        raise RunnerError("manifest.common_args must be an array of strings")

    raw_cases = manifest.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise RunnerError("manifest.cases must be a non-empty array")
    by_id: Dict[str, CaseSpec] = {}
    for ordinal, raw_case in enumerate(raw_cases):
        if not isinstance(raw_case, dict):
            raise RunnerError(f"manifest.cases[{ordinal}] must be an object")
        case_id = _safe_component(str(raw_case.get("case_id", "")), "case_id")
        circuit = _safe_component(str(raw_case.get("circuit", "")), "circuit")
        trojan = _safe_component(str(raw_case.get("trojan", "")), "trojan")
        cohort = _safe_component(str(raw_case.get("cohort", "")), "cohort")
        if case_id in by_id:
            raise RunnerError(f"duplicate case_id in manifest: {case_id}")
        legacy = raw_case.get("legacy_v6", {})
        if not isinstance(legacy, dict):
            raise RunnerError(f"legacy_v6 for {case_id} must be an object")
        by_id[case_id] = CaseSpec(
            ordinal=ordinal,
            case_id=case_id,
            circuit=circuit,
            trojan=trojan,
            cohort=cohort,
            timeout_seconds=_positive_number(
                raw_case.get("timeout_seconds"),
                f"timeout_seconds for {case_id}",
            ),
            legacy_v6=dict(legacy),
        )

    profiles = manifest.get("profiles")
    if not isinstance(profiles, dict):
        raise RunnerError("manifest.profiles must be an object")
    selected_ids = profiles.get(profile)
    if not isinstance(selected_ids, list) or not selected_ids:
        raise RunnerError(f"profile {profile!r} is missing or empty")
    if len(selected_ids) != len(set(selected_ids)):
        raise RunnerError(f"profile {profile!r} contains duplicate case IDs")
    selected: List[CaseSpec] = []
    for case_id in selected_ids:
        if not isinstance(case_id, str) or case_id not in by_id:
            raise RunnerError(
                f"profile {profile!r} references unknown case {case_id!r}"
            )
        selected.append(by_id[case_id])
    return roots, list(common_args), selected, _sha256_bytes(raw_bytes)


def _case_paths(roots: DatasetRoots, case: CaseSpec) -> CasePaths:
    return CasePaths(
        golden=roots.golden / f"{case.circuit}.bench",
        trojan=roots.trojan / case.circuit / f"{case.trojan}.bench",
        groundtruth=(
            roots.groundtruth
            / case.circuit
            / f"{case.trojan}_error_patterns.json"
        ),
    )


def _file_identity(path: Path) -> Dict[str, Any]:
    try:
        stat = path.stat()
    except OSError as exc:
        raise RunnerError(f"required file is unavailable: {path}: {exc}") from exc
    if not path.is_file():
        raise RunnerError(f"required path is not a file: {path}")
    return {
        "path": str(path),
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": _sha256_file(path),
    }


def _parse_scalar(value: str) -> Any:
    if re.fullmatch(r"[-+]?\d+", value):
        try:
            return int(value)
        except ValueError:
            pass
    if re.fullmatch(
        r"[-+]?(?:\d+\.\d*|\d*\.\d+|\d+)(?:[eE][-+]?\d+)?", value
    ):
        try:
            return float(value)
        except ValueError:
            pass
    if value == "true":
        return True
    if value == "false":
        return False
    if value == "null":
        return None
    return value


def parse_rule_synth_summaries(stdout: str) -> List[Dict[str, Any]]:
    """Parse every order-independent key/value rule_synth_summary line."""
    summaries: List[Dict[str, Any]] = []
    for line_number, line in enumerate(stdout.splitlines(), start=1):
        if not line.startswith("rule_synth_summary "):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            summaries.append(
                {"_raw": line, "_line": line_number, "_parse_error": str(exc)}
            )
            continue
        parsed: Dict[str, Any] = {"_raw": line, "_line": line_number}
        tail = tokens[1:]
        if len(tail) % 2:
            parsed["_parse_error"] = "odd number of key/value tokens"
            parsed["_unparsed_tail"] = tail[-1]
            tail = tail[:-1]
        for index in range(0, len(tail), 2):
            parsed[tail[index]] = _parse_scalar(tail[index + 1])
        summaries.append(parsed)
    return summaries


def parse_rule_apply_summaries(stdout: str) -> List[Dict[str, Any]]:
    """Parse every order-independent rule_apply_summary line."""
    summaries: List[Dict[str, Any]] = []
    for line_number, line in enumerate(stdout.splitlines(), start=1):
        if not line.startswith("rule_apply_summary "):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            summaries.append(
                {"_raw": line, "_line": line_number, "_parse_error": str(exc)}
            )
            continue
        parsed: Dict[str, Any] = {"_raw": line, "_line": line_number}
        tail = tokens[1:]
        if len(tail) % 2:
            parsed["_parse_error"] = "odd number of key/value tokens"
            parsed["_unparsed_tail"] = tail[-1]
            tail = tail[:-1]
        for index in range(0, len(tail), 2):
            parsed[tail[index]] = _parse_scalar(tail[index + 1])
        summaries.append(parsed)
    return summaries


def _summary_aggregates(
    summaries: Sequence[Mapping[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    if not summaries:
        return {"first": {}, "last": {}, "numeric_sum": {}}
    ignored = {"_raw", "_line", "_parse_error", "_unparsed_tail"}
    first = {key: value for key, value in summaries[0].items() if key not in ignored}
    last = {key: value for key, value in summaries[-1].items() if key not in ignored}
    sums: Dict[str, float] = {}
    all_integral: Dict[str, bool] = {}
    for summary in summaries:
        for key, value in summary.items():
            if key in ignored or isinstance(value, bool) or not isinstance(
                value, (int, float)
            ):
                continue
            sums[key] = sums.get(key, 0.0) + float(value)
            all_integral[key] = all_integral.get(key, True) and isinstance(value, int)
    numeric_sum: Dict[str, Any] = {
        key: int(value) if all_integral.get(key, False) else value
        for key, value in sums.items()
    }
    return {"first": first, "last": last, "numeric_sum": numeric_sum}


def parse_main_output(stdout: str, stderr: str) -> Dict[str, Any]:
    summaries = parse_rule_synth_summaries(stdout)
    apply_summaries = parse_rule_apply_summaries(stdout)
    runtime_matches = re.findall(
        r"\[TIMING\]\s+TOTAL:\s+([0-9]+(?:\.[0-9]+)?)\s+ms", stderr
    )
    cec_matches = re.findall(r"^cec_rounds\s+(\d+)\s*$", stdout, re.MULTILINE)
    payload_matches = re.findall(
        r"^payload_fix_selected\s+(-?\d+).*?\barea_delta\s+(-?\d+)"
        r".*?\blevel_delta\s+(-?\d+)",
        stdout,
        re.MULTILINE,
    )
    payload: Dict[str, Any] = {}
    if payload_matches:
        count, area, level = payload_matches[-1]
        payload = {
            "selected_nodes": int(count),
            "area_delta": int(area),
            "level_delta": int(level),
        }
    verify_pass = bool(
        re.search(
            r"(?:final_verify|kill_verify|trigger_sig_kill_verify):.*\bPASS\b",
            stderr,
        )
        or "vn_expand_kill+verify+write" in stderr
    )
    return {
        "rule_synth_summaries": summaries,
        "rule_synth_aggregates": _summary_aggregates(summaries),
        "rule_synth_summary_count": len(summaries),
        "rule_apply_summaries": apply_summaries,
        "rule_apply_aggregates": _summary_aggregates(apply_summaries),
        "rule_apply_summary_count": len(apply_summaries),
        "runtime_ms": float(runtime_matches[-1]) if runtime_matches else None,
        "cec_rounds": int(cec_matches[-1]) if cec_matches else None,
        "gt_verify": "PASS" if verify_pass else "FAIL",
        "legacy_vn_passes": len(
            re.findall(r"^vn_iter[0-9]+_rules\s", stdout, re.MULTILINE)
        ),
        "payload_fix": payload,
    }


def _temporary_sibling(path: Path, suffix: str = ".tmp") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=suffix, dir=str(path.parent)
    )
    os.close(fd)
    return Path(raw)


def _abc_quote_path(path: Path) -> str:
    """Quote one filename for ABC's command parser (not for a shell)."""
    value = str(path)
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise RunnerError(f"ABC path contains a control character: {path}")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _terminate_process_group(process: subprocess.Popen[Any]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        process.terminate()
    try:
        process.wait(timeout=1.0)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        process.kill()
    process.wait()


def _run_logged_process(
    command: Sequence[str],
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: float,
    env: Mapping[str, str],
) -> ProcessResult:
    stdout_tmp = _temporary_sibling(stdout_path)
    stderr_tmp = _temporary_sibling(stderr_path)
    started = time.monotonic()
    process: Optional[subprocess.Popen[Any]] = None
    launch_error: Optional[str] = None
    timed_out = False
    returncode: Optional[int] = None
    try:
        with stdout_tmp.open("wb") as stdout_sink, stderr_tmp.open("wb") as stderr_sink:
            try:
                process = subprocess.Popen(
                    list(command),
                    stdout=stdout_sink,
                    stderr=stderr_sink,
                    env=dict(env),
                    start_new_session=True,
                )
            except OSError as exc:
                launch_error = str(exc)
                stderr_sink.write(f"runner launch error: {exc}\n".encode("utf-8"))
            if process is not None:
                try:
                    returncode = process.wait(timeout=max(timeout_seconds, 0.001))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _terminate_process_group(process)
                    returncode = process.returncode
            stdout_sink.flush()
            stderr_sink.flush()
            os.fsync(stdout_sink.fileno())
            os.fsync(stderr_sink.fileno())
        os.replace(stdout_tmp, stdout_path)
        os.replace(stderr_tmp, stderr_path)
    finally:
        if stdout_tmp.exists():
            stdout_tmp.unlink()
        if stderr_tmp.exists():
            stderr_tmp.unlink()
    return ProcessResult(
        returncode=returncode,
        timed_out=timed_out,
        wall_ms=(time.monotonic() - started) * 1000.0,
        launch_error=launch_error,
    )


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _artifact_ref(path: Optional[Path], output_root: Path) -> Optional[str]:
    if path is None:
        return None
    try:
        return str(path.relative_to(output_root))
    except ValueError:
        return str(path)


def _external_cec_status(stdout: str, stderr: str) -> Tuple[str, Optional[bool]]:
    combined = stdout + "\n" + stderr
    equivalent = "Networks are equivalent" in combined
    not_equivalent = (
        "Networks are NOT EQUIVALENT" in combined
        or "not equivalent" in combined.lower()
    )
    if equivalent and not_equivalent:
        return "ABC_ERROR", None
    if equivalent:
        return "PASS", True
    if not_equivalent:
        return "CEC_FAIL", False
    return "ABC_ERROR", None


def _verify_run_identities(
    expected_groups: Mapping[str, Any],
) -> Dict[str, Any]:
    """Re-hash every tool/input after a run and report any mutation."""
    changes: Dict[str, Any] = {}
    for group_name, raw_group in expected_groups.items():
        if not isinstance(raw_group, Mapping):
            changes[str(group_name)] = {"error": "identity group is not an object"}
            continue
        for item_name, raw_expected in raw_group.items():
            key = f"{group_name}.{item_name}"
            if not isinstance(raw_expected, Mapping) or not isinstance(
                raw_expected.get("path"), str
            ):
                changes[key] = {"error": "invalid expected identity"}
                continue
            try:
                actual = _file_identity(Path(raw_expected["path"]))
            except RunnerError as exc:
                changes[key] = {"error": str(exc)}
                continue
            if (
                actual.get("size_bytes") != raw_expected.get("size_bytes")
                or actual.get("sha256") != raw_expected.get("sha256")
            ):
                changes[key] = {
                    "expected": dict(raw_expected),
                    "actual": actual,
                }
    return changes


def _measure_structure(
    show_binary: Optional[Path], bench: Path, deadline: float
) -> Dict[str, Any]:
    """Measure area/level without affecting the repair correctness status."""
    if show_binary is None:
        return {"status": "UNAVAILABLE", "area": None, "level": None}
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {"status": "SKIPPED_TIMEOUT", "area": None, "level": None}
    try:
        result = subprocess.run(
            [str(show_binary), str(bench)],
            text=True,
            capture_output=True,
            timeout=min(10.0, remaining),
            check=False,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "area": None, "level": None}
    except OSError as exc:
        return {
            "status": "ERROR",
            "area": None,
            "level": None,
            "error": str(exc),
        }
    match = re.search(r"\barea\s+(\d+)\s+(?:delay|level)\s+(\d+)\b", result.stdout)
    if result.returncode != 0 or match is None:
        return {
            "status": "ERROR",
            "returncode": result.returncode,
            "area": None,
            "level": None,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    return {
        "status": "PASS",
        "returncode": result.returncode,
        "area": int(match.group(1)),
        "level": int(match.group(2)),
    }


def _structural_metrics(
    show_binary: Optional[Path], paths: CasePaths, patched: Optional[Path], deadline: float
) -> Dict[str, Any]:
    measured = {
        "golden": _measure_structure(show_binary, paths.golden, deadline),
        "trojan": _measure_structure(show_binary, paths.trojan, deadline),
        "patched": (
            _measure_structure(show_binary, patched, deadline)
            if patched is not None
            else {"status": "NO_PATCH", "area": None, "level": None}
        ),
    }
    patched_values = measured["patched"]
    for baseline_name in ("trojan", "golden"):
        baseline = measured[baseline_name]
        if (
            isinstance(patched_values.get("area"), int)
            and isinstance(patched_values.get("level"), int)
            and isinstance(baseline.get("area"), int)
            and isinstance(baseline.get("level"), int)
        ):
            measured[f"patch_minus_{baseline_name}"] = {
                "area_delta": patched_values["area"] - baseline["area"],
                "level_delta": patched_values["level"] - baseline["level"],
            }
        else:
            measured[f"patch_minus_{baseline_name}"] = {
                "area_delta": None,
                "level_delta": None,
            }
    return measured


def _execute_run(
    run: PreparedRun,
    output_root: Path,
    binary: Path,
    abc: Path,
    show_binary: Optional[Path],
    abc_timeout_seconds: float,
    environment_meta: Mapping[str, Any],
) -> Dict[str, Any]:
    stem = f"{run.case.case_id}--{run.method}"
    stdout_path = output_root / "raw" / f"{stem}.stdout.log"
    stderr_path = output_root / "raw" / f"{stem}.stderr.log"
    cec_stdout_path = output_root / "raw" / f"{stem}.cec.stdout.log"
    cec_stderr_path = output_root / "raw" / f"{stem}.cec.stderr.log"
    patched_path = output_root / "patched" / f"{stem}.bench"
    # ABC selects its input parser from the final filename extension.  The
    # staging artifact must therefore end in .bench even though it is later
    # atomically promoted to the stable patched path.
    staged_patch = _temporary_sibling(patched_path, suffix=".bench")
    command = list(run.command)
    command[4] = str(staged_patch)

    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    # main performs internal CEC/CEGIS calls.  Pin those calls to the exact
    # ABC executable fingerprinted by this runner.
    env["ABC_BIN"] = str(abc)
    started_at = _utc_now()
    wall_started = time.monotonic()
    deadline = wall_started + run.timeout_seconds
    main_result = _run_logged_process(
        command,
        stdout_path,
        stderr_path,
        max(0.001, deadline - time.monotonic()),
        env,
    )
    stdout = _read_text(stdout_path)
    stderr = _read_text(stderr_path)
    parsed = parse_main_output(stdout, stderr)

    status = "ERROR"
    timeout_stage: Optional[str] = None
    abc_equivalent: Optional[bool] = None
    cec_result: Optional[ProcessResult] = None
    cec_command: List[str] = []
    if main_result.timed_out:
        status = "TIMEOUT"
        timeout_stage = "main"
    elif main_result.launch_error is not None:
        status = "HARNESS_ERROR"
    elif main_result.returncode != 0:
        status = f"ERROR_{main_result.returncode}"
    elif not staged_patch.is_file() or staged_patch.stat().st_size == 0:
        status = "NO_PATCH"
    else:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            status = "TIMEOUT"
            timeout_stage = "external_cec"
        else:
            cec_command = [
                str(abc),
                "-c",
                "cec " + _abc_quote_path(run.paths.golden) + " " +
                _abc_quote_path(staged_patch),
            ]
            cec_result = _run_logged_process(
                cec_command,
                cec_stdout_path,
                cec_stderr_path,
                min(abc_timeout_seconds, remaining),
                env,
            )
            if cec_result.timed_out:
                status = "TIMEOUT"
                timeout_stage = "external_cec"
            elif cec_result.launch_error is not None:
                status = "ABC_ERROR"
            elif cec_result.returncode != 0:
                status = "ABC_ERROR"
            else:
                parsed_cec_status, abc_equivalent = _external_cec_status(
                    _read_text(cec_stdout_path), _read_text(cec_stderr_path)
                )
                if parsed_cec_status in ("PASS", "CEC_FAIL"):
                    status = parsed_cec_status
                else:
                    status = "ABC_ERROR"

    final_patched: Optional[Path] = None
    if staged_patch.is_file() and staged_patch.stat().st_size > 0:
        patched_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged_patch, patched_path)
        final_patched = patched_path
    elif staged_patch.exists():
        staged_patch.unlink()

    structural = _structural_metrics(
        show_binary, run.paths, final_patched, deadline
    )
    execution_wall_ms = (time.monotonic() - wall_started) * 1000.0
    identity_started = time.monotonic()
    identity_changes = _verify_run_identities(run.identities)
    provenance_ms = (time.monotonic() - identity_started) * 1000.0
    if identity_changes:
        status = "HARNESS_ERROR"
    artifact_paths: Dict[str, Optional[Path]] = {
        "stdout": stdout_path,
        "stderr": stderr_path,
        "cec_stdout": cec_stdout_path if cec_stdout_path.exists() else None,
        "cec_stderr": cec_stderr_path if cec_stderr_path.exists() else None,
        "patched_bench": final_patched,
    }
    artifact_refs = {
        key: _artifact_ref(path, output_root) for key, path in artifact_paths.items()
    }
    artifact_identities = {
        key: {
            "size_bytes": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
        for key, path in artifact_paths.items()
        if path is not None and path.is_file()
    }
    record: Dict[str, Any] = {
        "schema_version": RUNNER_SCHEMA_VERSION,
        "cache_key": run.cache_key,
        "schedule_ordinal": run.schedule_ordinal,
        "method_ordinal": run.method_ordinal,
        "profile": run.profile,
        "case": {
            "case_id": run.case.case_id,
            "circuit": run.case.circuit,
            "trojan": run.case.trojan,
            "cohort": run.case.cohort,
            "legacy_v6": dict(run.case.legacy_v6),
        },
        "method": run.method,
        "status": status,
        "success": status == "PASS" and abc_equivalent is True,
        "timeout_seconds": run.timeout_seconds,
        "timeout_stage": timeout_stage,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "wall_ms": execution_wall_ms,
        "provenance_verification_ms": provenance_ms,
        "command": command,
        "main": {
            "returncode": main_result.returncode,
            "timed_out": main_result.timed_out,
            "wall_ms": main_result.wall_ms,
            "launch_error": main_result.launch_error,
        },
        "external_cec": {
            "command": cec_command,
            "returncode": cec_result.returncode if cec_result else None,
            "timed_out": cec_result.timed_out if cec_result else False,
            "wall_ms": cec_result.wall_ms if cec_result else None,
            "launch_error": cec_result.launch_error if cec_result else None,
            "equivalent": abc_equivalent,
        },
        "parsed": parsed,
        "structural_metrics": structural,
        "identities": dict(run.identities),
        "post_run_identity_changes": identity_changes,
        "environment": dict(environment_meta),
        "artifacts": artifact_refs,
        "artifact_identities": artifact_identities,
    }
    record_path = output_root / "records" / f"{stem}.json"
    _atomic_write_json(record_path, record)
    return record


def _record_is_resumable(
    record_path: Path, cache_key: str, output_root: Path
) -> Optional[Dict[str, Any]]:
    if not record_path.is_file():
        return None
    try:
        record = _load_json(record_path)
    except RunnerError:
        return None
    if record.get("schema_version") != RUNNER_SCHEMA_VERSION:
        return None
    if record.get("cache_key") != cache_key:
        return None
    if record.get("post_run_identity_changes"):
        return None
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, dict):
        return None
    artifact_identities = record.get("artifact_identities", {})
    if not isinstance(artifact_identities, dict):
        return None
    for key, relative in artifacts.items():
        if relative is None:
            continue
        if not isinstance(relative, str):
            return None
        artifact = (output_root / relative).resolve()
        try:
            artifact.relative_to(output_root.resolve())
        except ValueError:
            return None
        if not artifact.is_file():
            return None
        expected = artifact_identities.get(key)
        if not isinstance(expected, dict):
            return None
        if artifact.stat().st_size != expected.get("size_bytes"):
            return None
        if _sha256_file(artifact) != expected.get("sha256"):
            return None
    for key in ("stdout", "stderr"):
        if not isinstance(artifacts.get(key), str):
            return None
    if record.get("status") == "PASS":
        external_cec = record.get("external_cec", {})
        if not isinstance(external_cec, dict) or external_cec.get("returncode") != 0:
            return None
        for key in ("cec_stdout", "cec_stderr", "patched_bench"):
            if not isinstance(artifacts.get(key), str):
                return None
    return record


def _flatten_record(record: Mapping[str, Any]) -> Dict[str, Any]:
    case = record.get("case", {})
    parsed = record.get("parsed", {})
    main = record.get("main", {})
    cec = record.get("external_cec", {})
    payload = parsed.get("payload_fix", {})
    structural = record.get("structural_metrics", {})
    golden_structure = structural.get("golden", {})
    trojan_structure = structural.get("trojan", {})
    patched_structure = structural.get("patched", {})
    delta_trojan = structural.get("patch_minus_trojan", {})
    delta_golden = structural.get("patch_minus_golden", {})
    artifacts = record.get("artifacts", {})
    identities = record.get("identities", {})
    tools = identities.get("tools", {})
    actual_area_delta = delta_trojan.get("area_delta")
    actual_level_delta = delta_trojan.get("level_delta")
    row: Dict[str, Any] = {
        "case_id": case.get("case_id"),
        "cohort": case.get("cohort"),
        "circuit": case.get("circuit"),
        "trojan": case.get("trojan"),
        "method": record.get("method"),
        "profile": record.get("profile"),
        "status": record.get("status"),
        "success": record.get("success"),
        "main_returncode": main.get("returncode"),
        "timeout_stage": record.get("timeout_stage"),
        "gt_verify": parsed.get("gt_verify"),
        "abc_equivalent": cec.get("equivalent"),
        "cec_rounds": parsed.get("cec_rounds"),
        "legacy_vn_passes": parsed.get("legacy_vn_passes"),
        "runtime_ms": parsed.get("runtime_ms"),
        "wall_ms": record.get("wall_ms"),
        "provenance_verification_ms": record.get("provenance_verification_ms"),
        "main_wall_ms": main.get("wall_ms"),
        "cec_wall_ms": cec.get("wall_ms"),
        "payload_fix_nodes": payload.get("selected_nodes"),
        "area_delta": (
            actual_area_delta
            if actual_area_delta is not None
            else payload.get("area_delta")
        ),
        "level_delta": (
            actual_level_delta
            if actual_level_delta is not None
            else payload.get("level_delta")
        ),
        "reported_area_delta": payload.get("area_delta"),
        "reported_level_delta": payload.get("level_delta"),
        "golden_area": golden_structure.get("area"),
        "golden_level": golden_structure.get("level"),
        "trojan_area": trojan_structure.get("area"),
        "trojan_level": trojan_structure.get("level"),
        "patched_area": patched_structure.get("area"),
        "patched_level": patched_structure.get("level"),
        "actual_area_delta_trojan": actual_area_delta,
        "actual_level_delta_trojan": actual_level_delta,
        "actual_area_delta_golden": delta_golden.get("area_delta"),
        "actual_level_delta_golden": delta_golden.get("level_delta"),
        "rule_synth_summary_count": parsed.get("rule_synth_summary_count"),
        "rule_apply_summary_count": parsed.get("rule_apply_summary_count"),
        "binary_sha256": tools.get("binary", {}).get("sha256"),
        "abc_sha256": tools.get("abc", {}).get("sha256"),
        "highs_library_sha256": tools.get("highs_library", {}).get("sha256"),
        "cache_key": record.get("cache_key"),
        "stdout_log": artifacts.get("stdout"),
        "stderr_log": artifacts.get("stderr"),
        "cec_stdout_log": artifacts.get("cec_stdout"),
        "cec_stderr_log": artifacts.get("cec_stderr"),
        "patched_bench": artifacts.get("patched_bench"),
        "command_json": json.dumps(record.get("command", []), separators=(",", ":")),
        "rule_synth_summaries_json": json.dumps(
            parsed.get("rule_synth_summaries", []), separators=(",", ":")
        ),
        "rule_apply_summaries_json": json.dumps(
            parsed.get("rule_apply_summaries", []), separators=(",", ":")
        ),
    }
    aggregates = parsed.get("rule_synth_aggregates", {})
    for group in ("first", "last", "numeric_sum"):
        values = aggregates.get(group, {})
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            row[f"summary_{group}_{key}"] = value
    apply_aggregates = parsed.get("rule_apply_aggregates", {})
    for group in ("first", "last", "numeric_sum"):
        values = apply_aggregates.get(group, {})
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            row[f"apply_{group}_{key}"] = value
    return row


BASE_CSV_COLUMNS = [
    "case_id", "cohort", "circuit", "trojan", "method", "profile",
    "status", "success", "main_returncode", "timeout_stage", "gt_verify",
    "abc_equivalent", "cec_rounds", "legacy_vn_passes", "runtime_ms",
    "wall_ms", "provenance_verification_ms", "main_wall_ms", "cec_wall_ms",
    "payload_fix_nodes",
    "area_delta", "level_delta", "reported_area_delta", "reported_level_delta",
    "golden_area", "golden_level", "trojan_area", "trojan_level",
    "patched_area", "patched_level", "actual_area_delta_trojan",
    "actual_level_delta_trojan", "actual_area_delta_golden",
    "actual_level_delta_golden", "rule_synth_summary_count",
    "rule_apply_summary_count",
    "binary_sha256", "abc_sha256", "highs_library_sha256", "cache_key",
    "stdout_log", "stderr_log",
    "cec_stdout_log", "cec_stderr_log", "patched_bench", "command_json",
    "rule_synth_summaries_json", "rule_apply_summaries_json",
]


def _load_all_records(output_root: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    records_root = output_root / "records"
    if not records_root.is_dir():
        return records
    for path in sorted(records_root.glob("*.json")):
        try:
            value = _load_json(path)
        except RunnerError as exc:
            print(f"warning: ignoring unreadable record {path}: {exc}", file=sys.stderr)
            continue
        if value.get("schema_version") == RUNNER_SCHEMA_VERSION:
            records.append(value)
    records.sort(
        key=lambda item: (
            int(item.get("schedule_ordinal", 10**9)),
            int(item.get("method_ordinal", 10**9)),
            str(item.get("method", "")),
        )
    )
    return records


def _write_aggregates(
    output_root: Path,
    invocation: Mapping[str, Any],
    selected_cache_keys: Optional[set[str]] = None,
) -> Tuple[Path, Path]:
    records = _load_all_records(output_root)
    if selected_cache_keys is not None:
        records = [
            record for record in records
            if record.get("cache_key") in selected_cache_keys
        ]
    rows = [_flatten_record(record) for record in records]
    dynamic = sorted(
        {key for row in rows for key in row if key not in BASE_CSV_COLUMNS}
    )
    columns = BASE_CSV_COLUMNS + dynamic
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    csv_path = output_root / "results.csv"
    _atomic_write_bytes(csv_path, buffer.getvalue().encode("utf-8"))

    counts: Dict[str, int] = {}
    for record in records:
        status = str(record.get("status", "UNKNOWN"))
        counts[status] = counts.get(status, 0) + 1
    summary = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "invocation": dict(invocation),
        "record_count": len(records),
        "status_counts": counts,
        "records": records,
    }
    json_path = output_root / "summary.json"
    _atomic_write_json(json_path, summary)
    return csv_path, json_path


def _git_metadata(repo_root: Path) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root,
            text=True, capture_output=True, timeout=5, check=False,
        )
        if commit.returncode == 0:
            metadata["commit"] = commit.stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=repo_root,
            text=True, capture_output=True, timeout=5, check=False,
        )
        if status.returncode == 0:
            metadata["dirty"] = bool(status.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass
    return metadata


def _environment_metadata(repo_root: Path) -> Dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "OMP_NUM_THREADS": os.environ.get("OMP_NUM_THREADS"),
        "CUDA_VISIBLE_DEVICES": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "git": _git_metadata(repo_root),
    }


def _validate_executable(path: Path, label: str) -> None:
    if not path.is_file():
        raise RunnerError(f"{label} not found: {path}")
    if not os.access(path, os.X_OK):
        raise RunnerError(f"{label} is not executable: {path}")


def _validate_regular_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise RunnerError(f"{label} not found: {path}")


def _is_highs_soname(value: str) -> bool:
    return bool(re.fullmatch(r"libhighs\.so(?:\..+)?", Path(value).name.lower()))


def _resolved_highs_libraries(binary: Path) -> List[Path]:
    """Return the libhighs objects resolved by the platform dynamic loader."""
    try:
        result = subprocess.run(
            ["ldd", str(binary)], text=True, capture_output=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError(
            f"cannot inspect solver binary linkage with ldd: {exc}"
        ) from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().replace("\n", "; ")
        if len(detail) > 512:
            detail = detail[:512]
        raise RunnerError(
            f"cannot inspect solver binary linkage with ldd (exit "
            f"{result.returncode}): {detail or 'no diagnostic'}"
        )

    resolved: List[Path] = []
    missing: List[str] = []
    for raw_line in (result.stdout + "\n" + result.stderr).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=>" in line:
            soname, raw_target = line.split("=>", 1)
            soname = soname.strip().split()[0]
            if not _is_highs_soname(soname):
                continue
            target = raw_target.strip()
            if target.startswith("not found"):
                missing.append(soname)
                continue
            target = target.rsplit(" (", 1)[0].strip()
        else:
            target = line.rsplit(" (", 1)[0].strip()
            if not _is_highs_soname(target):
                continue
        candidate = Path(target)
        if candidate.is_file():
            resolved.append(candidate.resolve())
        else:
            missing.append(target)

    if missing:
        raise RunnerError(
            "solver binary has an unresolved HiGHS dependency: "
            + ", ".join(missing)
        )
    if not resolved:
        raise RunnerError(
            f"solver binary is not dynamically linked to libhighs: {binary}"
        )
    return resolved


def _validate_highs_library_linkage(binary: Path, highs_library: Path) -> None:
    """Require --highs-library to be the libhighs actually loaded by binary."""
    _validate_regular_file(highs_library, "HiGHS library")
    linked = _resolved_highs_libraries(binary)
    for candidate in linked:
        try:
            if highs_library.samefile(candidate):
                return
        except OSError:
            continue
    raise RunnerError(
        "--highs-library does not match the libhighs resolved by the solver "
        f"binary; provided={highs_library}, resolved="
        + ", ".join(str(path) for path in linked)
    )


def _validate_binary_methods(binary: Path, methods: Sequence[str]) -> None:
    try:
        result = subprocess.run(
            [str(binary), "--help"], text=True, capture_output=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError(f"cannot query binary CLI: {exc}") from exc
    help_text = result.stdout + "\n" + result.stderr
    missing = [method for method in methods if method not in help_text]
    if missing:
        raise RunnerError(
            "binary --help does not advertise selected method(s): "
            + ", ".join(missing)
            + "; rebuild the binary after integrating the method"
        )


def _create_parser(repo_root: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=repo_root)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--profile", default="all")
    parser.add_argument(
        "--method", action="append", choices=SUPPORTED_METHODS,
        help="rule method; repeat for A/B (default: vn-retrain and z3-pb)",
    )
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--bin", type=Path, default=Path("bin/main"))
    parser.add_argument("--abc", type=Path, default=Path("abc"))
    parser.add_argument(
        "--highs-library", type=Path,
        help="libhighs shared library used by --method milp-cover",
    )
    parser.add_argument(
        "--show", type=Path,
        help="optional area/level helper (default: bin/show or bin/script/show)",
    )
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument(
        "--timeout", type=float,
        help="override every per-case outer timeout in seconds",
    )
    parser.add_argument("--abc-timeout", type=float, default=60.0)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--force", action="store_true", help="rerun cached records")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def _resolve_cli_path(repo_root: Path, path: Path) -> Path:
    return path.resolve() if path.is_absolute() else (repo_root / path).resolve()


def main(argv: Optional[Sequence[str]] = None) -> int:
    default_repo = Path(__file__).resolve().parents[1]
    parser = _create_parser(default_repo)
    args = parser.parse_args(argv)
    try:
        repo_root = args.repo_root.resolve()
        manifest_path = _resolve_cli_path(repo_root, args.manifest)
        binary = _resolve_cli_path(repo_root, args.bin)
        abc = _resolve_cli_path(repo_root, args.abc)
        highs_library: Optional[Path] = (
            _resolve_cli_path(repo_root, args.highs_library)
            if args.highs_library is not None
            else None
        )
        if args.show is not None:
            show_binary: Optional[Path] = _resolve_cli_path(repo_root, args.show)
        else:
            show_binary = None
            for candidate in (Path("bin/show"), Path("bin/script/show")):
                resolved_candidate = _resolve_cli_path(repo_root, candidate)
                if resolved_candidate.is_file() and os.access(resolved_candidate, os.X_OK):
                    show_binary = resolved_candidate
                    break
        output_root = _resolve_cli_path(repo_root, args.output_root)
        methods = list(args.method or DEFAULT_METHODS)
        if len(methods) != len(set(methods)):
            raise RunnerError("--method values must be unique")
        if "milp-cover" in methods and highs_library is None:
            raise RunnerError(
                "--highs-library PATH is required with --method milp-cover"
            )
        if "milp-cover" not in methods and highs_library is not None:
            raise RunnerError(
                "--highs-library requires --method milp-cover"
            )
        if args.jobs != 1:
            raise RunnerError(
                "--jobs must be 1: methods for the same case can write the "
                "same intermediate *_rule_merged.bench file"
            )
        if args.timeout is not None:
            _positive_number(args.timeout, "--timeout")
        _positive_number(args.abc_timeout, "--abc-timeout")

        roots, common_args, cases, manifest_sha = load_manifest(
            manifest_path, repo_root, args.profile
        )
        if args.case_ids:
            wanted = set(args.case_ids)
            known = {case.case_id for case in cases}
            missing = sorted(wanted - known)
            if missing:
                raise RunnerError(
                    "--case is not in selected profile: " + ", ".join(missing)
                )
            cases = [case for case in cases if case.case_id in wanted]
        if not cases:
            raise RunnerError("no cases selected")

        binary_command = str(binary)
        schedules: List[Tuple[int, int, CaseSpec, str, float, CasePaths, Tuple[str, ...]]] = []
        schedule_ordinal = 0
        for case_index, case in enumerate(cases):
            ordered_methods = methods if case_index % 2 == 0 else list(reversed(methods))
            for method in ordered_methods:
                method_ordinal = methods.index(method)
                timeout_seconds = float(args.timeout or case.timeout_seconds)
                paths = _case_paths(roots, case)
                command = (
                    binary_command,
                    str(paths.golden),
                    str(paths.trojan),
                    str(paths.groundtruth),
                    "<staged-patched-bench>",
                    *common_args,
                    "--rule-method",
                    method,
                )
                schedules.append(
                    (
                        schedule_ordinal, method_ordinal, case, method,
                        timeout_seconds, paths, command,
                    )
                )
                schedule_ordinal += 1

        for _, _, case, method, timeout_seconds, paths, command in schedules:
            missing_paths = [
                path for path in (paths.golden, paths.trojan, paths.groundtruth)
                if not path.is_file()
            ]
            if missing_paths:
                raise RunnerError(
                    f"missing input for {case.case_id}/{method}: "
                    + ", ".join(str(path) for path in missing_paths)
                )
            if args.dry_run:
                print(
                    f"DRY-RUN case={case.case_id} method={method} "
                    f"timeout={timeout_seconds:g}s"
                )
                print("  " + shlex.join(command))
        if args.dry_run:
            print(
                f"DRY-RUN total={len(schedules)} profile={args.profile} "
                f"jobs={args.jobs} (no files written)"
            )
            return 0

        _validate_executable(binary, "solver binary")
        _validate_executable(abc, "ABC binary")
        if show_binary is None:
            print(
                "warning: area/level helper unavailable; structural metrics will be blank",
                file=sys.stderr,
            )
        elif not show_binary.is_file() or not os.access(show_binary, os.X_OK):
            print(
                f"warning: area/level helper unavailable: {show_binary}; "
                "structural metrics will be blank",
                file=sys.stderr,
            )
            show_binary = None
        _validate_binary_methods(binary, methods)
        if highs_library is not None:
            _validate_highs_library_linkage(binary, highs_library)
        print(
            "Fingerprinting binary, ABC, solver libraries, and selected "
            "input files ..."
        )
        identity_cache: Dict[Path, Dict[str, Any]] = {}

        def identity(path: Path) -> Dict[str, Any]:
            resolved = path.resolve()
            if resolved not in identity_cache:
                identity_cache[resolved] = _file_identity(resolved)
            return identity_cache[resolved]

        tools_identity = {
            "runner": identity(Path(__file__).resolve()),
            "binary": identity(binary),
            "abc": identity(abc),
        }
        if show_binary is not None:
            tools_identity["show"] = identity(show_binary)
        if highs_library is not None:
            tools_identity["highs_library"] = identity(highs_library)
        context_payload = {
            "runner_schema": RUNNER_SCHEMA_VERSION,
            "runner_sha256": tools_identity["runner"]["sha256"],
            "manifest_sha256": manifest_sha,
            "profile": args.profile,
            "methods": methods,
            "binary_sha256": tools_identity["binary"]["sha256"],
            "abc_sha256": tools_identity["abc"]["sha256"],
            "show_sha256": (
                tools_identity.get("show", {}).get("sha256")
                if show_binary is not None
                else None
            ),
            "highs_library_sha256": (
                tools_identity.get("highs_library", {}).get("sha256")
                if highs_library is not None
                else None
            ),
            "common_args": common_args,
            "timeout_override": args.timeout,
            "abc_timeout": args.abc_timeout,
        }
        context_payload["context_key"] = _sha256_bytes(
            json.dumps(context_payload, sort_keys=True).encode("utf-8")
        )
        context_path = output_root / "run_context.json"
        if context_path.is_file():
            existing_context = _load_json(context_path)
            if existing_context.get("context_key") != context_payload["context_key"]:
                raise RunnerError(
                    f"output root belongs to a different binary/configuration: "
                    f"{output_root}; choose a new --output-root"
                )
        else:
            _atomic_write_json(context_path, context_payload)

        environment_meta = _environment_metadata(repo_root)
        prepared: List[PreparedRun] = []
        for schedule in schedules:
            ordinal, method_ordinal, case, method, timeout_seconds, paths, command = schedule
            input_identities = {
                "golden": identity(paths.golden),
                "trojan": identity(paths.trojan),
                "groundtruth": identity(paths.groundtruth),
            }
            identities = {"tools": tools_identity, "inputs": input_identities}
            cache_payload = {
                "context_key": context_payload["context_key"],
                "case_id": case.case_id,
                "method": method,
                "timeout_seconds": timeout_seconds,
                "command": list(command)[5:],
                "input_sha256": {
                    key: value["sha256"] for key, value in input_identities.items()
                },
            }
            cache_key = _sha256_bytes(
                json.dumps(cache_payload, sort_keys=True).encode("utf-8")
            )
            prepared.append(
                PreparedRun(
                    schedule_ordinal=ordinal,
                    method_ordinal=method_ordinal,
                    profile=args.profile,
                    case=case,
                    paths=paths,
                    method=method,
                    timeout_seconds=timeout_seconds,
                    command=command,
                    cache_key=cache_key,
                    identities=identities,
                )
            )

        invocation = {
            "profile": args.profile,
            "methods": methods,
            "jobs": args.jobs,
            "manifest": str(manifest_path),
            "manifest_sha256": manifest_sha,
            "binary": str(binary),
            "abc": str(abc),
            "show": str(show_binary) if show_binary is not None else None,
            "highs_library": (
                str(highs_library) if highs_library is not None else None
            ),
            "context_key": context_payload["context_key"],
            "environment": environment_meta,
        }
        output_root.mkdir(parents=True, exist_ok=True)
        selected_keys = {run.cache_key for run in prepared}
        _write_aggregates(output_root, invocation, selected_keys)

        pending: List[PreparedRun] = []
        for run in prepared:
            record_path = (
                output_root / "records" / f"{run.case.case_id}--{run.method}.json"
            )
            cached = None if args.force else _record_is_resumable(
                record_path, run.cache_key, output_root
            )
            if cached is not None:
                print(
                    f"SKIP case={run.case.case_id} method={run.method} "
                    f"status={cached.get('status')}"
                )
            else:
                pending.append(run)

        def completed(record: Mapping[str, Any]) -> None:
            case = record.get("case", {})
            print(
                f"DONE case={case.get('case_id')} method={record.get('method')} "
                f"status={record.get('status')} wall_ms={record.get('wall_ms', 0):.1f}"
            )
            _write_aggregates(output_root, invocation, selected_keys)

        for run in pending:
            completed(
                _execute_run(
                    run, output_root, binary, abc, show_binary, args.abc_timeout,
                    environment_meta,
                )
            )

        csv_path, json_path = _write_aggregates(
            output_root, invocation, selected_keys
        )
        records = _load_all_records(output_root)
        selected_records = [
            record for record in records if record.get("cache_key") in selected_keys
        ]
        failed = [record for record in selected_records if not record.get("success")]
        print(f"CSV {csv_path}")
        print(f"JSON {json_path}")
        print(
            f"SUMMARY selected={len(selected_records)} pass={len(selected_records)-len(failed)} "
            f"nonpass={len(failed)} resumed={len(prepared)-len(pending)}"
        )
        return 0
    except (RunnerError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
