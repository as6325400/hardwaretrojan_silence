#!/usr/bin/env python3
"""Compare the exact V4 13-case scalar and multi-head Z3-PB runs.

The external ABC CEC result is the correctness authority.  This analyzer is
deliberately strict: it refuses partial runs, mismatched case sets, changed
inputs, or configuration/provenance drift before writing any report artifact.
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA_VERSION = "v4-z3-pb-multi-head-comparison/1"
DEFAULT_PROFILE = "smoke_extended"
EXPECTED_CASE_COUNT = 13
EXPECTED_FORMAL_CONFIG = {
    "rule_formal_refine": True,
    "rule_formal_timeout_ms": 10000,
    "rule_formal_max_rounds": 5,
    "rule_formal_cex_batch": 5,
}
EXPECTED_MULTI_HEAD_ROUNDS = 20
EXPECTED_TIMEOUT_SECONDS = 300.0
EXPECTED_ABC_TIMEOUT_SECONDS = 60.0

PAIRED_FIELDS = [
    "case_id", "cohort", "circuit", "phase_id", "split", "size_class",
    "trojan_count", "trigger_size", "trigger_topology",
    "positive_pattern_count", "scalar_status", "multi_head_status",
    "transition", "gain", "regression", "scalar_pass", "multi_head_pass",
    "scalar_abc_equivalent", "multi_head_abc_equivalent",
    "scalar_gt_verify", "multi_head_gt_verify", "scalar_timeout_stage",
    "multi_head_timeout_stage", "scalar_wall_ms", "multi_head_wall_ms",
    "multi_minus_scalar_wall_ms", "multi_over_scalar_wall",
    "scalar_runtime_ms", "multi_head_runtime_ms",
    "multi_minus_scalar_runtime_ms", "multi_over_scalar_runtime",
    "scalar_main_wall_ms", "multi_head_main_wall_ms",
    "scalar_external_cec_wall_ms", "multi_head_external_cec_wall_ms",
    "scalar_cec_rounds", "multi_head_cec_rounds",
    "scalar_golden_and", "multi_head_golden_and", "scalar_trojan_and",
    "multi_head_trojan_and", "scalar_patched_and", "multi_head_patched_and",
    "scalar_actual_and_delta_trojan", "multi_head_actual_and_delta_trojan",
    "multi_minus_scalar_actual_and_delta_trojan", "scalar_golden_level",
    "multi_head_golden_level", "scalar_trojan_level", "multi_head_trojan_level",
    "scalar_patched_level", "multi_head_patched_level",
    "scalar_actual_level_delta_trojan",
    "multi_head_actual_level_delta_trojan",
    "multi_minus_scalar_actual_level_delta_trojan", "initial_heads",
    "discovery_candidates", "discovery_candidate_source", "final_heads",
    "proved_heads", "all_final_heads_proved", "head_rule_events",
    "formal_rebuild_events", "formal_cex_returned", "formal_cex_added",
    "formal_global_cex_added", "formal_solver_checks", "formal_miter_ms",
    "head_optimizer_ms", "head_learning_ms", "head_miter_statuses_json",
    "cec_feedback_rounds", "cec_feedback_labels_added",
    "cec_feedback_corpus_added", "cec_feedback_new_heads",
    "input_golden_sha256", "input_trojan_sha256", "input_groundtruth_sha256",
    "scalar_binary_sha256", "multi_head_binary_sha256", "abc_sha256",
    "show_sha256",
]


class IncompleteRunError(RuntimeError):
    """The runner output does not yet contain the complete exact case set."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _context_key(payload: Mapping[str, Any]) -> str:
    content = dict(payload)
    content.pop("context_key", None)
    return hashlib.sha256(
        json.dumps(content, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read {label} {path}: {exc}") from exc


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


def _strict_bool(value: object, *, field: str, case_id: str) -> bool:
    text = str(value).strip().lower()
    if text in {"1", "true", "yes"}:
        return True
    if text in {"0", "false", "no"}:
        return False
    raise RuntimeError(f"invalid {field} for {case_id}: {value!r}")


def _optional_bool(value: object, *, field: str, case_id: str) -> Optional[bool]:
    if str(value).strip() == "":
        return None
    return _strict_bool(value, field=field, case_id=case_id)


def _load_manifest(
    path: Path, profile: str
) -> Tuple[Dict[str, Dict[str, Any]], List[str], str, List[str], Dict[str, List[str]]]:
    payload = _read_json(path, "manifest")
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise RuntimeError("manifest lacks a cases array")
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict) or not isinstance(profiles.get(profile), list):
        raise RuntimeError(f"manifest lacks profile {profile!r}")
    common_args = payload.get("common_args")
    if not isinstance(common_args, list) or not all(isinstance(arg, str) for arg in common_args):
        raise RuntimeError("manifest common_args must be a string array")
    by_id: Dict[str, Dict[str, Any]] = {}
    for raw_case in payload["cases"]:
        if not isinstance(raw_case, dict) or not isinstance(raw_case.get("v4"), dict):
            raise RuntimeError("manifest case lacks V4 metadata")
        case_id = raw_case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise RuntimeError("manifest case lacks case_id")
        if case_id in by_id:
            raise RuntimeError(f"duplicate manifest case_id: {case_id}")
        by_id[case_id] = raw_case
    case_ids = profiles[profile]
    if not all(isinstance(case_id, str) for case_id in case_ids):
        raise RuntimeError(f"manifest profile {profile!r} contains a non-string case")
    if len(case_ids) != len(set(case_ids)):
        raise RuntimeError(f"manifest profile {profile!r} contains duplicate cases")
    missing = [case_id for case_id in case_ids if case_id not in by_id]
    if missing:
        raise RuntimeError(f"profile cases missing from manifest: {missing}")
    if len(case_ids) != EXPECTED_CASE_COUNT:
        raise RuntimeError(
            f"profile {profile!r} is not the exact V4 13-case set: "
            f"observed {len(case_ids)} cases"
        )
    normalized_profiles: Dict[str, List[str]] = {}
    for name, values in profiles.items():
        if isinstance(name, str) and isinstance(values, list) and all(
            isinstance(value, str) for value in values
        ):
            normalized_profiles[name] = values
    return by_id, list(case_ids), _sha256(path), list(common_args), normalized_profiles


def _read_context(path: Path, label: str) -> Dict[str, Any]:
    payload = _read_json(path, f"{label} run context")
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} run context is not an object: {path}")
    actual_key = payload.get("context_key")
    if not isinstance(actual_key, str) or actual_key != _context_key(payload):
        raise RuntimeError(f"invalid context_key in {path}")
    return payload


def _validate_context(
    context: Mapping[str, Any], *, label: str, manifest_sha256: str,
    common_args: Sequence[str], multi_head: bool, expected_profile: Optional[str],
) -> None:
    if context.get("manifest_sha256") != manifest_sha256:
        raise RuntimeError(f"manifest SHA mismatch in {label} context")
    if context.get("methods") != ["z3-pb"]:
        raise RuntimeError(f"{label} context is not a z3-pb-only run")
    if context.get("common_args") != list(common_args):
        raise RuntimeError(f"common_args drift in {label} context")
    for key, expected in EXPECTED_FORMAL_CONFIG.items():
        if context.get(key) != expected:
            raise RuntimeError(
                f"formal configuration drift in {label} context: "
                f"{key}={context.get(key)!r}, expected {expected!r}"
            )
    if float(context.get("timeout_override", -1)) != EXPECTED_TIMEOUT_SECONDS:
        raise RuntimeError(f"unexpected timeout_override in {label} context")
    if float(context.get("abc_timeout", -1)) != EXPECTED_ABC_TIMEOUT_SECONDS:
        raise RuntimeError(f"unexpected abc_timeout in {label} context")
    if expected_profile is not None and context.get("profile") != expected_profile:
        raise RuntimeError(
            f"unexpected profile in {label} context: {context.get('profile')!r}"
        )
    if multi_head:
        if context.get("rule_multi_head") is not True:
            raise RuntimeError(f"multi-head is not enabled in {label} context")
        if context.get("rule_multi_head_max_rounds") != EXPECTED_MULTI_HEAD_ROUNDS:
            raise RuntimeError(f"unexpected multi-head rounds in {label} context")
    else:
        if context.get("rule_multi_head") not in (None, False):
            raise RuntimeError(f"multi-head is enabled in scalar {label} context")
        if context.get("rule_multi_head_max_rounds") not in (None,):
            raise RuntimeError(f"scalar {label} context contains multi-head rounds")
    for key in ("runner_sha256", "binary_sha256", "abc_sha256", "show_sha256"):
        value = context.get(key)
        if not isinstance(value, str) or len(value) != 64:
            raise RuntimeError(f"missing or invalid {key} in {label} context")


def _read_result_files(
    paths: Sequence[Path], label: str
) -> Tuple[Dict[str, Dict[str, str]], Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    rows: Dict[str, Dict[str, str]] = {}
    context_for_case: Dict[str, Dict[str, Any]] = {}
    sources: List[Dict[str, Any]] = []
    for path in paths:
        context_path = path.parent / "run_context.json"
        context = _read_context(context_path, label)
        try:
            with path.open(newline="", encoding="utf-8") as stream:
                reader = csv.DictReader(stream)
                if reader.fieldnames is None:
                    raise RuntimeError(f"{label} results has no CSV header: {path}")
                file_rows = [dict(row) for row in reader]
        except OSError as exc:
            raise RuntimeError(f"cannot read {label} results {path}: {exc}") from exc
        for row in file_rows:
            case_id = row.get("case_id", "")
            if not case_id:
                raise RuntimeError(f"{path} contains a row without case_id")
            if case_id in rows:
                raise RuntimeError(f"duplicate {label} case_id: {case_id}")
            rows[case_id] = row
            context_for_case[case_id] = context
        sources.append(
            {
                "path": str(path),
                "sha256": _sha256(path),
                "rows": len(file_rows),
                "context_path": str(context_path),
                "context_sha256": _sha256(context_path),
                "context": context,
            }
        )
    return rows, context_for_case, sources


def _assert_exact_case_set(
    observed: Iterable[str], expected: Sequence[str], label: str
) -> None:
    observed_set = set(observed)
    expected_set = set(expected)
    if observed_set != expected_set:
        missing = sorted(expected_set - observed_set)
        unexpected = sorted(observed_set - expected_set)
        raise IncompleteRunError(
            f"{label} raw is incomplete or not the exact V4 13-case set: "
            f"expected={len(expected_set)} observed={len(observed_set)} "
            f"missing={missing} unexpected={unexpected}"
        )


def _expected_tail(common_args: Sequence[str], multi_head: bool) -> List[str]:
    tail = list(common_args) + [
        "--rule-method", "z3-pb", "--rule-formal-refine",
        "--rule-formal-timeout-ms", "10000", "--rule-formal-max-rounds", "5",
        "--rule-formal-cex-batch", "5",
    ]
    if multi_head:
        tail.extend(
            ["--rule-multi-head", "--rule-multi-head-max-rounds", "20"]
        )
    return tail


def _parse_command(row: Mapping[str, str], case_id: str) -> List[str]:
    try:
        command = json.loads(row.get("command_json", ""))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid command_json for {case_id}") from exc
    if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
        raise RuntimeError(f"command_json is not a string array for {case_id}")
    if len(command) < 6:
        raise RuntimeError(f"command_json is too short for {case_id}")
    return command


def _validate_authoritative_status(
    row: Mapping[str, str], *, label: str, record: Optional[Mapping[str, Any]] = None,
) -> bool:
    case_id = row.get("case_id", "<unknown>")
    status = row.get("status", "")
    equivalent = _optional_bool(
        row.get("abc_equivalent", ""), field="abc_equivalent", case_id=case_id
    )
    success = _strict_bool(row.get("success", ""), field="success", case_id=case_id)
    authoritative = status == "PASS" and equivalent is True
    if success != authoritative:
        raise RuntimeError(
            f"{label} {case_id} success is not controlled by external ABC CEC"
        )
    if status == "PASS":
        if equivalent is not True:
            raise RuntimeError(f"{label} {case_id} PASS lacks ABC equivalence")
        for key in ("cec_stdout_log", "cec_stderr_log", "patched_bench"):
            if not row.get(key):
                raise RuntimeError(f"{label} {case_id} PASS lacks {key}")
    elif equivalent is True:
        raise RuntimeError(f"{label} {case_id} is non-PASS but ABC-equivalent")
    if status == "CEC_FAIL" and equivalent is not False:
        raise RuntimeError(f"{label} {case_id} CEC_FAIL lacks ABC inequivalence")
    if record is not None:
        external = record.get("external_cec")
        if not isinstance(external, dict):
            raise RuntimeError(f"{label} {case_id} record lacks external_cec")
        if external.get("equivalent") is not equivalent:
            raise RuntimeError(f"{label} {case_id} CSV/record ABC result mismatch")
        if status == "PASS" and (
            external.get("returncode") != 0 or external.get("timed_out") is not False
        ):
            raise RuntimeError(f"{label} {case_id} PASS has invalid external CEC record")
    return authoritative


def _identity(
    path: Path, cache: Dict[Path, Tuple[str, int]]
) -> Tuple[str, int]:
    resolved = path.resolve()
    if resolved not in cache:
        try:
            size = resolved.stat().st_size
        except OSError as exc:
            raise RuntimeError(f"cannot stat benchmark input {path}: {exc}") from exc
        cache[resolved] = (_sha256(resolved), size)
    return cache[resolved]


def _validate_row(
    row: Mapping[str, str], *, label: str, case: Mapping[str, Any],
    context: Mapping[str, Any], common_args: Sequence[str], multi_head: bool,
    identity_cache: Dict[Path, Tuple[str, int]],
) -> Tuple[List[str], Dict[str, str]]:
    case_id = str(case["case_id"])
    if row.get("method") != "z3-pb":
        raise RuntimeError(f"{label} {case_id} is not z3-pb")
    if row.get("profile") != context.get("profile"):
        raise RuntimeError(f"{label} {case_id} row/context profile mismatch")
    if row.get("binary_sha256") != context.get("binary_sha256"):
        raise RuntimeError(f"{label} {case_id} binary provenance mismatch")
    if row.get("abc_sha256") != context.get("abc_sha256"):
        raise RuntimeError(f"{label} {case_id} ABC provenance mismatch")
    command = _parse_command(row, case_id)
    if command[5:] != _expected_tail(common_args, multi_head):
        raise RuntimeError(f"{label} {case_id} command configuration drift")
    metadata = case["v4"]
    expected_inputs = (
        ("golden", metadata.get("source_golden_sha256"), None),
        (
            "trojan", metadata.get("source_combined_sha256"),
            metadata.get("source_combined_size_bytes"),
        ),
        (
            "groundtruth", metadata.get("source_groundtruth_sha256"),
            metadata.get("source_groundtruth_size_bytes"),
        ),
    )
    identities: Dict[str, str] = {}
    for command_index, (name, expected_sha, expected_size) in enumerate(
        expected_inputs, start=1
    ):
        if not isinstance(expected_sha, str) or len(expected_sha) != 64:
            raise RuntimeError(f"manifest lacks {name} SHA for {case_id}")
        actual_sha, actual_size = _identity(Path(command[command_index]), identity_cache)
        if actual_sha != expected_sha:
            raise RuntimeError(
                f"{label} {case_id} {name} input SHA mismatch: "
                f"{actual_sha} != {expected_sha}"
            )
        if expected_size is not None and actual_size != expected_size:
            raise RuntimeError(f"{label} {case_id} {name} input size mismatch")
        identities[name] = actual_sha
    _validate_authoritative_status(row, label=label)
    return command, identities


def _json_summary_list(
    row: Mapping[str, str], json_key: str, count_key: str, case_id: str
) -> List[Dict[str, Any]]:
    try:
        value = json.loads(row.get(json_key, ""))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid {json_key} for {case_id}") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RuntimeError(f"{json_key} is not an object array for {case_id}")
    count = _number(row.get(count_key, ""))
    if count != len(value):
        raise RuntimeError(f"{case_id} {count_key} does not match {json_key}")
    return value


def _sum_telemetry(rows: Sequence[Mapping[str, Any]], key: str) -> int | float:
    values = [_number(row.get(key, "")) for row in rows]
    return sum(value for value in values if value is not None)


def _multi_head_telemetry(row: Mapping[str, str]) -> Dict[str, Any]:
    case_id = row.get("case_id", "<unknown>")
    discovery = _json_summary_list(
        row, "multi_head_discovery_summaries_json",
        "multi_head_discovery_summary_count", case_id,
    )
    rules = _json_summary_list(
        row, "multi_head_rule_summaries_json",
        "multi_head_rule_summary_count", case_id,
    )
    patches = _json_summary_list(
        row, "multi_head_patch_summaries_json",
        "multi_head_patch_summary_count", case_id,
    )
    feedback = _json_summary_list(
        row, "multi_head_cec_feedback_summaries_json",
        "multi_head_cec_feedback_summary_count", case_id,
    )
    first_discovery = discovery[0] if discovery else {}
    final_patch = patches[-1] if patches else {}
    statuses = Counter(
        str(item.get("miter_status", "missing")) for item in rules
    )
    return {
        "initial_heads": _number(first_discovery.get("heads", "")),
        "discovery_candidates": _number(first_discovery.get("candidates", "")),
        "discovery_candidate_source": first_discovery.get("candidate_source"),
        "final_heads": _number(final_patch.get("heads", "")),
        "proved_heads": _number(final_patch.get("proved_heads", "")),
        "all_final_heads_proved": (
            int(final_patch.get("heads") == final_patch.get("proved_heads"))
            if final_patch and final_patch.get("heads") is not None
            and final_patch.get("proved_heads") is not None else None
        ),
        "head_rule_events": len(rules),
        "formal_rebuild_events": sum(
            1 for item in rules if (_number(item.get("pass", "")) or 0) > 1
        ),
        "formal_cex_returned": _sum_telemetry(rules, "returned"),
        "formal_cex_added": _sum_telemetry(rules, "added"),
        "formal_global_cex_added": _sum_telemetry(rules, "global_added"),
        "formal_solver_checks": _sum_telemetry(rules, "checks"),
        "formal_miter_ms": _sum_telemetry(rules, "miter_ms"),
        "head_optimizer_ms": _sum_telemetry(rules, "optimizer_ms"),
        "head_learning_ms": _sum_telemetry(rules, "total_ms"),
        "head_miter_statuses_json": json.dumps(dict(sorted(statuses.items()))),
        "cec_feedback_rounds": len(feedback),
        "cec_feedback_labels_added": _sum_telemetry(feedback, "labels_added"),
        "cec_feedback_corpus_added": _sum_telemetry(feedback, "corpus_added"),
        "cec_feedback_new_heads": _sum_telemetry(feedback, "new_heads"),
    }


def _load_multi_summary(
    root: Path, rows: Mapping[str, Mapping[str, str]], expected_case_ids: Sequence[str],
    context: Mapping[str, Any], manifest_cases: Mapping[str, Mapping[str, Any]],
    identity_cache: Dict[Path, Tuple[str, int]],
) -> Tuple[Dict[str, Mapping[str, Any]], Dict[str, Any]]:
    path = root / "summary.json"
    payload = _read_json(path, "multi-head runner summary")
    if not isinstance(payload, dict) or not isinstance(payload.get("records"), list):
        raise IncompleteRunError(f"multi-head raw summary is missing records: {path}")
    records = payload["records"]
    if payload.get("record_count") != len(records):
        raise IncompleteRunError("multi-head raw summary record_count is inconsistent")
    by_id: Dict[str, Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("case"), dict):
            raise RuntimeError("multi-head summary contains a malformed record")
        case_id = record["case"].get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise RuntimeError("multi-head summary record lacks case_id")
        if case_id in by_id:
            raise RuntimeError(f"duplicate multi-head summary case_id: {case_id}")
        by_id[case_id] = record
    _assert_exact_case_set(by_id, expected_case_ids, "multi-head summary")
    invocation = payload.get("invocation")
    if not isinstance(invocation, dict):
        raise RuntimeError("multi-head summary lacks invocation provenance")
    for key in (
        "context_key", "manifest_sha256", "profile", "methods",
        "rule_formal_refine", "rule_formal_timeout_ms", "rule_formal_max_rounds",
        "rule_formal_cex_batch", "rule_multi_head", "rule_multi_head_max_rounds",
    ):
        if invocation.get(key) != context.get(key):
            raise RuntimeError(f"multi-head summary/context mismatch for {key}")
    for case_id, record in by_id.items():
        row = rows[case_id]
        if record.get("method") != "z3-pb":
            raise RuntimeError(f"multi-head record {case_id} is not z3-pb")
        if record.get("profile") != context.get("profile"):
            raise RuntimeError(f"multi-head record {case_id} profile mismatch")
        if record.get("status") != row.get("status"):
            raise RuntimeError(f"multi-head record {case_id} status mismatch")
        if record.get("cache_key") != row.get("cache_key"):
            raise RuntimeError(f"multi-head record {case_id} cache key mismatch")
        command = _parse_command(row, case_id)
        if record.get("command") != command:
            raise RuntimeError(f"multi-head record {case_id} command mismatch")
        identities = record.get("identities")
        if not isinstance(identities, dict):
            raise RuntimeError(f"multi-head record {case_id} lacks identities")
        tools = identities.get("tools")
        inputs = identities.get("inputs")
        if not isinstance(tools, dict) or not isinstance(inputs, dict):
            raise RuntimeError(f"multi-head record {case_id} lacks tool/input identities")
        for tool, context_key in (
            ("binary", "binary_sha256"), ("abc", "abc_sha256"),
            ("show", "show_sha256"), ("runner", "runner_sha256"),
        ):
            if not isinstance(tools.get(tool), dict) or (
                tools[tool].get("sha256") != context.get(context_key)
            ):
                raise RuntimeError(f"multi-head record {case_id} {tool} identity mismatch")
        metadata = manifest_cases[case_id]["v4"]
        for name, expected in (
            ("golden", metadata["source_golden_sha256"]),
            ("trojan", metadata["source_combined_sha256"]),
            ("groundtruth", metadata["source_groundtruth_sha256"]),
        ):
            item = inputs.get(name)
            if not isinstance(item, dict) or item.get("sha256") != expected:
                raise RuntimeError(f"multi-head record {case_id} {name} identity mismatch")
            current_sha, _ = _identity(Path(str(item.get("path", ""))), identity_cache)
            if current_sha != expected:
                raise RuntimeError(f"multi-head record {case_id} {name} file changed")
        _validate_authoritative_status(row, label="multi-head", record=record)
    return by_id, {
        "path": str(path), "sha256": _sha256(path),
        "schema_version": payload.get("schema_version"),
        "record_count": len(records),
    }


def _metric(row: Mapping[str, str], key: str) -> int | float | None:
    return _number(row.get(key, ""))


def _difference(left: object, right: object) -> int | float | None:
    left_number = _number(left)
    right_number = _number(right)
    if left_number is None or right_number is None:
        return None
    return right_number - left_number


def _ratio(numerator: object, denominator: object) -> float | None:
    top = _number(numerator)
    bottom = _number(denominator)
    if top is None or bottom is None or bottom <= 0:
        return None
    return float(top) / float(bottom)


def build_pairs(
    manifest_cases: Mapping[str, Mapping[str, Any]], case_ids: Sequence[str],
    scalar_rows: Mapping[str, Mapping[str, str]],
    multi_rows: Mapping[str, Mapping[str, str]],
    input_identities: Mapping[str, Mapping[str, str]],
    scalar_binary_sha256: str, multi_binary_sha256: str,
    abc_sha256: str, show_sha256: str,
) -> List[Dict[str, Any]]:
    pairs: List[Dict[str, Any]] = []
    for case_id in case_ids:
        scalar = scalar_rows[case_id]
        multi = multi_rows[case_id]
        scalar_pass = _validate_authoritative_status(scalar, label="scalar")
        multi_pass = _validate_authoritative_status(multi, label="multi-head")
        metadata = manifest_cases[case_id]["v4"]
        telemetry = _multi_head_telemetry(multi)
        scalar_wall = _metric(scalar, "wall_ms")
        multi_wall = _metric(multi, "wall_ms")
        scalar_runtime = _metric(scalar, "runtime_ms")
        multi_runtime = _metric(multi, "runtime_ms")
        scalar_area_delta = _metric(scalar, "actual_area_delta_trojan")
        multi_area_delta = _metric(multi, "actual_area_delta_trojan")
        scalar_level_delta = _metric(scalar, "actual_level_delta_trojan")
        multi_level_delta = _metric(multi, "actual_level_delta_trojan")
        for structural_key in (
            "golden_area", "golden_level", "trojan_area", "trojan_level"
        ):
            scalar_value = _metric(scalar, structural_key)
            multi_value = _metric(multi, structural_key)
            if (
                scalar_value is not None and multi_value is not None
                and scalar_value != multi_value
            ):
                raise RuntimeError(
                    f"paired structural metric mismatch for {case_id}: "
                    f"{structural_key}={scalar_value} vs {multi_value}"
                )
        pair: Dict[str, Any] = {
            "case_id": case_id,
            "cohort": manifest_cases[case_id].get("cohort"),
            "circuit": manifest_cases[case_id].get("circuit"),
            "phase_id": metadata.get("phase_id"),
            "split": metadata.get("split"),
            "size_class": metadata.get("size_class"),
            "trojan_count": metadata.get("trojan_count"),
            "trigger_size": metadata.get("trigger_size"),
            "trigger_topology": metadata.get("trigger_topology"),
            "positive_pattern_count": metadata.get("positive_pattern_count"),
            "scalar_status": scalar.get("status"),
            "multi_head_status": multi.get("status"),
            "transition": f"{scalar.get('status')}->{multi.get('status')}",
            "gain": int(not scalar_pass and multi_pass),
            "regression": int(scalar_pass and not multi_pass),
            "scalar_pass": int(scalar_pass),
            "multi_head_pass": int(multi_pass),
            "scalar_abc_equivalent": _optional_bool(
                scalar.get("abc_equivalent", ""), field="abc_equivalent", case_id=case_id
            ),
            "multi_head_abc_equivalent": _optional_bool(
                multi.get("abc_equivalent", ""), field="abc_equivalent", case_id=case_id
            ),
            "scalar_gt_verify": scalar.get("gt_verify"),
            "multi_head_gt_verify": multi.get("gt_verify"),
            "scalar_timeout_stage": scalar.get("timeout_stage"),
            "multi_head_timeout_stage": multi.get("timeout_stage"),
            "scalar_wall_ms": scalar_wall,
            "multi_head_wall_ms": multi_wall,
            "multi_minus_scalar_wall_ms": _difference(scalar_wall, multi_wall),
            "multi_over_scalar_wall": _ratio(multi_wall, scalar_wall),
            "scalar_runtime_ms": scalar_runtime,
            "multi_head_runtime_ms": multi_runtime,
            "multi_minus_scalar_runtime_ms": _difference(scalar_runtime, multi_runtime),
            "multi_over_scalar_runtime": _ratio(multi_runtime, scalar_runtime),
            "scalar_main_wall_ms": _metric(scalar, "main_wall_ms"),
            "multi_head_main_wall_ms": _metric(multi, "main_wall_ms"),
            "scalar_external_cec_wall_ms": _metric(scalar, "cec_wall_ms"),
            "multi_head_external_cec_wall_ms": _metric(multi, "cec_wall_ms"),
            "scalar_cec_rounds": _metric(scalar, "cec_rounds"),
            "multi_head_cec_rounds": _metric(multi, "cec_rounds"),
            "scalar_golden_and": _metric(scalar, "golden_area"),
            "multi_head_golden_and": _metric(multi, "golden_area"),
            "scalar_trojan_and": _metric(scalar, "trojan_area"),
            "multi_head_trojan_and": _metric(multi, "trojan_area"),
            "scalar_patched_and": _metric(scalar, "patched_area"),
            "multi_head_patched_and": _metric(multi, "patched_area"),
            "scalar_actual_and_delta_trojan": scalar_area_delta,
            "multi_head_actual_and_delta_trojan": multi_area_delta,
            "multi_minus_scalar_actual_and_delta_trojan": _difference(
                scalar_area_delta, multi_area_delta
            ),
            "scalar_golden_level": _metric(scalar, "golden_level"),
            "multi_head_golden_level": _metric(multi, "golden_level"),
            "scalar_trojan_level": _metric(scalar, "trojan_level"),
            "multi_head_trojan_level": _metric(multi, "trojan_level"),
            "scalar_patched_level": _metric(scalar, "patched_level"),
            "multi_head_patched_level": _metric(multi, "patched_level"),
            "scalar_actual_level_delta_trojan": scalar_level_delta,
            "multi_head_actual_level_delta_trojan": multi_level_delta,
            "multi_minus_scalar_actual_level_delta_trojan": _difference(
                scalar_level_delta, multi_level_delta
            ),
            **telemetry,
            "input_golden_sha256": input_identities[case_id]["golden"],
            "input_trojan_sha256": input_identities[case_id]["trojan"],
            "input_groundtruth_sha256": input_identities[case_id]["groundtruth"],
            "scalar_binary_sha256": scalar_binary_sha256,
            "multi_head_binary_sha256": multi_binary_sha256,
            "abc_sha256": abc_sha256,
            "show_sha256": show_sha256,
        }
        pairs.append(pair)
    return pairs


def _sum_available(rows: Iterable[Mapping[str, Any]], key: str) -> float:
    return sum(float(row[key]) for row in rows if row.get(key) is not None)


def _mean_available(rows: Iterable[Mapping[str, Any]], key: str) -> float | None:
    values = [float(row[key]) for row in rows if row.get(key) is not None]
    return statistics.fmean(values) if values else None


def _geomean(values: Sequence[float]) -> float | None:
    positive = [value for value in values if value > 0]
    if len(positive) != len(values) or not values:
        return None
    return math.exp(sum(math.log(value) for value in values) / len(values))


def aggregate(pairs: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    both_pass = [row for row in pairs if row["scalar_pass"] and row["multi_head_pass"]]
    both_runtime = [
        row for row in both_pass
        if row.get("scalar_runtime_ms") is not None
        and row.get("multi_head_runtime_ms") is not None
    ]
    both_qor = [
        row for row in both_pass
        if row.get("scalar_actual_and_delta_trojan") is not None
        and row.get("multi_head_actual_and_delta_trojan") is not None
        and row.get("scalar_actual_level_delta_trojan") is not None
        and row.get("multi_head_actual_level_delta_trojan") is not None
    ]
    return {
        "case_count": len(pairs),
        "scalar_pass": sum(int(row["scalar_pass"]) for row in pairs),
        "multi_head_pass": sum(int(row["multi_head_pass"]) for row in pairs),
        "pass_delta": sum(int(row["multi_head_pass"] - row["scalar_pass"]) for row in pairs),
        "gains": sum(int(row["gain"]) for row in pairs),
        "regressions": sum(int(row["regression"]) for row in pairs),
        "scalar_statuses": dict(sorted(Counter(row["scalar_status"] for row in pairs).items())),
        "multi_head_statuses": dict(
            sorted(Counter(row["multi_head_status"] for row in pairs).items())
        ),
        "transitions": dict(sorted(Counter(row["transition"] for row in pairs).items())),
        "all_cases_wall": {
            "scalar_ms": _sum_available(pairs, "scalar_wall_ms"),
            "multi_head_ms": _sum_available(pairs, "multi_head_wall_ms"),
            "multi_over_scalar": _ratio(
                _sum_available(pairs, "multi_head_wall_ms"),
                _sum_available(pairs, "scalar_wall_ms"),
            ),
        },
        "both_pass": {
            "case_count": len(both_pass),
            "scalar_wall_ms": _sum_available(both_pass, "scalar_wall_ms"),
            "multi_head_wall_ms": _sum_available(both_pass, "multi_head_wall_ms"),
            "multi_over_scalar_wall_geomean": _geomean(
                [float(row["multi_over_scalar_wall"]) for row in both_pass]
            ),
            "runtime_case_count": len(both_runtime),
            "scalar_runtime_ms": _sum_available(both_runtime, "scalar_runtime_ms"),
            "multi_head_runtime_ms": _sum_available(both_runtime, "multi_head_runtime_ms"),
            "multi_over_scalar_runtime_geomean": _geomean(
                [float(row["multi_over_scalar_runtime"]) for row in both_runtime]
            ),
        },
        "both_pass_qor": {
            "case_count": len(both_qor),
            "scalar_and_delta_trojan_sum": _sum_available(
                both_qor, "scalar_actual_and_delta_trojan"
            ),
            "multi_head_and_delta_trojan_sum": _sum_available(
                both_qor, "multi_head_actual_and_delta_trojan"
            ),
            "scalar_and_delta_trojan_mean": _mean_available(
                both_qor, "scalar_actual_and_delta_trojan"
            ),
            "multi_head_and_delta_trojan_mean": _mean_available(
                both_qor, "multi_head_actual_and_delta_trojan"
            ),
            "scalar_level_delta_trojan_mean": _mean_available(
                both_qor, "scalar_actual_level_delta_trojan"
            ),
            "multi_head_level_delta_trojan_mean": _mean_available(
                both_qor, "multi_head_actual_level_delta_trojan"
            ),
        },
        "multi_head_telemetry": {
            "cases_with_discovery": sum(
                row.get("initial_heads") is not None for row in pairs
            ),
            "cases_with_patch": sum(row.get("final_heads") is not None for row in pairs),
            "final_heads_sum": _sum_available(pairs, "final_heads"),
            "proved_heads_sum": _sum_available(pairs, "proved_heads"),
            "head_rule_events": _sum_available(pairs, "head_rule_events"),
            "formal_rebuild_events": _sum_available(pairs, "formal_rebuild_events"),
            "formal_cex_returned": _sum_available(pairs, "formal_cex_returned"),
            "formal_cex_added": _sum_available(pairs, "formal_cex_added"),
            "formal_solver_checks": _sum_available(pairs, "formal_solver_checks"),
            "formal_miter_ms": _sum_available(pairs, "formal_miter_ms"),
            "cec_feedback_rounds": _sum_available(pairs, "cec_feedback_rounds"),
            "cec_feedback_labels_added": _sum_available(
                pairs, "cec_feedback_labels_added"
            ),
            "cec_feedback_new_heads": _sum_available(pairs, "cec_feedback_new_heads"),
        },
    }


def _atomic_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", newline="", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    ) as stream:
        temporary = Path(stream.name)
        writer = csv.DictWriter(stream, fieldnames=PAIRED_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    ) as stream:
        temporary = Path(stream.name)
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _format_number(value: object, digits: int = 2) -> str:
    if value is None:
        return "—"
    if isinstance(value, int):
        return str(value)
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def _report(summary: Mapping[str, Any], pairs: Sequence[Mapping[str, Any]]) -> str:
    aggregate_data = summary["aggregate"]
    provenance = summary["provenance"]
    lines = [
        "# V4 13-case Z3-PB multi-head comparison",
        "",
        "Correctness is counted only when the runner status is `PASS` and the "
        "external ABC CEC result is equivalent. Ground-truth simulation is "
        "reported as telemetry, not used as the correctness authority.",
        "",
        "## Outcome",
        "",
        f"- Scalar Z3-PB + formal: **{aggregate_data['scalar_pass']}/{aggregate_data['case_count']} PASS**",
        f"- Multi-head Z3-PB + formal: **{aggregate_data['multi_head_pass']}/{aggregate_data['case_count']} PASS**",
        f"- Net change: **{aggregate_data['pass_delta']:+d} PASS** "
        f"({aggregate_data['gains']} gains, {aggregate_data['regressions']} regressions)",
        "",
        "## Status transitions",
        "",
        "| Transition | Cases |",
        "|---|---:|",
    ]
    for transition, count in aggregate_data["transitions"].items():
        lines.append(f"| `{transition}` | {count} |")
    lines.extend(
        [
            "",
            "## Per-case results",
            "",
            "| Case | Scalar | Multi-head | Wall scalar / multi (ms) | "
            "AND delta scalar / multi | Level delta scalar / multi | Heads proved/final |",
            "|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in pairs:
        wall = (
            f"{_format_number(row.get('scalar_wall_ms'))} / "
            f"{_format_number(row.get('multi_head_wall_ms'))}"
        )
        area = (
            f"{_format_number(row.get('scalar_actual_and_delta_trojan'))} / "
            f"{_format_number(row.get('multi_head_actual_and_delta_trojan'))}"
        )
        level = (
            f"{_format_number(row.get('scalar_actual_level_delta_trojan'))} / "
            f"{_format_number(row.get('multi_head_actual_level_delta_trojan'))}"
        )
        heads = (
            f"{_format_number(row.get('proved_heads'))}/"
            f"{_format_number(row.get('final_heads'))}"
        )
        lines.append(
            f"| `{row['case_id']}` | `{row['scalar_status']}` | "
            f"`{row['multi_head_status']}` | {wall} | {area} | {level} | {heads} |"
        )
    both_pass = aggregate_data["both_pass"]
    qor = aggregate_data["both_pass_qor"]
    telemetry = aggregate_data["multi_head_telemetry"]
    lines.extend(
        [
            "",
            "## Paired runtime and QoR",
            "",
            f"- All 13 cases total wall time: scalar "
            f"{_format_number(aggregate_data['all_cases_wall']['scalar_ms'])} ms, "
            f"multi-head {_format_number(aggregate_data['all_cases_wall']['multi_head_ms'])} ms.",
            f"- Both-PASS subset: {both_pass['case_count']} cases; multi/scalar "
            f"wall-time geometric mean "
            f"{_format_number(both_pass['multi_over_scalar_wall_geomean'], 3)}×.",
            f"- Both-PASS QoR subset: {qor['case_count']} cases; mean actual AND "
            f"delta vs Trojan scalar/multi = "
            f"{_format_number(qor['scalar_and_delta_trojan_mean'])} / "
            f"{_format_number(qor['multi_head_and_delta_trojan_mean'])}; mean "
            f"level delta = {_format_number(qor['scalar_level_delta_trojan_mean'])} / "
            f"{_format_number(qor['multi_head_level_delta_trojan_mean'])}.",
            "",
            "## Multi-head telemetry",
            "",
            f"- Cases reaching discovery/patch: {telemetry['cases_with_discovery']} / "
            f"{telemetry['cases_with_patch']}.",
            f"- Final/proved heads summed across cases: "
            f"{_format_number(telemetry['final_heads_sum'])} / "
            f"{_format_number(telemetry['proved_heads_sum'])}.",
            f"- Head rule events / formal rebuild events: "
            f"{_format_number(telemetry['head_rule_events'])} / "
            f"{_format_number(telemetry['formal_rebuild_events'])}.",
            f"- Formal CEX returned/added and solver checks: "
            f"{_format_number(telemetry['formal_cex_returned'])} / "
            f"{_format_number(telemetry['formal_cex_added'])} / "
            f"{_format_number(telemetry['formal_solver_checks'])}.",
            f"- Internal CEC feedback rounds / labels added / new heads: "
            f"{_format_number(telemetry['cec_feedback_rounds'])} / "
            f"{_format_number(telemetry['cec_feedback_labels_added'])} / "
            f"{_format_number(telemetry['cec_feedback_new_heads'])}.",
            "",
            "## Provenance",
            "",
            f"- Manifest SHA-256: `{provenance['manifest_sha256']}`",
            f"- Scalar binary SHA-256: `{provenance['scalar_binary_sha256']}`",
            f"- Multi-head binary SHA-256: `{provenance['multi_head_binary_sha256']}`",
            f"- ABC SHA-256: `{provenance['abc_sha256']}`",
            f"- `show` SHA-256: `{provenance['show_sha256']}`",
            f"- Validated benchmark inputs: {provenance['validated_input_case_count']} exact cases.",
            f"- Formal config: timeout 10000 ms, 5 scalar refinement rounds, "
            f"5 CEX/check; multi-head refinement limit 20.",
            "",
            "`actual_*_and` columns are the runner's ABC `show` area metric "
            "(AIG AND count); QoR comparisons are restricted to cases where both arms PASS.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_checksums(output_dir: Path) -> None:
    entries = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_file() and path != output_dir / "SHA256SUMS":
            relative = path.relative_to(output_dir)
            entries.append(f"{_sha256(path)}  {relative.as_posix()}\n")
    _atomic_text(output_dir / "SHA256SUMS", "".join(entries))


def analyze(
    *, manifest: Path, baseline_results: Sequence[Path], multi_head_root: Path,
    output_dir: Path, profile: str = DEFAULT_PROFILE,
) -> Dict[str, Any]:
    manifest_cases, case_ids, manifest_sha, common_args, manifest_profiles = (
        _load_manifest(manifest, profile)
    )
    for required in (
        multi_head_root / "run_context.json",
        multi_head_root / "results.csv",
        multi_head_root / "summary.json",
    ):
        if not required.is_file():
            raise IncompleteRunError(
                f"multi-head raw is incomplete: missing {required}"
            )
    scalar_rows, scalar_contexts, scalar_sources = _read_result_files(
        baseline_results, "scalar"
    )
    multi_results = multi_head_root / "results.csv"
    multi_rows, multi_contexts, multi_sources = _read_result_files(
        [multi_results], "multi-head"
    )
    _assert_exact_case_set(scalar_rows, case_ids, "scalar baseline")
    _assert_exact_case_set(multi_rows, case_ids, "multi-head")

    unique_scalar_contexts = {id(value): value for value in scalar_contexts.values()}.values()
    for context in unique_scalar_contexts:
        _validate_context(
            context, label="scalar", manifest_sha256=manifest_sha,
            common_args=common_args, multi_head=False, expected_profile=None,
        )
        context_profile = context.get("profile")
        if context_profile not in manifest_profiles:
            raise RuntimeError(f"scalar context profile is absent from manifest: {context_profile!r}")
    multi_context = next(iter(multi_contexts.values()))
    _validate_context(
        multi_context, label="multi-head", manifest_sha256=manifest_sha,
        common_args=common_args, multi_head=True, expected_profile=profile,
    )

    scalar_binary_hashes = {context.get("binary_sha256") for context in unique_scalar_contexts}
    scalar_abc_hashes = {context.get("abc_sha256") for context in unique_scalar_contexts}
    scalar_show_hashes = {context.get("show_sha256") for context in unique_scalar_contexts}
    scalar_runner_hashes = {context.get("runner_sha256") for context in unique_scalar_contexts}
    if len(scalar_binary_hashes) != 1 or len(scalar_abc_hashes) != 1 \
            or len(scalar_show_hashes) != 1 or len(scalar_runner_hashes) != 1:
        raise RuntimeError("scalar baseline fragments have inconsistent tool provenance")
    scalar_binary_sha = str(next(iter(scalar_binary_hashes)))
    abc_sha = str(next(iter(scalar_abc_hashes)))
    show_sha = str(next(iter(scalar_show_hashes)))
    if multi_context.get("abc_sha256") != abc_sha:
        raise RuntimeError("scalar/multi-head ABC binary mismatch")
    if multi_context.get("show_sha256") != show_sha:
        raise RuntimeError("scalar/multi-head show binary mismatch")
    multi_binary_sha = str(multi_context["binary_sha256"])

    identity_cache: Dict[Path, Tuple[str, int]] = {}
    scalar_inputs: Dict[str, Dict[str, str]] = {}
    multi_inputs: Dict[str, Dict[str, str]] = {}
    for case_id in case_ids:
        scalar_context = scalar_contexts[case_id]
        context_profile = scalar_context.get("profile")
        if case_id not in manifest_profiles[str(context_profile)]:
            raise RuntimeError(
                f"scalar case {case_id} does not belong to context profile {context_profile}"
            )
        _, scalar_inputs[case_id] = _validate_row(
            scalar_rows[case_id], label="scalar", case=manifest_cases[case_id],
            context=scalar_context, common_args=common_args, multi_head=False,
            identity_cache=identity_cache,
        )
        _, multi_inputs[case_id] = _validate_row(
            multi_rows[case_id], label="multi-head", case=manifest_cases[case_id],
            context=multi_context, common_args=common_args, multi_head=True,
            identity_cache=identity_cache,
        )
        if scalar_inputs[case_id] != multi_inputs[case_id]:
            raise RuntimeError(f"paired benchmark input mismatch for {case_id}")

    _, multi_summary_meta = _load_multi_summary(
        multi_head_root, multi_rows, case_ids, multi_context, manifest_cases,
        identity_cache,
    )
    pairs = build_pairs(
        manifest_cases, case_ids, scalar_rows, multi_rows, scalar_inputs,
        scalar_binary_sha, multi_binary_sha, abc_sha, show_sha,
    )
    aggregate_data = aggregate(pairs)
    if aggregate_data["case_count"] != EXPECTED_CASE_COUNT:
        raise RuntimeError("internal error: aggregate is not the exact 13-case set")

    provenance = {
        "manifest": str(manifest),
        "manifest_sha256": manifest_sha,
        "profile": profile,
        "case_ids": case_ids,
        "validated_input_case_count": len(scalar_inputs),
        "scalar_binary_sha256": scalar_binary_sha,
        "multi_head_binary_sha256": multi_binary_sha,
        "abc_sha256": abc_sha,
        "show_sha256": show_sha,
        "scalar_runner_sha256": next(iter(scalar_runner_hashes)),
        "multi_head_runner_sha256": multi_context.get("runner_sha256"),
        "scalar_sources": scalar_sources,
        "multi_head_sources": multi_sources,
        "multi_head_summary": multi_summary_meta,
        "config": {
            **EXPECTED_FORMAL_CONFIG,
            "rule_multi_head": True,
            "rule_multi_head_max_rounds": EXPECTED_MULTI_HEAD_ROUNDS,
            "timeout_override": EXPECTED_TIMEOUT_SECONDS,
            "abc_timeout": EXPECTED_ABC_TIMEOUT_SECONDS,
            "common_args": common_args,
        },
    }
    # Avoid embedding each full context twice inside summary source metadata.
    for source in provenance["scalar_sources"] + provenance["multi_head_sources"]:
        context = source.pop("context")
        source["context_key"] = context.get("context_key")
        source["profile"] = context.get("profile")
        source["runner_schema"] = context.get("runner_schema")

    summary: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "correctness_authority": "external ABC CEC",
        "provenance": provenance,
        "aggregate": aggregate_data,
    }

    # Validation is complete.  Only now may the output directory be mutated.
    output_dir.mkdir(parents=True, exist_ok=True)
    paired_path = output_dir / "paired_results.csv"
    _atomic_csv(paired_path, pairs)
    summary["paired_results_sha256"] = _sha256(paired_path)
    summary_path = output_dir / "summary.json"
    _atomic_text(summary_path, json.dumps(summary, indent=2, sort_keys=True) + "\n")
    report_path = output_dir / "REPORT.md"
    _atomic_text(report_path, _report(summary, pairs))
    _write_checksums(output_dir)
    return summary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--baseline-results", type=Path, action="append", required=True,
        help="scalar Z3-PB+formal result CSV; repeat for on_01 and on_02",
    )
    parser.add_argument(
        "--multi-head-root", type=Path, required=True,
        help="completed runner output root containing results.csv and summary.json",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        summary = analyze(
            manifest=args.manifest,
            baseline_results=args.baseline_results,
            multi_head_root=args.multi_head_root,
            output_dir=args.output_dir,
            profile=args.profile,
        )
    except (IncompleteRunError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    result = summary["aggregate"]
    print(
        f"cases={result['case_count']} scalar_pass={result['scalar_pass']} "
        f"multi_head_pass={result['multi_head_pass']} "
        f"gains={result['gains']} regressions={result['regressions']} "
        f"output={args.output_dir.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
