#!/usr/bin/env python3
"""Generate reproducible V4 multi-independent-Trojan BENCH cases.

The core dataset deliberately uses primary-input trigger literals.  Distinct
primary inputs make every requested trigger-activation mask constructively
satisfiable; an optional shared-literal fraction provides a controlled overlap
stress test while retaining at least one unique literal per Trojan instance.

Each case is self-contained and contains:

* ``golden.bench`` -- a byte-for-byte copy of the source circuit;
* ``combined.bench`` -- all requested Trojan instances inserted;
* ``individual/HTi.bench`` -- exactly one Trojan instance inserted; and
* ``case_manifest.json`` -- hashes, interfaces, trigger rules, payload sites,
  and partial PI assignments for every exact activation mask.

No existing dataset is overwritten.  Re-running an existing case is an error
unless ``--skip-existing`` is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA_VERSION = "v4-multi-independent-trojan/1"
GENERATOR_NAME = "generate_multi_trojan_dataset.py"
GENERATOR_VERSION = "1.0.0"
SUPPORTED_TROJAN_COUNTS = frozenset({1, 2, 3, 5})

_DECL_RE = re.compile(r"^(INPUT|OUTPUT)\s*\(\s*([^)]*?)\s*\)\s*$", re.IGNORECASE)
_ASSIGN_RE = re.compile(r"^([^=\s]+)\s*=\s*(.*?)\s*$")
_GATE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*$")


class GenerationError(RuntimeError):
    """Raised for an invalid or infeasible requested dataset case."""


@dataclass(frozen=True)
class Gate:
    output: str
    operation: str
    inputs: Tuple[str, ...]


@dataclass
class BenchCircuit:
    path: Path
    primary_inputs: List[str]
    primary_outputs: List[str]
    gates: Dict[str, Gate]
    depths: Dict[str, int]
    fanout_counts: Dict[str, int]
    distance_to_output: Dict[str, int]
    existing_nets: set[str]

    @classmethod
    def parse(cls, path: Path) -> "BenchCircuit":
        primary_inputs: List[str] = []
        primary_outputs: List[str] = []
        gates: Dict[str, Gate] = {}
        depths: Dict[str, int] = {}
        fanout_counts: Dict[str, int] = {}
        existing_nets: set[str] = set()

        try:
            source = path.open("r", encoding="utf-8", errors="strict")
        except OSError as exc:
            raise GenerationError(f"cannot open BENCH file {path}: {exc}") from exc

        with source:
            for line_number, raw in enumerate(source, 1):
                parsed = _parse_bench_line(raw, line_number, path)
                if parsed is None:
                    continue
                kind, name, operation, inputs = parsed
                if kind == "input":
                    if name in existing_nets:
                        raise GenerationError(
                            f"{path}:{line_number}: duplicate net declaration {name!r}"
                        )
                    primary_inputs.append(name)
                    existing_nets.add(name)
                    depths[name] = 0
                    fanout_counts.setdefault(name, 0)
                    continue
                if kind == "output":
                    primary_outputs.append(name)
                    continue

                if name in existing_nets:
                    raise GenerationError(
                        f"{path}:{line_number}: duplicate driver for net {name!r}"
                    )
                assert operation is not None
                gate = Gate(name, operation, inputs)
                gates[name] = gate
                existing_nets.add(name)
                fanout_counts.setdefault(name, 0)
                if operation == "VDD":
                    depths[name] = 0
                    continue

                missing = [net for net in inputs if net not in depths]
                if missing:
                    raise GenerationError(
                        f"{path}:{line_number}: forward or undefined input net(s): "
                        + ", ".join(missing[:8])
                    )
                depths[name] = 1 + max(depths[net] for net in inputs)
                for net in inputs:
                    fanout_counts[net] = fanout_counts.get(net, 0) + 1

        if not primary_inputs:
            raise GenerationError(f"{path}: no INPUT declarations")
        if not primary_outputs:
            raise GenerationError(f"{path}: no OUTPUT declarations")
        undefined_outputs = [net for net in primary_outputs if net not in existing_nets]
        if undefined_outputs:
            raise GenerationError(
                f"{path}: undefined OUTPUT net(s): " + ", ".join(undefined_outputs[:8])
            )

        # Traverse from outputs towards PIs.  This both proves output reachability
        # and computes the shortest structural distance from every live net to a PO.
        distance_to_output: Dict[str, int] = {}
        stack: List[Tuple[str, int]] = [(net, 0) for net in primary_outputs]
        while stack:
            net, distance = stack.pop()
            previous = distance_to_output.get(net)
            if previous is not None and previous <= distance:
                continue
            distance_to_output[net] = distance
            gate = gates.get(net)
            if gate is not None:
                for source_net in gate.inputs:
                    stack.append((source_net, distance + 1))

        return cls(
            path=path,
            primary_inputs=primary_inputs,
            primary_outputs=primary_outputs,
            gates=gates,
            depths=depths,
            fanout_counts=fanout_counts,
            distance_to_output=distance_to_output,
            existing_nets=existing_nets,
        )

    def victim_candidates_by_depth(self) -> Dict[int, List[str]]:
        outputs = set(self.primary_outputs)
        groups: Dict[int, List[str]] = {}
        for net in self.gates:
            # Replacing fanouts of a direct PO would leave that PO unchanged, so
            # direct outputs are excluded.  Dangling gates are excluded as well.
            if net in outputs:
                continue
            if self.fanout_counts.get(net, 0) == 0:
                continue
            if net not in self.distance_to_output:
                continue
            groups.setdefault(self.depths[net], []).append(net)
        for nets in groups.values():
            nets.sort()
        return groups


@dataclass(frozen=True)
class TriggerLiteral:
    net: str
    required_value: int
    shared: bool


@dataclass
class TrojanInstance:
    instance_id: str
    victim_net: str
    literals: List[TriggerLiteral]
    trigger_net: str
    payload_result_net: str
    logic_lines: List[str]


class NameFactory:
    def __init__(self, existing: Iterable[str]) -> None:
        self._used = set(existing)

    def reserve(self, requested: str) -> str:
        if requested not in self._used:
            self._used.add(requested)
            return requested
        suffix = 1
        while f"{requested}_{suffix}" in self._used:
            suffix += 1
        chosen = f"{requested}_{suffix}"
        self._used.add(chosen)
        return chosen


def _parse_bench_line(
    raw: str, line_number: int, path: Path
) -> Optional[Tuple[str, str, Optional[str], Tuple[str, ...]]]:
    stripped = raw.strip()
    if not stripped or stripped.startswith("#"):
        return None

    declaration = _DECL_RE.fullmatch(stripped)
    if declaration:
        kind = declaration.group(1).lower()
        name = declaration.group(2).strip()
        if not name:
            raise GenerationError(f"{path}:{line_number}: empty {kind.upper()} name")
        return kind, name, None, ()

    assignment = _ASSIGN_RE.fullmatch(stripped)
    if not assignment:
        raise GenerationError(f"{path}:{line_number}: unsupported BENCH syntax: {stripped!r}")
    output = assignment.group(1)
    expression = assignment.group(2)
    if expression.lower() == "vdd":
        return "gate", output, "VDD", ()

    gate_match = _GATE_RE.fullmatch(expression)
    if not gate_match:
        raise GenerationError(
            f"{path}:{line_number}: unsupported gate expression: {expression!r}"
        )
    operation = gate_match.group(1).upper()
    inputs_text = gate_match.group(2).strip()
    inputs = tuple(token.strip() for token in inputs_text.split(",") if token.strip())
    if not inputs:
        raise GenerationError(f"{path}:{line_number}: gate {operation} has no inputs")
    return "gate", output, operation, inputs


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file_record(path: Path) -> Dict[str, object]:
    return {"sha256": _sha256_file(path), "size_bytes": path.stat().st_size}


def _resolve_inputs(raw_inputs: Sequence[str]) -> List[Path]:
    paths: List[Path] = []
    for raw in raw_inputs:
        candidate = Path(raw).expanduser()
        if candidate.is_dir():
            paths.extend(sorted(candidate.glob("*.bench")))
        elif candidate.is_file():
            if candidate.suffix.lower() != ".bench":
                raise GenerationError(f"input is not a .bench file: {candidate}")
            paths.append(candidate)
        else:
            raise GenerationError(f"input path does not exist: {candidate}")

    unique: Dict[Path, None] = {}
    for path in paths:
        unique[path.resolve()] = None
    resolved = sorted(unique, key=lambda item: str(item))
    if not resolved:
        raise GenerationError("no .bench inputs found")
    return resolved


def _select_victims(
    circuit: BenchCircuit,
    count: int,
    placement: str,
    rng: random.Random,
    allow_fallback: bool,
) -> Tuple[List[str], Dict[str, object]]:
    groups = circuit.victim_candidates_by_depth()
    feasible = {depth: nets for depth, nets in groups.items() if len(nets) >= count}
    fallback_used = False
    fallback_reason: Optional[str] = None

    if feasible:
        if placement == "random":
            # Pick an anchor from the union, so larger depth groups naturally
            # receive proportional weight without relying on dict order.
            anchors = sorted(net for nets in feasible.values() for net in nets)
            anchor = anchors[rng.randrange(len(anchors))]
            depth = circuit.depths[anchor]
            victims = rng.sample(feasible[depth], count)
        elif placement == "output-near":
            # Compare the N nearest candidates at each depth.  Equal depth makes
            # the selected victims a structural antichain.
            ranked_groups: List[Tuple[Tuple[float, int, int], int, List[str]]] = []
            for depth, nets in feasible.items():
                ranked = sorted(
                    nets,
                    key=lambda net: (circuit.distance_to_output[net], net),
                )
                nearest = ranked[:count]
                score = (
                    sum(circuit.distance_to_output[net] for net in nearest) / count,
                    max(circuit.distance_to_output[net] for net in nearest),
                    depth,
                )
                ranked_groups.append((score, depth, ranked))
            _, depth, ranked = min(ranked_groups, key=lambda item: item[0])
            cutoff_distance = circuit.distance_to_output[ranked[count - 1]]
            near_pool = [
                net
                for net in ranked
                if circuit.distance_to_output[net] <= cutoff_distance
            ]
            victims = rng.sample(near_pool, count)
        else:  # guarded by argparse, retained for programmatic callers
            raise GenerationError(f"unknown victim placement: {placement}")
        actual_strategy = "same_topological_depth_antichain"
        selected_depth: Optional[int] = circuit.depths[victims[0]]
    else:
        eligible = sorted(net for nets in groups.values() for net in nets)
        if len(eligible) < count:
            raise GenerationError(
                f"{circuit.path}: needs {count} distinct output-reachable internal "
                f"victims, but only {len(eligible)} are eligible"
            )
        if not allow_fallback:
            raise GenerationError(
                f"{circuit.path}: cannot place {count} victims at a common "
                "topological depth; pass --allow-victim-fallback to relax the "
                "structural-antichain constraint"
            )
        fallback_used = True
        fallback_reason = "no topological depth contained enough eligible victims"
        if placement == "output-near":
            eligible.sort(key=lambda net: (circuit.distance_to_output[net], net))
            victims = eligible[:count]
        else:
            victims = rng.sample(eligible, count)
        actual_strategy = "distinct_output_reachable_relaxed"
        selected_depth = None

    return victims, {
        "requested": placement,
        "actual_strategy": actual_strategy,
        "same_depth_antichain": not fallback_used,
        "selected_topological_depth": selected_depth,
        "fallback_allowed": allow_fallback,
        "fallback_used": fallback_used,
        "fallback_reason": fallback_reason,
    }


def _shared_literal_count(trigger_size: int, requested_overlap: float, count: int) -> int:
    if count == 1:
        return 0
    # Quantize to the nearest representable literal count.  Python's round is
    # deterministic; the actual ratio is always recorded in the manifest.
    shared = int(round(trigger_size * requested_overlap))
    shared = max(0, min(trigger_size - 1, shared))
    if requested_overlap > 0.0 and shared == 0:
        raise GenerationError(
            f"trigger overlap {requested_overlap} is too small for trigger size "
            f"{trigger_size}; no shared literal would be generated"
        )
    return shared


def _select_trigger_literals(
    primary_inputs: Sequence[str],
    count: int,
    trigger_size: int,
    requested_overlap: float,
    rng: random.Random,
) -> Tuple[List[List[TriggerLiteral]], int]:
    shared_count = _shared_literal_count(trigger_size, requested_overlap, count)
    unique_per_instance = trigger_size - shared_count
    required_inputs = shared_count + count * unique_per_instance
    if required_inputs > len(primary_inputs):
        raise GenerationError(
            f"needs {required_inputs} distinct PI trigger sources for N={count}, "
            f"trigger_size={trigger_size}, shared_literals={shared_count}; circuit "
            f"has only {len(primary_inputs)} PIs"
        )

    pool = sorted(primary_inputs)
    rng.shuffle(pool)
    chosen = pool[:required_inputs]
    cursor = 0
    shared: List[TriggerLiteral] = []
    for net in chosen[:shared_count]:
        shared.append(TriggerLiteral(net, rng.getrandbits(1), True))
    cursor += shared_count

    result: List[List[TriggerLiteral]] = []
    for _ in range(count):
        literals = list(shared)
        for net in chosen[cursor : cursor + unique_per_instance]:
            literals.append(TriggerLiteral(net, rng.getrandbits(1), False))
        cursor += unique_per_instance
        result.append(literals)
    return result, shared_count


def _build_instance(
    index: int,
    victim: str,
    literals: Sequence[TriggerLiteral],
    names: NameFactory,
) -> TrojanInstance:
    instance_id = f"HT{index}"
    prefix = f"__v4_{instance_id.lower()}"
    lines: List[str] = []
    trigger_inputs: List[str] = []

    for literal_index, literal in enumerate(literals):
        if literal.required_value == 1:
            trigger_inputs.append(literal.net)
        else:
            inverse = names.reserve(f"{prefix}_literal{literal_index}_not")
            lines.append(f"{inverse} = NOT({literal.net})\n")
            trigger_inputs.append(inverse)

    trigger_net = names.reserve(f"{prefix}_trigger")
    if len(trigger_inputs) == 1:
        lines.append(f"{trigger_net} = BUFF({trigger_inputs[0]})\n")
    else:
        lines.append(f"{trigger_net} = AND({','.join(trigger_inputs)})\n")

    # Decomposed XOR keeps the generated netlist within the gate vocabulary
    # already handled by this repository's parser/simulator.
    trigger_not = names.reserve(f"{prefix}_trigger_not")
    victim_not = names.reserve(f"{prefix}_victim_not")
    keep_term = names.reserve(f"{prefix}_keep_term")
    flip_term = names.reserve(f"{prefix}_flip_term")
    payload_result = names.reserve(f"{prefix}_payload")
    lines.extend(
        [
            f"{trigger_not} = NOT({trigger_net})\n",
            f"{victim_not} = NOT({victim})\n",
            f"{keep_term} = AND({trigger_not},{victim})\n",
            f"{flip_term} = AND({trigger_net},{victim_not})\n",
            f"{payload_result} = OR({keep_term},{flip_term})\n",
        ]
    )
    return TrojanInstance(
        instance_id=instance_id,
        victim_net=victim,
        literals=list(literals),
        trigger_net=trigger_net,
        payload_result_net=payload_result,
        logic_lines=lines,
    )


def _fanout_occurrences(
    circuit: BenchCircuit, victims: Sequence[str]
) -> Dict[str, List[Dict[str, object]]]:
    victim_set = set(victims)
    result: Dict[str, List[Dict[str, object]]] = {victim: [] for victim in victims}
    for gate in circuit.gates.values():
        indices_by_victim: Dict[str, List[int]] = {}
        for index, source in enumerate(gate.inputs):
            if source in victim_set:
                indices_by_victim.setdefault(source, []).append(index)
        for victim, indices in indices_by_victim.items():
            result[victim].append(
                {"gate_output": gate.output, "input_indices": indices}
            )
    return result


def _rewrite_bench(
    circuit: BenchCircuit,
    output_path: Path,
    replacements: Mapping[str, str],
    instances: Sequence[TrojanInstance],
) -> None:
    with circuit.path.open("r", encoding="utf-8", errors="strict") as source, output_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as output:
        for line_number, raw in enumerate(source, 1):
            parsed = _parse_bench_line(raw, line_number, circuit.path)
            if parsed is None or parsed[0] != "gate" or parsed[2] == "VDD":
                output.write(raw)
                continue
            _, gate_output, operation, gate_inputs = parsed
            rewritten = tuple(replacements.get(net, net) for net in gate_inputs)
            if rewritten == gate_inputs:
                output.write(raw)
            else:
                assert operation is not None
                output.write(f"{gate_output} = {operation}({','.join(rewritten)})\n")

        output.write("\n# --- V4 multi-independent Trojan logic ---\n")
        for instance in instances:
            output.write(f"# {instance.instance_id}\n")
            output.writelines(instance.logic_lines)


def _exact_mask_witnesses(
    instances: Sequence[TrojanInstance],
) -> Dict[str, Dict[str, int]]:
    """Return partial PI assignments satisfying each exact activation mask."""
    count = len(instances)
    all_literals: Dict[str, int] = {}
    for instance in instances:
        for literal in instance.literals:
            previous = all_literals.setdefault(literal.net, literal.required_value)
            if previous != literal.required_value:
                raise AssertionError("shared trigger PI received inconsistent values")

    witnesses: Dict[str, Dict[str, int]] = {}
    for mask in range(1 << count):
        assignment = dict(all_literals)
        for index, instance in enumerate(instances):
            if mask & (1 << index):
                continue
            unique_literals = [literal for literal in instance.literals if not literal.shared]
            if not unique_literals:
                raise AssertionError("instance has no unique literal for exact-mask witness")
            blocker = unique_literals[0]
            assignment[blocker.net] = 1 - blocker.required_value
        # Character order follows instances[] directly: the leftmost character
        # is HT0, the next is HT1, and so on.  Do not expose the internal integer
        # bit order in the interchange format.
        key = "".join("1" if mask & (1 << index) else "0" for index in range(count))
        witnesses[key] = dict(sorted(assignment.items()))
    return witnesses


def _manifest_instance(
    instance: TrojanInstance,
    individual_path: str,
    fanouts: Sequence[Dict[str, object]],
) -> Dict[str, object]:
    return {
        "instance_id": instance.instance_id,
        "individual_path": individual_path,
        "victim_net": instance.victim_net,
        "trigger": {
            "source_kind": "primary_input",
            "gate": "AND",
            "trigger_net": instance.trigger_net,
            "literals": [
                {
                    "net": literal.net,
                    "required_value": literal.required_value,
                    "estimated_probability": 0.5,
                    "shared_across_instances": literal.shared,
                }
                for literal in instance.literals
            ],
            "expected_activation_probability": math.ldexp(1.0, -len(instance.literals)),
        },
        "payload": {
            "type": "XOR_TOGGLE",
            "source_net": instance.victim_net,
            "result_net": instance.payload_result_net,
            "rewritten_fanouts": list(fanouts),
        },
    }


def generate_case(
    source_path: Path,
    output_root: Path,
    trojan_count: int,
    trigger_size: int,
    seed: int,
    requested_overlap: float,
    victim_placement: str,
    allow_victim_fallback: bool,
    skip_existing: bool,
) -> Optional[Path]:
    if trojan_count not in SUPPORTED_TROJAN_COUNTS:
        raise GenerationError(
            f"unsupported Trojan count {trojan_count}; choose from "
            + ", ".join(map(str, sorted(SUPPORTED_TROJAN_COUNTS)))
        )
    if trigger_size < 1:
        raise GenerationError("trigger size must be at least 1")
    if seed < 0 or seed > (1 << 63) - 1:
        raise GenerationError("seed must be in [0, 2^63-1]")
    if not 0.0 <= requested_overlap < 1.0:
        raise GenerationError("trigger overlap must be in [0, 1)")

    source_path = source_path.resolve()
    source_sha256 = _sha256_file(source_path)
    benchmark = source_path.stem
    overlap_tag = int(round(requested_overlap * 1000))
    case_id = (
        f"{benchmark}_n{trojan_count}_t{trigger_size}_o{overlap_tag:03d}_"
        f"s{seed}_{source_sha256[:8]}"
    )
    benchmark_root = output_root / benchmark
    destination = benchmark_root / case_id
    if destination.exists():
        if skip_existing:
            return None
        raise GenerationError(
            f"refusing to overwrite existing case: {destination}; use "
            "--skip-existing to leave it untouched"
        )

    circuit = BenchCircuit.parse(source_path)
    rng = random.Random(seed)
    victims, placement_record = _select_victims(
        circuit,
        trojan_count,
        victim_placement,
        rng,
        allow_victim_fallback,
    )
    trigger_rules, shared_count = _select_trigger_literals(
        circuit.primary_inputs,
        trojan_count,
        trigger_size,
        requested_overlap,
        rng,
    )
    name_factory = NameFactory(circuit.existing_nets)
    instances = [
        _build_instance(index, victims[index], trigger_rules[index], name_factory)
        for index in range(trojan_count)
    ]
    fanouts = _fanout_occurrences(circuit, victims)
    for victim in victims:
        if not fanouts[victim]:
            raise AssertionError(f"selected victim {victim!r} unexpectedly has no fanout")

    benchmark_root.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=f".{case_id}.tmp.", dir=benchmark_root))
    try:
        individual_dir = temp_dir / "individual"
        individual_dir.mkdir()
        golden_path = temp_dir / "golden.bench"
        combined_path = temp_dir / "combined.bench"
        shutil.copyfile(source_path, golden_path)

        combined_replacements = {
            instance.victim_net: instance.payload_result_net for instance in instances
        }
        _rewrite_bench(circuit, combined_path, combined_replacements, instances)

        relative_individual_paths: Dict[str, str] = {}
        for instance in instances:
            relative = f"individual/{instance.instance_id}.bench"
            relative_individual_paths[instance.instance_id] = relative
            _rewrite_bench(
                circuit,
                temp_dir / relative,
                {instance.victim_net: instance.payload_result_net},
                [instance],
            )

        all_relative_files = ["golden.bench", "combined.bench"] + [
            relative_individual_paths[instance.instance_id] for instance in instances
        ]
        file_records = {
            relative: _file_record(temp_dir / relative) for relative in all_relative_files
        }
        # The copied file must be byte-identical, not merely parse-equivalent.
        if file_records["golden.bench"]["sha256"] != source_sha256:
            raise AssertionError("golden copy hash differs from source hash")

        actual_overlap = shared_count / trigger_size
        unique_per_instance = trigger_size - shared_count
        if shared_count:
            expected_any_activation = math.ldexp(1.0, -shared_count) * (
                1.0 - (1.0 - math.ldexp(1.0, -unique_per_instance)) ** trojan_count
            )
            topology = "shared_trigger_literals"
        else:
            expected_any_activation = 1.0 - (
                1.0 - math.ldexp(1.0, -trigger_size)
            ) ** trojan_count
            topology = "disjoint"

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "case_id": case_id,
            "benchmark": benchmark,
            "golden_path": "golden.bench",
            "combined_path": "combined.bench",
            "paths": {
                "golden": "golden.bench",
                "combined": "combined.bench",
                "individual": relative_individual_paths,
            },
            "interfaces": {
                "primary_inputs": circuit.primary_inputs,
                "primary_outputs": circuit.primary_outputs,
            },
            "generation": {
                "generator": GENERATOR_NAME,
                "generator_version": GENERATOR_VERSION,
                "generator_sha256": _sha256_file(Path(__file__).resolve()),
                "seed": seed,
                "trojan_count": trojan_count,
                "trigger_size": trigger_size,
                "trigger_source": "pi",
                "requested_trigger_overlap": requested_overlap,
                "actual_trigger_overlap": actual_overlap,
                "shared_literal_count": shared_count,
                "unique_literals_per_instance": unique_per_instance,
                # ``topology`` is retained as a compact matrix key and refers
                # only to trigger-literal sharing.  Payload cones may reconverge
                # even though victim nets are distinct and form an antichain.
                "topology": topology,
                "interaction_topology": topology,
                "trigger_topology": topology,
                "payload_topology": (
                    "distinct_victims_same_depth"
                    if placement_record["same_depth_antichain"]
                    else "distinct_victims_relaxed"
                ),
                "payload_cone_overlap": "unconstrained",
                "payload_placement": placement_record,
                "source_golden_sha256": source_sha256,
            },
            "files": file_records,
            "instances": [
                _manifest_instance(
                    instance,
                    relative_individual_paths[instance.instance_id],
                    fanouts[instance.victim_net],
                )
                for instance in instances
            ],
            "trigger_witnesses": {
                "description": (
                    "Partial PI assignments that make exactly the trigger instances "
                    "encoded by each mask true. Unlisted PIs are unconstrained; output "
                    "observability must be established by the GT witness tool."
                ),
                "mask_encoding": (
                    "N-character binary string in instances[] order; leftmost "
                    "character is HT0, next character is HT1, etc."
                ),
                "partial_pi_assignments": _exact_mask_witnesses(instances),
            },
            "expected_activation": {
                "per_instance_probability": math.ldexp(1.0, -trigger_size),
                "any_instance_probability": expected_any_activation,
                "assumption": "independent uniformly distributed primary inputs",
            },
        }
        manifest_path = temp_dir / "case_manifest.json"
        with manifest_path.open("w", encoding="utf-8", newline="\n") as output:
            json.dump(manifest, output, indent=2, sort_keys=True)
            output.write("\n")

        # The case becomes visible under its final name only after every file and
        # hash has been produced successfully.
        os.replace(temp_dir, destination)
    except BaseException:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

    return destination / "case_manifest.json"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate self-contained, reproducible V4 multi-independent-Trojan "
            "BENCH cases. Inputs, counts, trigger sizes, overlaps, and seeds form "
            "a Cartesian product."
        )
    )
    parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        metavar="BENCH_OR_DIR",
        help="one or more .bench files or directories containing .bench files",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("generated_datasets/V4_multiIndependentTrojan"),
        help="new dataset root (default: %(default)s)",
    )
    parser.add_argument(
        "--trojan-count",
        nargs="+",
        type=int,
        default=[2],
        metavar="N",
        help="Trojan instance count(s); supported: 1 2 3 5 (default: 2)",
    )
    parser.add_argument(
        "--trigger-size",
        nargs="+",
        type=int,
        default=[5],
        metavar="K",
        help="literal count(s) per instance (default: 5)",
    )
    parser.add_argument(
        "--seed",
        nargs="+",
        type=int,
        required=True,
        metavar="SEED",
        help="one or more explicit reproducibility seeds",
    )
    parser.add_argument(
        "--trigger-overlap",
        nargs="+",
        type=float,
        default=[0.0],
        metavar="FRACTION",
        help=(
            "requested shared-literal fraction(s) in [0,1); quantized to a whole "
            "literal count and recorded exactly (default: 0)"
        ),
    )
    parser.add_argument(
        "--trigger-source",
        choices=["pi"],
        default="pi",
        help="core trigger source mode; currently only guaranteed-satisfiable PI mode",
    )
    parser.add_argument(
        "--victim-placement",
        choices=["random", "output-near"],
        default="random",
        help="victim selection policy (default: %(default)s)",
    )
    parser.add_argument(
        "--allow-victim-fallback",
        action="store_true",
        help="allow distinct but non-antichain victims if strict placement is infeasible",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="leave an existing case untouched instead of failing",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        inputs = _resolve_inputs(args.input)
        counts = list(dict.fromkeys(args.trojan_count))
        trigger_sizes = list(dict.fromkeys(args.trigger_size))
        seeds = list(dict.fromkeys(args.seed))
        overlaps = list(dict.fromkeys(args.trigger_overlap))
        output_root = args.output_root.expanduser().resolve()

        generated = 0
        skipped = 0
        for source_path in inputs:
            for count in counts:
                for trigger_size in trigger_sizes:
                    for overlap in overlaps:
                        # Cross-instance overlap has no meaning for N=1.  Avoid
                        # producing duplicate single-Trojan experimental cells.
                        if count == 1 and overlap != 0.0:
                            print(
                                f"SKIP {source_path.stem}: N=1 has no cross-instance "
                                f"trigger overlap (requested {overlap})",
                                file=sys.stderr,
                            )
                            skipped += len(seeds)
                            continue
                        for seed in seeds:
                            manifest_path = generate_case(
                                source_path=source_path,
                                output_root=output_root,
                                trojan_count=count,
                                trigger_size=trigger_size,
                                seed=seed,
                                requested_overlap=overlap,
                                victim_placement=args.victim_placement,
                                allow_victim_fallback=args.allow_victim_fallback,
                                skip_existing=args.skip_existing,
                            )
                            if manifest_path is None:
                                print(f"SKIP existing case for {source_path.stem}")
                                skipped += 1
                            else:
                                print(f"GENERATED {manifest_path}")
                                generated += 1
        print(f"Done: generated={generated}, skipped={skipped}, root={output_root}")
        return 0
    except GenerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
