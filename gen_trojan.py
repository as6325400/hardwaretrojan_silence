import os
import re
import time
import random
from typing import Dict, List, Tuple, Set, Optional

from circuit import Circuit  # 你原本的 Circuit

# ======================
# User-configurable settings
# ======================
INPUT_BENCH_DIR = "./benchmarks"
OUTPUT_ROOT_DIR = "./trojaned_bench"  # 你想放哪裡都行

NUM_SAMPLES_PER_CIRCUIT = 30

# trigger 規則大小：每個 trigger 用幾條 rare wires (AND 起來)
TRIGGER_SIZE = 5

# Version 1: Single trigger, multi payload
V1_NUM_PAYLOADS = 4  # 一個 trigger 控幾個 victim

# Version 2: Multi trigger, single payload
V2_NUM_TRIGGERS = 3  # 幾個 trigger OR 起來控制同一個 victim

# Version 3: Multi trigger, multi payload
V3_NUM_TRIGGERS = 3
V3_NUM_PAYLOADS = 6  # victims 數量（會 round-robin 分配到 triggers）

# 可選：是否用 ABC CEC 驗證 NOT EQUIVALENT（需要你本機有 ./abc 和 library）
ENABLE_ABC_VERIFY = False
ABC_BIN = "./abc"
ABC_GENLIB = "yc.genlib"
ABC_TIMEOUT_SEC = 30


# ======================
# Helpers
# ======================
def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def parse_bench_nets(path: str) -> Set[str]:
    """
    Roughly collect all net names from a .bench to avoid name collisions.
    """
    nets: Set[str] = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("INPUT(") or line.startswith("OUTPUT("):
                m = re.search(r"\(([^)]+)\)", line)
                if m:
                    nets.add(m.group(1).strip())
                continue
            if "=" in line:
                left, right = line.split("=", 1)
                nets.add(left.strip().replace(" ", ""))
                m = re.search(r"\(([^)]*)\)", right)
                if m:
                    inside = m.group(1).replace(" ", "")
                    for tok in inside.split(","):
                        if tok:
                            nets.add(tok)
    return nets


class NameFactory:
    def __init__(self, existing: Set[str], prefix: str = "__ht_r"):
        self.existing = set(existing)
        self.prefix = prefix
        self.idx = 0

    def new(self) -> str:
        while True:
            name = f"{self.prefix}{self.idx}"
            self.idx += 1
            if name not in self.existing:
                self.existing.add(name)
                return name


def bench_emit_not(dst: str, a: str) -> str:
    return f"{dst} = NOT({a})\n"


def bench_emit_and(dst: str, inputs: List[str]) -> str:
    # .bench 的 AND 可以是可變 fanin（你原本就是這樣寫）
    inside = ",".join(inputs)
    return f"{dst} = AND({inside})\n"


def bench_emit_or(dst: str, inputs: List[str]) -> str:
    inside = ",".join(inputs)
    return f"{dst} = OR({inside})\n"


def bench_emit_xor_toggle(
    nf: NameFactory, victim: str, trigger: str
) -> Tuple[List[str], str]:
    """
    Generate logic equivalent to result = victim XOR trigger, using your style:
      not_t = NOT(trigger)
      not_v = NOT(victim)
      a1 = AND(not_t, victim)
      a2 = AND(trigger, not_v)
      result = OR(a1, a2)
    Returns (lines, result_net)
    """
    lines: List[str] = []
    not_t = nf.new()
    lines.append(bench_emit_not(not_t, trigger))
    not_v = nf.new()
    lines.append(bench_emit_not(not_v, victim))
    a1 = nf.new()
    lines.append(bench_emit_and(a1, [not_t, victim]))
    a2 = nf.new()
    lines.append(bench_emit_and(a2, [trigger, not_v]))
    res = nf.new()
    lines.append(bench_emit_or(res, [a1, a2]))
    return lines, res


def choose_victims(
    circuit: Circuit,
    num_payloads: int,
    min_candidate_needed: int,
    trojan_size_per_trigger: int,
    max_tries: int = 2000,
) -> List[str]:
    """
    Pick multiple victims from circuit.low_ob_node.
    Heuristic: ensure each chosen victim has enough remaining rare candidates.
    """
    num_rare = len(circuit.rare_node_name)
    low_ob = list(circuit.low_ob_node)
    random.shuffle(low_ob)

    victims: List[str] = []
    tries = 0
    for cand_v in low_ob:
        tries += 1
        if tries > max_tries:
            break

        # forbid = union of payload_TFO keys of current victims + this victim
        forbid: Set[str] = set()
        for v in victims:
            forbid |= set(circuit.payload_TFO[v].keys())
        forbid |= set(circuit.payload_TFO[cand_v].keys())

        candidate_count = len(set(circuit.rare_node_name) - forbid)

        # min_candidate_needed 是估算：你後面要抽幾組 trigger、每組抽 trojan_size
        if candidate_count >= min_candidate_needed:
            victims.append(cand_v)
            if len(victims) >= num_payloads:
                return victims

    # fallback：如果沒挑滿，就放寬條件直接抽
    while len(victims) < num_payloads:
        victims.append(random.choice(circuit.low_ob_node))
    return victims


def build_trigger(
    circuit: Circuit,
    nf: NameFactory,
    forbidden: Set[str],
    trojan_size: int,
    used_rare_pool: Optional[Set[str]] = None,
) -> Tuple[List[str], str, List[Tuple[str, int]]]:
    """
    Build a trigger net:
      - sample rare wires from (rare_node_name - forbidden)
      - if a wire is in rare_zero => use NOT(w) as literal (so literal is w==0)
      - else literal is w==1
    Returns:
      (lines, trigger_net, rule_literals)
    rule_literals: list of (wire_name, required_value) where required_value in {0,1}
    """
    candidate = list(set(circuit.rare_node_name) - set(forbidden))
    if used_rare_pool is not None:
        # 讓不同 trigger 盡量不要共用同一條 rare wire（可增加多樣性）
        candidate = [x for x in candidate if x not in used_rare_pool]

    if len(candidate) < trojan_size:
        # 不夠就退回允許重疊
        candidate = list(set(circuit.rare_node_name) - set(forbidden))

    if len(candidate) < trojan_size:
        raise RuntimeError(
            f"Not enough trigger candidates: need {trojan_size}, got {len(candidate)}"
        )

    rare_list = random.sample(candidate, trojan_size)
    if used_rare_pool is not None:
        used_rare_pool |= set(rare_list)

    lines: List[str] = []
    trigger_inputs: List[str] = []
    rule: List[Tuple[str, int]] = []

    for w in rare_list:
        if w in circuit.rare_zero:
            inv = nf.new()
            lines.append(bench_emit_not(inv, w))
            trigger_inputs.append(inv)
            rule.append((w, 0))  # inv=1 => w must be 0
        else:
            trigger_inputs.append(w)
            rule.append((w, 1))

    trig = nf.new()
    lines.append(bench_emit_and(trig, trigger_inputs))
    return lines, trig, rule


def rewrite_bench_with_replacements(
    origin_file: str,
    output_file: str,
    replace_map: Dict[str, str],
    appended_lines: List[str],
) -> None:
    """
    Copy origin bench, replace any gate input net that appears in replace_map.
    Append trojan lines at the end.
    """
    with open(output_file, "w", encoding="utf-8") as out:
        with open(origin_file, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.rstrip("\n")
                stripped = line.replace(" ", "")

                if not stripped or stripped.startswith("#"):
                    out.write(raw)
                    continue

                if stripped.startswith("INPUT") or stripped.startswith("OUTPUT"):
                    out.write(raw)
                    continue

                if "=" not in stripped:
                    out.write(raw)
                    continue

                left, right = stripped.split("=", 1)
                # skip vdd special
                if right == "vdd":
                    out.write(raw)
                    continue

                m = re.match(r"(\w+)\(([^)]*)\)", right)
                if not m:
                    out.write(raw)
                    continue

                gate = m.group(1)
                inputs_str = m.group(2).replace(" ", "")
                inputs = [] if inputs_str == "" else inputs_str.split(",")

                changed = False
                for i, net in enumerate(inputs):
                    if net in replace_map:
                        inputs[i] = replace_map[net]
                        changed = True

                if changed:
                    out.write(f"{left} = {gate}({','.join(inputs)})\n")
                else:
                    out.write(raw)

        # append trojan logic
        out.write("\n# --- inserted trojan logic ---\n")
        for l in appended_lines:
            out.write(l)


def write_rule_txt(
    txt_path: str,
    variant_name: str,
    victims: List[str],
    trigger_rules: List[List[Tuple[str, int]]],
    victim_to_trigger_idx: Dict[str, List[int]],
    note: str = "",
) -> None:
    """
    trigger_rules[k] = list of (wire, required_value)
    victim_to_trigger_idx[victim] = list of trigger indices that activate it (usually 1, sometimes multiple)
    """
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"variant: {variant_name}\n")
        if note:
            f.write(f"note: {note}\n")
        f.write("\n[Victims]\n")
        for v in victims:
            f.write(f"- {v}  (activated by triggers: {victim_to_trigger_idx.get(v, [])})\n")

        f.write("\n[Triggers]\n")
        for k, rule in enumerate(trigger_rules):
            # rule as conjunction
            conds = []
            for w, val in rule:
                conds.append(f"{w}=={val}")
            f.write(f"T{k}: " + " & ".join(conds) + "\n")


def abc_not_equivalent_check(origin_bench: str, trojan_bench: str) -> bool:
    """
    Optional: Use ABC to check NOT EQUIVALENT.
    Requires:
      - ./abc exists
      - yc.genlib exists
    """
    # write verilog temp then cec is easier; but you already used bench->verilog path in your code.
    # We'll do:
    # 1) read origin bench; strash; write_verilog tmp1.v
    # 2) read trojan bench; strash; write_verilog tmp2.v
    # 3) cec -s tmp1.v tmp2.v
    t1 = "__tmp1.v"
    t2 = "__tmp2.v"

    cmd1 = f'{ABC_BIN} -c "read_library {ABC_GENLIB}; read {origin_bench}; strash; write_verilog {t1};"'
    cmd2 = f'{ABC_BIN} -c "read_library {ABC_GENLIB}; read {trojan_bench}; strash; write_verilog {t2};"'
    cmd3 = f'{ABC_BIN} -c "cec -s {t1} {t2}"'

    try:
        p1 = subprocess.run(cmd1, shell=True, text=True, capture_output=True, timeout=ABC_TIMEOUT_SEC)
        p2 = subprocess.run(cmd2, shell=True, text=True, capture_output=True, timeout=ABC_TIMEOUT_SEC)
        p3 = subprocess.run(cmd3, shell=True, text=True, capture_output=True, timeout=ABC_TIMEOUT_SEC)
    except Exception:
        return False

    out = (p3.stdout or "") + (p3.stderr or "")
    return ("NOT EQUIVALENT" in out)


# ======================
# Variant generators (BENCH)
# ======================
def gen_v1_single_trigger_multi_payload(
    origin_file: str,
    out_bench: str,
    out_rule_txt: str,
    circuit: Circuit,
    trojan_size: int,
    num_payloads: int,
) -> None:
    """
    V1: Single trigger, distributed payloads (many victims share same trigger)
    """
    existing = parse_bench_nets(origin_file)
    nf = NameFactory(existing)

    # Pick victims
    # 只需要 1 組 trigger，所以至少要有 trojan_size candidates
    victims = choose_victims(
        circuit,
        num_payloads=num_payloads,
        min_candidate_needed=trojan_size,
        trojan_size_per_trigger=trojan_size,
    )

    # Forbidden wires：避免 trigger wires 落在 victims 的 TFO（你原本的概念）
    forbidden = set()
    for v in victims:
        forbidden |= set(circuit.payload_TFO[v].keys())

    trigger_lines, trig, trig_rule = build_trigger(
        circuit=circuit,
        nf=nf,
        forbidden=forbidden,
        trojan_size=trojan_size,
        used_rare_pool=None,
    )

    appended: List[str] = []
    appended += trigger_lines

    replace_map: Dict[str, str] = {}
    for v in victims:
        payload_lines, res = bench_emit_xor_toggle(nf, v, trig)
        appended += payload_lines
        replace_map[v] = res

    rewrite_bench_with_replacements(origin_file, out_bench, replace_map, appended)

    # rule file
    victim_to_triggers = {v: [0] for v in victims}
    write_rule_txt(
        out_rule_txt,
        variant_name="V1_singleTrigger_multiPayload",
        victims=victims,
        trigger_rules=[trig_rule],
        victim_to_trigger_idx=victim_to_triggers,
        note=f"All victims are XOR-toggled by T0",
    )


def gen_v2_multi_trigger_single_payload(
    origin_file: str,
    out_bench: str,
    out_rule_txt: str,
    circuit: Circuit,
    trojan_size: int,
    num_triggers: int,
) -> None:
    """
    V2: Multiple triggers, single payload
    - Build T0..T(K-1)
    - effective_trigger = OR(T0..T(K-1))
    - one victim toggled by effective_trigger
    """
    existing = parse_bench_nets(origin_file)
    nf = NameFactory(existing)

    # Pick one victim with enough candidate wires
    # 最保守：需要 trojan_size candidates (每個 trigger 都會再挑，但我們允許 triggers 之間可重疊，所以只看一組也可)
    victim = choose_victims(
        circuit,
        num_payloads=1,
        min_candidate_needed=trojan_size,
        trojan_size_per_trigger=trojan_size,
    )[0]
    victims = [victim]

    forbidden = set(circuit.payload_TFO[victim].keys())
    used_pool: Set[str] = set()

    trigger_rules: List[List[Tuple[str, int]]] = []
    trigger_nets: List[str] = []
    appended: List[str] = []

    for _ in range(num_triggers):
        t_lines, t_net, t_rule = build_trigger(
            circuit=circuit,
            nf=nf,
            forbidden=forbidden,
            trojan_size=trojan_size,
            used_rare_pool=used_pool,
        )
        appended += t_lines
        trigger_nets.append(t_net)
        trigger_rules.append(t_rule)

    # OR all triggers into effective trigger
    eff = nf.new()
    appended.append(bench_emit_or(eff, trigger_nets))

    payload_lines, res = bench_emit_xor_toggle(nf, victim, eff)
    appended += payload_lines
    replace_map = {victim: res}

    rewrite_bench_with_replacements(origin_file, out_bench, replace_map, appended)

    victim_to_triggers = {victim: list(range(num_triggers))}
    write_rule_txt(
        out_rule_txt,
        variant_name="V2_multiTrigger_singlePayload",
        victims=victims,
        trigger_rules=trigger_rules,
        victim_to_trigger_idx=victim_to_triggers,
        note="Payload toggles if ANY trigger is satisfied (OR of triggers).",
    )


def gen_v3_multi_trigger_multi_payload(
    origin_file: str,
    out_bench: str,
    out_rule_txt: str,
    circuit: Circuit,
    trojan_size: int,
    num_triggers: int,
    num_payloads: int,
) -> None:
    """
    V3: Multiple triggers, multiple payloads
    - Build T0..T(K-1)
    - Pick M victims
    - Assign victims to triggers round-robin
    - Each victim toggled by its assigned trigger (Vi XOR T(assign(i)))
    """
    existing = parse_bench_nets(origin_file)
    nf = NameFactory(existing)

    victims = choose_victims(
        circuit,
        num_payloads=num_payloads,
        # 我們希望 triggers 盡量不在 victims 的 TFO，且 triggers 有 K 組
        # 粗估需要 trojan_size (一組) 其實就能跑，但這邊給大一點增加挑選品質：
        min_candidate_needed=max(trojan_size, trojan_size),
        trojan_size_per_trigger=trojan_size,
    )

    # Forbidden：可用兩種策略
    # - aggressive: union all victims' TFO => trigger candidates 變小，但更不容易被 payload 影響
    # - mild: 只避開「該 trigger 所對應 victims 的 TFO」 => 成功率高
    # 這裡用 mild：先建 triggers 時先不 union 全部 victims，後面若不夠再 fallback
    used_pool: Set[str] = set()

    trigger_rules: List[List[Tuple[str, int]]] = []
    trigger_nets: List[str] = []
    appended: List[str] = []

    # 先用「全部 victims union TFO」當 forbidden（更安全但可能候選不足）
    forbidden_all = set()
    for v in victims:
        forbidden_all |= set(circuit.payload_TFO[v].keys())

    # build triggers
    for _ in range(num_triggers):
        try:
            t_lines, t_net, t_rule = build_trigger(
                circuit=circuit,
                nf=nf,
                forbidden=forbidden_all,
                trojan_size=trojan_size,
                used_rare_pool=used_pool,
            )
        except RuntimeError:
            # fallback: 不避開全部 victims 的 TFO（提高成功率）
            t_lines, t_net, t_rule = build_trigger(
                circuit=circuit,
                nf=nf,
                forbidden=set(),  # relaxed
                trojan_size=trojan_size,
                used_rare_pool=used_pool,
            )
        appended += t_lines
        trigger_nets.append(t_net)
        trigger_rules.append(t_rule)

    replace_map: Dict[str, str] = {}
    victim_to_triggers: Dict[str, List[int]] = {}

    for i, v in enumerate(victims):
        tidx = i % num_triggers
        victim_to_triggers[v] = [tidx]
        payload_lines, res = bench_emit_xor_toggle(nf, v, trigger_nets[tidx])
        appended += payload_lines
        replace_map[v] = res

    rewrite_bench_with_replacements(origin_file, out_bench, replace_map, appended)

    write_rule_txt(
        out_rule_txt,
        variant_name="V3_multiTrigger_multiPayload",
        victims=victims,
        trigger_rules=trigger_rules,
        victim_to_trigger_idx=victim_to_triggers,
        note="Victims are assigned to triggers round-robin; each victim toggles when its assigned trigger fires.",
    )


# ======================
# Main
# ======================
def list_bench_files(input_dir: str) -> List[str]:
    files = []
    for fn in os.listdir(input_dir):
        if fn.endswith(".bench"):
            files.append(os.path.join(input_dir, fn))
    files.sort()
    return files


def generate_for_one_circuit(origin_file: str) -> None:
    base = os.path.basename(origin_file).replace(".bench", "")
    print(f"\n=== Processing {base} ===")

    # build circuit features once
    circuit = Circuit(origin_file)
    circuit.low_ob_tfo()

    # output folders
    out_v1 = os.path.join(OUTPUT_ROOT_DIR, "V1_singleTrigger_multiPayload", base)
    out_v2 = os.path.join(OUTPUT_ROOT_DIR, "V2_multiTrigger_singlePayload", base)
    out_v3 = os.path.join(OUTPUT_ROOT_DIR, "V3_multiTrigger_multiPayload", base)
    ensure_dir(out_v1)
    ensure_dir(out_v2)
    ensure_dir(out_v3)

    # generate 30 samples each variant
    for idx in range(NUM_SAMPLES_PER_CIRCUIT):
        # -------- V1 --------
        out_bench = os.path.join(out_v1, f"{base}_trojan{idx}.bench")
        out_txt = os.path.join(out_v1, f"{base}_trojan{idx}.txt")
        gen_v1_single_trigger_multi_payload(
            origin_file, out_bench, out_txt, circuit, TRIGGER_SIZE, V1_NUM_PAYLOADS
        )

        # -------- V2 --------
        out_bench = os.path.join(out_v2, f"{base}_trojan{idx}.bench")
        out_txt = os.path.join(out_v2, f"{base}_trojan{idx}.txt")
        gen_v2_multi_trigger_single_payload(
            origin_file, out_bench, out_txt, circuit, TRIGGER_SIZE, V2_NUM_TRIGGERS
        )

        # -------- V3 --------
        out_bench = os.path.join(out_v3, f"{base}_trojan{idx}.bench")
        out_txt = os.path.join(out_v3, f"{base}_trojan{idx}.txt")
        gen_v3_multi_trigger_multi_payload(
            origin_file, out_bench, out_txt, circuit, TRIGGER_SIZE, V3_NUM_TRIGGERS, V3_NUM_PAYLOADS
        )

        if (idx + 1) % 5 == 0:
            print(f"  generated {idx+1}/{NUM_SAMPLES_PER_CIRCUIT} for {base}")

    print(f"Done: {base}")


def main():
    if not os.path.isdir(INPUT_BENCH_DIR):
        raise RuntimeError(f"INPUT_BENCH_DIR not found: {INPUT_BENCH_DIR}")

    ensure_dir(OUTPUT_ROOT_DIR)
    bench_files = list_bench_files(INPUT_BENCH_DIR)

    if not bench_files:
        print(f"No .bench files in: {INPUT_BENCH_DIR}")
        return

    for bf in bench_files:
        generate_for_one_circuit(bf)

    print("\nAll done! Output:", OUTPUT_ROOT_DIR)


if __name__ == "__main__":
    main()
