#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

make -C src ../bin/main -j4 >/dev/null

test_tmp=$(mktemp -d /tmp/literal-patch-cut-cex.XXXXXX)
trap 'rm -rf "$test_tmp"' EXIT

run_case() {
    local case_name=$1
    local golden=$2
    local trojan=$3
    local groundtruth=$4
    shift 4

    timeout 120s bin/main "$golden" "$trojan" "$groundtruth" \
        "$test_tmp/${case_name}.bench" "$@" \
        >"$test_tmp/${case_name}.out" \
        2>"$test_tmp/${case_name}.err"
}

# Empty protected-negative input retains the ordinary direct-cut behavior.
run_case control \
    benchmarks/c5315.bench \
    trojaned_bench/V0_singleTrigger_singlePayload/c5315/c5315_trojan28.bench \
    groundtruth/V0_singleTrigger_singlePayload/c5315/c5315_trojan28_error_patterns.json \
    --rule-method z3-pb
grep -q '^literal_patch_cut_selected ' "$test_tmp/control.out"
! grep -q 'failed: protected non-trigger ' "$test_tmp/control.err"
grep -q '\[TIMING\]   abc_cec: .* (PASS)' "$test_tmp/control.err"

# c7552_trojan82 used to select the same bad unconditional cut in all five
# CEC rounds.  Its first ABC false-positive becomes protected negative 13
# (zero-based mismatch index 12); the next attempt must reject that cut and
# eventually select a different literal whose patch passes CEC.
run_case c7552_trojan82 \
    benchmarks/c7552.bench \
    trojaned_bench/V0_singleTrigger_singlePayload/c7552/c7552_trojan82.bench \
    groundtruth/V0_singleTrigger_singlePayload/c7552/c7552_trojan82_error_patterns.json \
    --depth 10 --neg-ratio 50 --mine-rounds 15 --mine-max 5000 \
    --rule-method z3-pb --rule-formal-refine \
    --rule-formal-timeout-ms 10000 --rule-formal-max-rounds 5 \
    --rule-formal-cex-batch 5

grep -q '^cec_new_negative total_extra_neg 13 type false_positive duplicate 0$' \
    "$test_tmp/c7552_trojan82.out"
grep -q 'failed: protected non-trigger groundtruth mismatch pattern 12$' \
    "$test_tmp/c7552_trojan82.err"

first_literal=$(awk '
    /^rule_apply_summary / && / source literal_patch_cut / {
        for (i = 2; i < NF; i += 2) {
            if ($i == "literal_node") { print $(i + 1); exit }
        }
    }
' "$test_tmp/c7552_trojan82.out")
last_literal=$(awk '
    /^rule_apply_summary / && / source literal_patch_cut / {
        for (i = 2; i < NF; i += 2) {
            if ($i == "literal_node") value = $(i + 1)
        }
    }
    END { print value }
' "$test_tmp/c7552_trojan82.out")
[[ -n "$first_literal" && -n "$last_literal" ]]
[[ "$first_literal" != "$last_literal" ]]
grep -q '^cec_rounds 1$' "$test_tmp/c7552_trojan82.out"
grep -q '\[TIMING\]   abc_cec: .* (PASS)' "$test_tmp/c7552_trojan82.err"

echo "literal_patch_cut_cex_tests PASS"
