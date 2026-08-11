#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

highs_root=${HIGHS_ROOT:-"$HOME/.local/or-tools"}
make -C src HIGHS_ROOT="$highs_root" \
    ../bin/main ../bin/script/test_cli_options \
    ../bin/script/test_set_cover_optimizer -j4 >/dev/null
bin/script/test_cli_options
bin/script/test_set_cover_optimizer

test_tmp=$(mktemp -d /tmp/rule-method-selftest.XXXXXX)
trap 'rm -rf "$test_tmp"' EXIT

golden="benchmarks/c2670.bench"
trojan="trojaned_bench/V0_singleTrigger_singlePayload/c2670/c2670_trojan0.bench"
groundtruth="groundtruth/V0_singleTrigger_singlePayload/c2670/c2670_trojan0_error_patterns.json"

summary_value() {
    local key="$1"
    local file="$2"
    awk -v key="$key" '
        /^rule_synth_summary / {
            for (i = 2; i < NF; i += 2) {
                if ($i == key) value = $(i + 1)
            }
        }
        END { if (value != "") print value }
    ' "$file"
}

miter_value() {
    local key="$1"
    local file="$2"
    awk -v key="$key" '
        /^rule_miter_summary / {
            for (i = 2; i < NF; i += 2) {
                if ($i == key) value = $(i + 1)
            }
        }
        END { if (value != "") print value }
    ' "$file"
}

check_method() {
    local case_name="$1"
    local expected_method="$2"
    shift 2
    local stdout_file="$test_tmp/${case_name}.out"
    local stderr_file="$test_tmp/${case_name}.err"
    local patched_file="$test_tmp/${case_name}.bench"

    timeout 120s bin/main "$golden" "$trojan" "$groundtruth" "$patched_file" \
        "$@" >"$stdout_file" 2>"$stderr_file"

    local summary_count
    summary_count=$(grep -c '^rule_synth_summary ' "$stdout_file")
    [[ "$summary_count" -ge 1 ]]
    local apply_count
    apply_count=$(grep -c '^rule_apply_summary ' "$stdout_file")
    [[ "$apply_count" -eq "$summary_count" ]]
    [[ "$(summary_value strategy "$stdout_file")" == "$expected_method" ]]
    awk '
        /^rule_apply_summary / {
            rules = 0
            literals = 0
            for (i = 2; i < NF; i += 2) {
                if ($i == "effective_rules") rules = $(i + 1)
                if ($i == "effective_literals") literals = $(i + 1)
            }
            if (rules < 1 || literals < 1) exit 1
            seen += 1
        }
        END { if (seen < 1) exit 1 }
    ' "$stdout_file"

    local logged_builds
    local summary_builds
    logged_builds=$(grep -c '^decision_tree_rules ' "$stdout_file")
    summary_builds=$(awk '
        /^rule_synth_summary / {
            for (i = 2; i < NF; i += 2) {
                if ($i == "dt_builds") total += $(i + 1)
            }
        }
        END { print total + 0 }
    ' "$stdout_file")
    [[ "$logged_builds" -eq "$summary_builds" ]]
    awk '
        /^rule_synth_summary / || /^rule_apply_summary / {
            type = ($1 == "rule_synth_summary") ? "synth" : "apply"
            id = ""
            for (i = 2; i < NF; i += 2) {
                if ($i == "rule_build_attempt") id = $(i + 1)
            }
            if (id == "") exit 1
            if (type == "synth") synth[id] += 1
            else apply[id] += 1
        }
        END {
            for (id in synth) {
                if (synth[id] != 1 || apply[id] != 1) exit 1
            }
            for (id in apply) {
                if (synth[id] != 1 || apply[id] != 1) exit 1
            }
        }
    ' "$stdout_file"

    if [[ "$expected_method" == "dt" ]]; then
        [[ "$(summary_value vn_generated "$stdout_file")" == "0" ]]
        [[ "$(summary_value vn_used "$stdout_file")" == "0" ]]
    fi
    [[ -s "$patched_file" ]]
    grep -q '\[TIMING\]   abc_cec: .* (PASS)' "$stderr_file"
}

check_method vn-retrain vn-retrain
check_method dt dt --rule-method dt

check_method z3-pb z3-pb --rule-method z3-pb
[[ "$(summary_value optimizer_status "$test_tmp/z3-pb.out")" == "accepted" ]]
[[ "$(summary_value optimizer_accepted "$test_tmp/z3-pb.out")" -ge 1 ]]
[[ "$(summary_value optimizer_optimal "$test_tmp/z3-pb.out")" == "1" ]]
[[ "$(summary_value optimizer_verified "$test_tmp/z3-pb.out")" == "1" ]]

check_method z3-pb-timeout z3-pb --rule-method z3-pb --rule-opt-timeout-ms 0
[[ "$(summary_value strategy "$test_tmp/z3-pb-timeout.out")" == "z3-pb" ]]
[[ "$(summary_value optimizer_status "$test_tmp/z3-pb-timeout.out")" == "timeout" ]]
[[ "$(summary_value optimizer_accepted "$test_tmp/z3-pb-timeout.out")" == "0" ]]

check_method z3-pb-formal z3-pb --rule-method z3-pb \
    --rule-formal-refine --rule-formal-timeout-ms 10000
[[ "$(grep -c '^rule_miter_summary ' "$test_tmp/z3-pb-formal.out")" -ge 1 ]]
[[ "$(miter_value status "$test_tmp/z3-pb-formal.out")" == "proved" ]]
[[ "$(miter_value proved "$test_tmp/z3-pb-formal.out")" == "1" ]]

check_method z3-pb-formal-timeout z3-pb --rule-method z3-pb \
    --rule-formal-refine --rule-formal-timeout-ms 0
[[ "$(miter_value status "$test_tmp/z3-pb-formal-timeout.out")" == "timeout" ]]
[[ "$(miter_value proved "$test_tmp/z3-pb-formal-timeout.out")" == "0" ]]
[[ "$(miter_value retry "$test_tmp/z3-pb-formal-timeout.out")" == "0" ]]

check_method milp-cover milp-cover --rule-method milp-cover
[[ "$(summary_value optimizer_status "$test_tmp/milp-cover.out")" == "accepted" ]]
[[ "$(summary_value optimizer_accepted "$test_tmp/milp-cover.out")" -ge 1 ]]
[[ "$(summary_value optimizer_backend "$test_tmp/milp-cover.out")" == \
    "highs-set-cover-milp" ]]
[[ "$(summary_value cover_pool_complete "$test_tmp/milp-cover.out")" == "1" ]]
[[ "$(summary_value cover_rules_optimal "$test_tmp/milp-cover.out")" == "1" ]]
[[ "$(summary_value cover_literals_optimal "$test_tmp/milp-cover.out")" == "1" ]]
[[ "$(summary_value cover_hardware_optimal "$test_tmp/milp-cover.out")" == "1" ]]
[[ "$(summary_value cover_logic_risk_optimal "$test_tmp/milp-cover.out")" == "1" ]]
[[ "$(summary_value cover_third_objective "$test_tmp/milp-cover.out")" == \
    "unique_inverters" ]]
[[ "$(summary_value cover_fourth_objective "$test_tmp/milp-cover.out")" == \
    "logic_risk_proxy" ]]
[[ "$(summary_value cover_logic_risk_context "$test_tmp/milp-cover.out")" == "1" ]]
[[ "$(summary_value mip1_status "$test_tmp/milp-cover.out")" == "Optimal" ]]
[[ "$(summary_value mip2_status "$test_tmp/milp-cover.out")" == "Optimal" ]]
[[ "$(summary_value lp3_status "$test_tmp/milp-cover.out")" == "Optimal" ]]
[[ "$(summary_value mip3_status "$test_tmp/milp-cover.out")" == "Optimal" ]]
[[ "$(summary_value lp4_status "$test_tmp/milp-cover.out")" == "Optimal" ]]
[[ "$(summary_value mip4_status "$test_tmp/milp-cover.out")" == "Optimal" ]]
[[ "$(summary_value cover_inverters_after "$test_tmp/milp-cover.out")" -le \
    "$(summary_value cover_inverters_before "$test_tmp/milp-cover.out")" ]]

check_method milp-cover-formal milp-cover --rule-method milp-cover \
    --rule-formal-refine --rule-formal-timeout-ms 10000
[[ "$(grep -c '^rule_miter_summary ' "$test_tmp/milp-cover-formal.out")" -ge 1 ]]
[[ "$(miter_value status "$test_tmp/milp-cover-formal.out")" == "proved" ]]
[[ "$(miter_value proved "$test_tmp/milp-cover-formal.out")" == "1" ]]

check_method milp-cover-phase4-timeout milp-cover --rule-method milp-cover \
    --rule-cover-phase4-timeout-ms 0
[[ "$(summary_value optimizer_status "$test_tmp/milp-cover-phase4-timeout.out")" == \
    "accepted_phase4_timeout" ]]
[[ "$(summary_value optimizer_accepted "$test_tmp/milp-cover-phase4-timeout.out")" == "1" ]]
[[ "$(summary_value optimizer_optimal "$test_tmp/milp-cover-phase4-timeout.out")" == "0" ]]
[[ "$(summary_value cover_hardware_optimal "$test_tmp/milp-cover-phase4-timeout.out")" == "1" ]]
[[ "$(summary_value cover_logic_risk_optimal "$test_tmp/milp-cover-phase4-timeout.out")" == "0" ]]
[[ "$(summary_value cover_phase4_timeout_fallback "$test_tmp/milp-cover-phase4-timeout.out")" == "1" ]]

check_method milp-cover-timeout milp-cover --rule-method milp-cover \
    --rule-opt-timeout-ms 0
[[ "$(summary_value optimizer_status "$test_tmp/milp-cover-timeout.out")" == "timeout" ]]
[[ "$(summary_value optimizer_accepted "$test_tmp/milp-cover-timeout.out")" == "0" ]]

echo "rule_method_telemetry_tests PASS"
