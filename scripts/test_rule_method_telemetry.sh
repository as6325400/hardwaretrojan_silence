#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

make -C src ../bin/main ../bin/script/test_cli_options -j4 >/dev/null
bin/script/test_cli_options

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

check_method() {
    local expected_method="$1"
    shift
    local stdout_file="$test_tmp/${expected_method}.out"
    local stderr_file="$test_tmp/${expected_method}.err"
    local patched_file="$test_tmp/${expected_method}.bench"

    timeout 120s bin/main "$golden" "$trojan" "$groundtruth" "$patched_file" \
        "$@" >"$stdout_file" 2>"$stderr_file"

    local summary_count
    summary_count=$(grep -c '^rule_synth_summary ' "$stdout_file")
    [[ "$summary_count" -ge 1 ]]
    [[ "$(summary_value strategy "$stdout_file")" == "$expected_method" ]]

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

    if [[ "$expected_method" == "dt" ]]; then
        [[ "$(summary_value vn_generated "$stdout_file")" == "0" ]]
        [[ "$(summary_value vn_used "$stdout_file")" == "0" ]]
    fi
    [[ -s "$patched_file" ]]
    grep -q '\[TIMING\]   abc_cec: .* (PASS)' "$stderr_file"
}

check_method vn-retrain
check_method dt --rule-method dt

echo "rule_method_telemetry_tests PASS"
