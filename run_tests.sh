#!/usr/bin/env bash
set -uo pipefail

BASE="."
BIN="$BASE/bin/main"
BENCH="$BASE/benchmarks"
TROJAN="$BASE/trojaned_bench/V0_singleTrigger_singlePayload"
GT="$BASE/groundtruth/V0_singleTrigger_singlePayload"
OUTPUT_DIR="/tmp/silence_v0_patched"
CSV="$BASE/results_v6_signature_min.csv"
PER_TEST_TIMEOUT=300  # 5 minutes per test

mkdir -p "$OUTPUT_DIR"

# CSV header
echo "circuit,trojan,success,gt_verify,vn_rounds,runtime_ms,area_delta,level_delta,cec_rounds" > "$CSV"

pass=0
fail=0
err=0
total=0

for gt_file in "$GT"/*/*_error_patterns.json; do
    circuit=$(basename "$(dirname "$gt_file")")
    trojan_name=$(basename "$gt_file" _error_patterns.json)

    golden="$BENCH/${circuit}.bench"
    trojan_bench="$TROJAN/${circuit}/${trojan_name}.bench"
    output_bench="$OUTPUT_DIR/${trojan_name}_patched.bench"

    total=$((total + 1))

    if [[ ! -f "$golden" ]]; then
        echo "SKIP $trojan_name: golden not found"
        echo "$circuit,$trojan_name,SKIP_NO_GOLDEN,,,,," >> "$CSV"
        continue
    fi
    if [[ ! -f "$trojan_bench" ]]; then
        echo "SKIP $trojan_name: trojan bench not found"
        echo "$circuit,$trojan_name,SKIP_NO_TROJAN,,,,," >> "$CSV"
        continue
    fi
    # Skip if groundtruth has no trigger patterns
    if grep -q '"pattern_count": 0' "$gt_file" 2>/dev/null; then
        echo "SKIP $trojan_name: no trigger patterns in groundtruth"
        echo "$circuit,$trojan_name,SKIP_NO_PATTERNS,,,,," >> "$CSV"
        continue
    fi

    echo -n "[$total] $trojan_name ... "

    # Remove stale output from previous runs
    rm -f "$output_bench"

    tmp_out=$(mktemp)
    tmp_err=$(mktemp)

    set +e
    timeout "$PER_TEST_TIMEOUT" "$BIN" "$golden" "$trojan_bench" "$gt_file" "$output_bench" \
        > "$tmp_out" 2> "$tmp_err"
    rc=$?
    set -e

    # --- success: determined by ABC CEC ---
    success="FAIL"
    if [[ $rc -eq 124 ]]; then
        success="TIMEOUT"
        err=$((err + 1))
    elif [[ $rc -eq 137 ]]; then
        success="OOM_KILLED"
        err=$((err + 1))
    elif [[ $rc -ne 0 ]]; then
        success="ERROR_$rc"
        err=$((err + 1))
    elif [[ -f "$output_bench" ]]; then
        # Run ABC CEC: golden vs patched
        cec_out=$("$BASE/abc" -c "cec $golden $output_bench" 2>&1 || true)
        if echo "$cec_out" | grep -q 'Networks are equivalent'; then
            success="PASS"
            pass=$((pass + 1))
        else
            success="CEC_FAIL"
            fail=$((fail + 1))
        fi
    else
        fail=$((fail + 1))
    fi

    # --- gt_verify: did internal groundtruth simulation pass? ---
    gt_verify="FAIL"
    if grep -q 'final_verify:.*PASS' "$tmp_err" 2>/dev/null || \
       grep -q 'kill_verify:.*PASS' "$tmp_err" 2>/dev/null || \
       grep -q 'vn_expand_kill+verify+write' "$tmp_err" 2>/dev/null; then
        gt_verify="PASS"
    fi

    # --- vn_rounds: count distinct vn_iter{N}_rules lines ---
    vn_rounds=$(grep -cE '^vn_iter[0-9]+_rules ' "$tmp_out" 2>/dev/null || true)
    vn_rounds=${vn_rounds:-0}

    # --- runtime (ms) ---
    runtime=$(grep '\[TIMING\] TOTAL:' "$tmp_err" 2>/dev/null | \
              sed -n 's/.*TOTAL: \([0-9.]*\) ms/\1/p' | head -1 || true)
    runtime=${runtime:-""}

    # --- area_delta / level_delta ---
    fix_line=$(grep '^payload_fix_selected ' "$tmp_out" 2>/dev/null | tail -1 || true)
    area_delta=$(echo "$fix_line" | sed -n 's/.*area_delta \(-\?[0-9]*\).*/\1/p')
    level_delta=$(echo "$fix_line" | sed -n 's/.*level_delta \(-\?[0-9]*\).*/\1/p')
    area_delta=${area_delta:-""}
    level_delta=${level_delta:-""}

    # --- cec_rounds ---
    cec_rounds=$(grep '^cec_rounds ' "$tmp_out" 2>/dev/null | awk '{print $2}' | head -1 || true)
    cec_rounds=${cec_rounds:-""}

    # --- append to CSV ---
    echo "$circuit,$trojan_name,$success,$gt_verify,$vn_rounds,$runtime,$area_delta,$level_delta,$cec_rounds" >> "$CSV"

    echo "$success  gt=$gt_verify  vn=$vn_rounds  cec=$cec_rounds  time=${runtime}ms  area=$area_delta  level=$level_delta"

    rm -f "$tmp_out" "$tmp_err"
done

echo ""
echo "========================================"
echo "Done: $total tests"
echo "  PASS:  $pass"
echo "  FAIL:  $fail"
echo "  ERROR: $err"
echo "CSV: $CSV"
echo "========================================"
