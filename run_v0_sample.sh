#!/usr/bin/env bash
set -euo pipefail

ROOT="trojaned_bench/V0_singleTrigger_singlePayload"
GT_ROOT="groundtruth/V0_singleTrigger_singlePayload"
BENCH_ROOT="benchmarks"
MAIN="./bin/main"

SAMPLE_N="${1:-5}"
FLAGS=(--no-filter --include-pi --depth 10 --mine-max 0)
OUT_DIR="outputs"
LOG_DIR="$OUT_DIR/logs"
OUT_CSV="${OUT_CSV:-${OUT_TSV:-$OUT_DIR/v0_fix_results.csv}}"

if [[ ! -d "$ROOT" ]]; then
  echo "[error] missing dir: $ROOT" >&2
  exit 1
fi

if [[ ! -x "$MAIN" ]]; then
  echo "[error] missing executable: $MAIN" >&2
  exit 1
fi

if ! command -v abc >/dev/null 2>&1; then
  echo "[error] abc not found in PATH" >&2
  exit 1
fi

if ! command -v shuf >/dev/null 2>&1; then
  echo "[warn] shuf not found; using first $SAMPLE_N files per circuit" >&2
  SHUF_AVAILABLE=0
else
  SHUF_AVAILABLE=1
fi

mkdir -p "$OUT_DIR"
mkdir -p "$LOG_DIR"
if [[ ! -f "$OUT_CSV" ]]; then
  printf "circuit,trojan_bench,groundtruth,gt_exists,main_exit,run_time_sec,patched_bench,cec_result,cec_detail,orig_area,orig_delay,patched_area,patched_delay\n" > "$OUT_CSV"
fi

csv_escape() {
  local s="$1"
  s="${s//\"/\"\"}"
  printf "\"%s\"" "$s"
}

append_row() {
  local circuit="$1"
  local trojan="$2"
  local gt="$3"
  local gt_exists="$4"
  local main_exit="$5"
  local run_time="$6"
  local patched="$7"
  local cec_result="$8"
  local cec_detail="$9"
  local orig_area="${10}"
  local orig_delay="${11}"
  local patched_area="${12}"
  local patched_delay="${13}"

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$(csv_escape "$circuit")" \
    "$(csv_escape "$trojan")" \
    "$(csv_escape "$gt")" \
    "$(csv_escape "$gt_exists")" \
    "$(csv_escape "$main_exit")" \
    "$(csv_escape "$run_time")" \
    "$(csv_escape "$patched")" \
    "$(csv_escape "$cec_result")" \
    "$(csv_escape "$cec_detail")" \
    "$(csv_escape "$orig_area")" \
    "$(csv_escape "$orig_delay")" \
    "$(csv_escape "$patched_area")" \
    "$(csv_escape "$patched_delay")" \
    >> "$OUT_CSV"
}

sanitize_detail() {
  printf "%s" "$1" | tr '\t\n' '  ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

for dir in "$ROOT"/c*; do
  [[ -d "$dir" ]] || continue
  circuit="$(basename "$dir")"
  golden="$BENCH_ROOT/$circuit.bench"

  if [[ ! -f "$golden" ]]; then
    echo "[skip] missing golden bench: $golden" >&2
    continue
  fi

  mapfile -t trojan_files < <(
    find "$dir" -maxdepth 1 -type f -name "${circuit}_trojan*.bench" ! -name "*_patched.bench" | sort
  )

  if [[ ${#trojan_files[@]} -eq 0 ]]; then
    echo "[skip] no trojan benches in $dir" >&2
    continue
  fi

  if [[ ${#trojan_files[@]} -gt "$SAMPLE_N" ]]; then
    if [[ "$SHUF_AVAILABLE" -eq 1 ]]; then
      mapfile -t selected < <(printf '%s\n' "${trojan_files[@]}" | shuf -n "$SAMPLE_N")
    else
      mapfile -t selected < <(printf '%s\n' "${trojan_files[@]}" | head -n "$SAMPLE_N")
    fi
  else
    selected=("${trojan_files[@]}")
  fi

  for trojan in "${selected[@]}"; do
    base="$(basename "$trojan" .bench)"
    gt="$GT_ROOT/$circuit/${base}_error_patterns.json"
    patched="${trojan%.bench}_patched.bench"
    log_path="$LOG_DIR/${base}_patch.log"

    if [[ ! -f "$gt" ]]; then
      echo "[skip] missing groundtruth: $gt" >&2
      append_row "$circuit" "$trojan" "$gt" 0 "skip_missing" "" "" "not_run" "missing_groundtruth" "" "" "" ""
      continue
    fi

    echo "=== ${circuit}: $(basename "$trojan")"
    start_time="$(date +%s)"
    set +e
    "$MAIN" "$golden" "$trojan" "$gt" "${FLAGS[@]}" | tee "$log_path"
    main_exit=$?
    set -e
    end_time="$(date +%s)"
    run_time=$((end_time - start_time))
    if [[ $main_exit -ne 0 ]]; then
      echo "[fail] main failed for $trojan" >&2
      append_row "$circuit" "$trojan" "$gt" 1 "$main_exit" "$run_time" "" "not_run" "main_failed" "" "" "" ""
      continue
    fi

    orig_area=""
    orig_delay=""
    if [[ -x "$OUT_DIR/../bin/script/show" ]]; then
      if show_out="$("$OUT_DIR/../bin/script/show" "$trojan" 2>/dev/null)"; then
        orig_area="$(printf "%s" "$show_out" | awk '/area/ {print $2}')"
        orig_delay="$(printf "%s" "$show_out" | awk '/delay/ {print $4}')"
      fi
    fi

    if [[ -f "$patched" ]]; then
      echo "CEC: $patched"
      set +e
      cec_out="$(abc -q "read_bench $golden; cec $patched" 2>&1)"
      cec_status=$?
      set -e

      cec_detail="$(sanitize_detail "$cec_out")"
      if [[ $cec_status -ne 0 ]]; then
        echo "[warn] abc failed for $patched" >&2
        append_row "$circuit" "$trojan" "$gt" 1 "$main_exit" "$patched" "abc_fail" "$cec_detail"
        continue
      fi

      patched_area=""
      patched_delay=""
      if [[ -x "$OUT_DIR/../bin/script/show" ]]; then
        if show_out="$("$OUT_DIR/../bin/script/show" "$patched" 2>/dev/null)"; then
          patched_area="$(printf "%s" "$show_out" | awk '/area/ {print $2}')"
          patched_delay="$(printf "%s" "$show_out" | awk '/delay/ {print $4}')"
        fi
      fi

      if printf "%s" "$cec_out" | grep -qi "NOT EQUIVALENT"; then
        cec_result="not_equiv"
      elif printf "%s" "$cec_out" | grep -qi "equivalent"; then
        cec_result="equivalent"
      else
        cec_result="unknown"
      fi
      append_row "$circuit" "$trojan" "$gt" 1 "$main_exit" "$run_time" "$patched" "$cec_result" "$cec_detail" "$orig_area" "$orig_delay" "$patched_area" "$patched_delay"
    else
      echo "[warn] patched bench missing: $patched" >&2
      append_row "$circuit" "$trojan" "$gt" 1 "$main_exit" "$run_time" "$patched" "patched_missing" "patched bench missing" "$orig_area" "$orig_delay" "" ""
    fi
  done
done
