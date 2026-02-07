#!/usr/bin/env bash
set -euo pipefail

ROOT="trojaned_bench/V0_singleTrigger_singlePayload"
GT_ROOT="groundtruth/V0_singleTrigger_singlePayload"
BENCH_ROOT="benchmarks"
MAIN="./bin/main"

SAMPLE_N="${1:-5}"
FLAGS=(--no-filter --include-pi --depth 10 --mine-max 0)
OUT_DIR="outputs"
OUT_TSV="${OUT_TSV:-$OUT_DIR/v0_fix_results.tsv}"

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
if [[ ! -f "$OUT_TSV" ]]; then
  printf "circuit\ttrojan_bench\tgroundtruth\tgt_exists\tmain_exit\tpatched_bench\tcec_result\tcec_detail\n" > "$OUT_TSV"
fi

append_row() {
  local circuit="$1"
  local trojan="$2"
  local gt="$3"
  local gt_exists="$4"
  local main_exit="$5"
  local patched="$6"
  local cec_result="$7"
  local cec_detail="$8"

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$circuit" "$trojan" "$gt" "$gt_exists" "$main_exit" "$patched" "$cec_result" "$cec_detail" \
    >> "$OUT_TSV"
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

    if [[ ! -f "$gt" ]]; then
      echo "[skip] missing groundtruth: $gt" >&2
      append_row "$circuit" "$trojan" "$gt" 0 "skip_missing" "" "not_run" "missing_groundtruth"
      continue
    fi

    echo "=== ${circuit}: $(basename "$trojan")"
    set +e
    "$MAIN" "$golden" "$trojan" "$gt" "${FLAGS[@]}"
    main_exit=$?
    set -e
    if [[ $main_exit -ne 0 ]]; then
      echo "[fail] main failed for $trojan" >&2
      append_row "$circuit" "$trojan" "$gt" 1 "$main_exit" "" "not_run" "main_failed"
      continue
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

      if printf "%s" "$cec_out" | grep -qi "NOT EQUIVALENT"; then
        cec_result="not_equiv"
      elif printf "%s" "$cec_out" | grep -qi "equivalent"; then
        cec_result="equivalent"
      else
        cec_result="unknown"
      fi
      append_row "$circuit" "$trojan" "$gt" 1 "$main_exit" "$patched" "$cec_result" "$cec_detail"
    else
      echo "[warn] patched bench missing: $patched" >&2
      append_row "$circuit" "$trojan" "$gt" 1 "$main_exit" "$patched" "patched_missing" "patched bench missing"
    fi
  done
done
