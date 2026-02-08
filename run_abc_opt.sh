#!/usr/bin/env bash
set -euo pipefail

CSV_IN="${1:-outputs/v0_fix_results.csv}"
CSV_OUT="${2:-outputs/abc_opt_results.csv}"
SHOW="./bin/script/show"

if [[ ! -f "$CSV_IN" ]]; then
  echo "[error] missing input CSV: $CSV_IN" >&2
  exit 1
fi
if ! command -v abc >/dev/null 2>&1; then
  echo "[error] abc not found in PATH" >&2
  exit 1
fi

printf "circuit,trojan_bench,patched_bench,trojan_area,trojan_delay,trojan_opt_area,trojan_opt_delay,patched_area,patched_delay,patched_opt_area,patched_opt_delay\n" > "$CSV_OUT"

csv_escape() {
  local s="$1"
  s="${s//\"/\"\"}"
  printf "\"%s\"" "$s"
}

# Get area/delay from bin/script/show (bench gate count)
get_area_delay() {
  local bench="$1"
  local area="" delay=""
  if [[ -x "$SHOW" ]] && [[ -f "$bench" ]]; then
    local out
    if out="$("$SHOW" "$bench" 2>/dev/null)"; then
      area="$(printf "%s" "$out" | awk '/area/ {print $2}')"
      delay="$(printf "%s" "$out" | awk '/delay/ {print $4}')"
    fi
  fi
  printf "%s %s" "$area" "$delay"
}

# Run ABC strash+fraig and parse print_stats output for "and" (area) and "lev" (delay)
abc_opt_stats() {
  local input="$1"
  local area="" delay=""
  local out
  if out="$(abc -q "read_bench $input; strash; fraig; print_stats" 2>&1)"; then
    # print_stats format: "name : i/o = X/Y  lat = Z  and = A  lev = L"
    area="$(printf "%s" "$out" | grep -oP 'and =\s*\K[0-9]+')" || true
    delay="$(printf "%s" "$out" | grep -oP 'lev =\s*\K[0-9]+')" || true
  fi
  printf "%s %s" "$area" "$delay"
}

# Also get baseline AIG stats (strash only, no fraig) for reference
abc_base_stats() {
  local input="$1"
  local area="" delay=""
  local out
  if out="$(abc -q "read_bench $input; strash; print_stats" 2>&1)"; then
    area="$(printf "%s" "$out" | grep -oP 'and =\s*\K[0-9]+')" || true
    delay="$(printf "%s" "$out" | grep -oP 'lev =\s*\K[0-9]+')" || true
  fi
  printf "%s %s" "$area" "$delay"
}

tail -n +2 "$CSV_IN" | while IFS= read -r line; do
  # Parse CSV fields (handle quoted fields)
  circuit="$(printf "%s" "$line" | awk -F',' '{gsub(/^"|"$/,"",$1); print $1}')"
  trojan="$(printf "%s" "$line" | awk -F',' '{gsub(/^"|"$/,"",$2); print $2}')"
  patched="$(printf "%s" "$line" | awk -F',' '{gsub(/^"|"$/,"",$7); print $7}')"

  # Skip rows without valid patched bench
  if [[ -z "$patched" ]] || [[ ! -f "$patched" ]]; then
    continue
  fi
  if [[ ! -f "$trojan" ]]; then
    continue
  fi

  base="$(basename "$trojan" .bench)"

  echo "=== $circuit: $(basename "$trojan")"

  # Get original bench stats
  read -r t_area t_delay <<< "$(get_area_delay "$trojan")"
  read -r p_area p_delay <<< "$(get_area_delay "$patched")"

  # Get AIG stats after strash+fraig
  echo "  optimizing trojan..."
  read -r t_opt_area t_opt_delay <<< "$(abc_opt_stats "$trojan")"
  echo "  optimizing patched..."
  read -r p_opt_area p_opt_delay <<< "$(abc_opt_stats "$patched")"

  echo "  trojan:  area $t_area -> $t_opt_area  delay $t_delay -> $t_opt_delay"
  echo "  patched: area $p_area -> $p_opt_area  delay $p_delay -> $p_opt_delay"

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$(csv_escape "$circuit")" \
    "$(csv_escape "$trojan")" \
    "$(csv_escape "$patched")" \
    "$(csv_escape "${t_area:-}")" \
    "$(csv_escape "${t_delay:-}")" \
    "$(csv_escape "${t_opt_area:-}")" \
    "$(csv_escape "${t_opt_delay:-}")" \
    "$(csv_escape "${p_area:-}")" \
    "$(csv_escape "${p_delay:-}")" \
    "$(csv_escape "${p_opt_area:-}")" \
    "$(csv_escape "${p_opt_delay:-}")" \
    >> "$CSV_OUT"

done

echo ""
echo "Results written to $CSV_OUT"
