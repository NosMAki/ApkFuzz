#!/usr/bin/env bash
# run-mutator-comparison.sh  -  research question 2: which strategy is best?
#
# Runs every locked variant .so under build/mutators/ for a fixed duration, with
# REPEATS independent runs each (distinct pinned seeds), and records a normalized
# CSV. Strategy comparison needs REPEATS (variance across seeds), not one long run
# -- that is what run-duration-comparison.sh is for. Keep the two questions apart.
#
# Each variant is a locked .so: it ignores APKFUZZ_MUTATOR_MODE, so the mode we
# pass is only a label; effective_mode in the CSV comes from the mutator itself.
#
# Rehearsal:
#   SECONDS_PER=60 REPEATS=2 scripts/run-mutator-comparison.sh
# Subset:
#   VARIANTS="crc-both-different size-both-different" scripts/run-mutator-comparison.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/campaign-lib.sh"

MUT_DIR="${MUT_DIR:-$PROJECT_ROOT/build/mutators}"
SECONDS_PER="${SECONDS_PER:-7200}"        # 2h per run
REPEATS="${REPEATS:-3}"
BASE_SEED="${BASE_SEED:-2000}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_ROOT="${OUT_ROOT:-$PROJECT_ROOT/campaign-mutator-$STAMP}"
CSV="$OUT_ROOT/mutator-summary.csv"

# Which variants: explicit VARIANTS list (labels) or every .so in MUT_DIR.
declare -a sos=()
if [ -n "${VARIANTS:-}" ]; then
  for v in $VARIANTS; do sos+=("$MUT_DIR/cm-ApkVulFuzz2-$v.so"); done
else
  shopt -s nullglob
  sos=("$MUT_DIR"/cm-ApkVulFuzz2-*.so)
fi
[ "${#sos[@]}" -gt 0 ] || { echo "error: no variants found in $MUT_DIR (build them first)" >&2; exit 1; }

mkdir -p "$OUT_ROOT"
capture_machine_state "$OUT_ROOT/machine-state.txt"
csv_init "$CSV"

total=$(( ${#sos[@]} * REPEATS ))
echo "variants=${#sos[@]} repeats=$REPEATS secs_each=${SECONDS_PER}  => $total runs"
echo "estimated wall time: ~$(awk -v t="$total" -v s="$SECONDS_PER" 'BEGIN{printf "%.1f", t*s/3600}') h (serial)"

idx=0
for so in "${sos[@]}"; do
  [ -f "$so" ] || { echo "!! missing variant: $so (skipping)"; continue; }
  label="$(basename "$so" .so)"; label="${label#cm-ApkVulFuzz2-}"
  for rep in $(seq 1 "$REPEATS"); do
    run_and_record "${label}-r${rep}" "$label" "$rep" "$so" "$label" "$((BASE_SEED+idx))" "$SECONDS_PER" "$OUT_ROOT" "$CSV"
    idx=$((idx+1))
  done
done

echo
echo "== mutator comparison done =="
echo "csv           : $CSV"
echo "machine state : $OUT_ROOT/machine-state.txt"
echo "saved patches : $OUT_ROOT/patches/"
