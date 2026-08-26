#!/usr/bin/env bash
# run-duration-comparison.sh  -  research question 1: does splitting the budget help?
#
#   one LONG run  vs  several SHORT runs  at the same total CPU budget.
#
# METHODOLOGY WARNING
#   1 x 72h vs 6 x 12h with one long run is n=1 vs n=6: there is no variance in
#   the long arm to compare against. Answer it as a UNION-OF-COVERAGE question --
#   "does the union of the short runs' coverage beat the single long run?" -- for
#   which n=1 per arm is fine (the metric is a union, not a mean). If instead you
#   want a mean-with-variance claim, set REPEATS>1 to run several long runs too
#   (e.g. REPEATS=3 -> 3 x 72h vs 18 x 12h) and budget the machine time for it.
#
#   Per-run fuzzer_stats give execs/coverage/crashes. The union-of-coverage
#   number itself is a POST step over the saved queues (not in fuzzer_stats);
#   this script records everything needed for it and leaves the union to analysis.
#
# Rehearsal:
#   LONG_SECONDS=600 SHORT_SECONDS=100 SHORT_RUNS=6 scripts/run-duration-comparison.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/campaign-lib.sh"

MUTATOR="${MUTATOR:-$PROJECT_ROOT/build/cm-ApkVulFuzz2.so}"
MODE="${MODE:-manifest-bitflip}"
LONG_SECONDS="${LONG_SECONDS:-259200}"   # 72h
SHORT_SECONDS="${SHORT_SECONDS:-43200}"  # 12h
SHORT_RUNS="${SHORT_RUNS:-6}"
REPEATS="${REPEATS:-1}"                   # long-arm repeats (1 => union-of-coverage framing)
BASE_SEED="${BASE_SEED:-1000}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_ROOT="${OUT_ROOT:-$PROJECT_ROOT/campaign-duration-$STAMP}"
CSV="$OUT_ROOT/duration-summary.csv"

[ -f "$MUTATOR" ] || { echo "error: mutator not found: $MUTATOR" >&2; exit 1; }
mkdir -p "$OUT_ROOT"
capture_machine_state "$OUT_ROOT/machine-state.txt"
csv_init "$CSV"

if [ "$REPEATS" -eq 1 ]; then
  echo "NOTE: REPEATS=1 -> union-of-coverage framing (no variance in the long arm)."
else
  echo "NOTE: REPEATS=$REPEATS -> $REPEATS x long vs $((REPEATS*SHORT_RUNS)) x short (mean+variance)."
fi
echo "mutator=$(basename "$MUTATOR") mode=$MODE long=${LONG_SECONDS}s short=${SHORT_SECONDS}s x${SHORT_RUNS}"

idx=0
for rep in $(seq 1 "$REPEATS"); do
  # long arm
  run_and_record "long-${rep}" "long" "$rep" "$MUTATOR" "$MODE" "$((BASE_SEED+idx))" "$LONG_SECONDS" "$OUT_ROOT" "$CSV"
  idx=$((idx+1))
  # matching short arm
  for s in $(seq 1 "$SHORT_RUNS"); do
    run_and_record "short-${rep}-${s}" "short" "$rep" "$MUTATOR" "$MODE" "$((BASE_SEED+idx))" "$SHORT_SECONDS" "$OUT_ROOT" "$CSV"
    idx=$((idx+1))
  done
done

echo
echo "== duration comparison done =="
echo "csv           : $CSV"
echo "machine state : $OUT_ROOT/machine-state.txt"
echo "saved patches : $OUT_ROOT/patches/  (reconstruct with scripts/apply-patch.py)"
echo
echo "next: compute union-of-coverage across the short arm's queues vs the long run"
echo "      (post-analysis over $OUT_ROOT/*/default/queue)."
