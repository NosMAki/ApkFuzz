#!/usr/bin/env bash
# Run the planned long-run comparison:
#   one 72-hour campaign vs six 12-hour campaigns.
#
# Defaults can be shortened for rehearsal:
#   ONE_SECONDS=60 SPLIT_SECONDS=10 scripts/run-campaign-comparison.sh ...
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MUTATOR="${1:-$PROJECT_ROOT/build/cm-ApkVulFuzz2.so}"
MODE="${2:-manifest-bitflip}"
STAMP="$(date +%Y%m%d-%H%M%S)"
CAMPAIGN_ROOT="${3:-$PROJECT_ROOT/campaign-$STAMP}"

ONE_SECONDS="${ONE_SECONDS:-259200}"      # 72 hours
SPLIT_RUNS="${SPLIT_RUNS:-6}"
SPLIT_SECONDS="${SPLIT_SECONDS:-43200}"   # 12 hours

PYTHON="$PROJECT_ROOT/.venv/bin/python3"
[ -x "$PYTHON" ] || PYTHON="$(command -v python3)"

mkdir -p "$CAMPAIGN_ROOT"

run_campaign() {
  local label="$1"
  local seconds="$2"
  local save_dir="$CAMPAIGN_ROOT/mutants-$label"
  local out_dir="$CAMPAIGN_ROOT/$label"

  if [ -e "$out_dir" ]; then
    echo "error: output already exists: $out_dir" >&2
    exit 1
  fi

  echo
  echo ">> campaign=$label seconds=$seconds mode=$MODE mutator=$MUTATOR"
  mkdir -p "$save_dir"
  APKFUZZ_SAVE_DIR="$save_dir" \
    bash "$SCRIPT_DIR/run-corpus-smoke.sh" "$seconds" "$MUTATOR" "$MODE"

  local latest
  latest="$(find "$PROJECT_ROOT" -maxdepth 1 -type d -name 'afl-corpus-smoke-*' -printf '%T@ %p\n' |
    sort -nr | sed -n '1s/^[^ ]* //p')"
  if [ -z "$latest" ]; then
    echo "error: could not find latest afl-corpus-smoke output" >&2
    exit 1
  fi
  mv "$latest" "$out_dir"
}

run_campaign one-72h "$ONE_SECONDS"

for i in $(seq 1 "$SPLIT_RUNS"); do
  run_campaign "split-12h-$i" "$SPLIT_SECONDS"
done

compare_args=("one-72h=$CAMPAIGN_ROOT/one-72h")
for i in $(seq 1 "$SPLIT_RUNS"); do
  compare_args+=("split-12h-$i=$CAMPAIGN_ROOT/split-12h-$i")
done

"$PYTHON" "$SCRIPT_DIR/compare-mutators.py" "${compare_args[@]}" \
  --csv "$CAMPAIGN_ROOT/afl-summary.csv"

echo
echo "Campaign comparison written to:"
echo "  $CAMPAIGN_ROOT/afl-summary.csv"
echo
echo "Mutants were saved under:"
echo "  $CAMPAIGN_ROOT/mutants-*"
