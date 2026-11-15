#!/usr/bin/env bash
# Planned two-arm F-Droid experiment. Nothing starts without explicit --start.
# Usage: run-fdroid-72h-sequence.sh {--check|--start} RUN_ID
set -euo pipefail

if [ "$#" -ne 2 ] || { [ "$1" != --check ] && [ "$1" != --start ]; }; then
  echo "usage: $0 {--check|--start} RUN_ID" >&2
  exit 2
fi
action="$1"
run_id="$2"
[[ "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || {
  echo "error: RUN_ID must contain only letters, digits, underscores or hyphens" >&2
  exit 2
}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Freeze non-mode mutator settings for these two planned arms.
unset APKFUZZ_MAX_FLIPS APKFUZZ_GEN_CAP APKFUZZ_SEGMENT_OFFSET APKFUZZ_SEGMENT_SIZE
unset APKFUZZ_FIELD_PATTERN APKFUZZ_FIELD_TARGET APKFUZZ_NO_DEDUP
export APKFUZZ_CAPTURE_LIMIT_OVERRIDE=12
random_out="$root/results/fdroid-72h-$run_id-random-range"
manifest_out="$root/results/fdroid-72h-$run_id-manifest-bitflip"
runner="$root/scripts/run-fdroid-locked-arm.sh"

# Recheck both arms at launch, before creating either output directory.
bash "$runner" random-range 259200 10407 "$random_out" --check
bash "$runner" manifest-bitflip 259200 10408 "$manifest_out" --check
if [ "$action" = --check ]; then
  echo "READY: both 72-hour arm preflights passed; no AFL run started"
  exit 0
fi

echo "Starting random-range arm: $random_out"
bash "$runner" random-range 259200 10407 "$random_out"
echo "Random-range completed successfully; rechecking manifest-bitflip resources"
bash "$runner" manifest-bitflip 259200 10408 "$manifest_out" --check
echo "Starting manifest-bitflip arm: $manifest_out"
bash "$runner" manifest-bitflip 259200 10408 "$manifest_out"
echo "Both 72-hour arms completed: $run_id"
