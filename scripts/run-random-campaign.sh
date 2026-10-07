#!/usr/bin/env bash
# Serial, bounded random-mutator campaign: one AFL instance per original APK.
# Default: two hours per APK. Use --check for preflight without starting AFL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT_ROOT="$ROOT/Evaluation-SSBSE-2026/input"
SO="$ROOT/build/mutators/cm-ApkVulFuzz2-random-range.so"
SECONDS_PER_APK="${SECONDS_PER_APK:-7200}"
BASE_SEED="${BASE_SEED:-22000}"
FLIPS="${FLIPS:-1}"
GEN_CAP="${GEN_CAP:-1}"
OUT_ROOT="${OUT_ROOT:-$ROOT/campaign-random-$(date +%Y%m%d-%H%M%S)}"
CHECK_ONLY=0
if [ "${1:-}" = "--check" ]; then CHECK_ONLY=1
elif [ "$#" -ne 0 ]; then echo "usage: $0 [--check]" >&2; exit 2; fi

for value in "$SECONDS_PER_APK" "$BASE_SEED" "$FLIPS" "$GEN_CAP"; do
  [[ "$value" =~ ^[0-9]+$ ]] || { echo "error: duration, seed, flips and generation cap must be integers" >&2; exit 2; }
done
[ "$SECONDS_PER_APK" -gt 0 ] && [ "$FLIPS" -gt 0 ] && [ "$GEN_CAP" -gt 0 ] || {
  echo "error: duration, flips and generation cap must be positive" >&2; exit 2; }
case "$OUT_ROOT" in /*) : ;; *) OUT_ROOT="$PWD/$OUT_ROOT" ;; esac

command -v afl-fuzz >/dev/null || { echo "error: afl-fuzz is unavailable" >&2; exit 1; }
command -v flock >/dev/null || { echo "error: flock is unavailable" >&2; exit 1; }
exec 9> /tmp/apkvulfuzz-random-campaign.lock
flock -n 9 || { echo "error: another random campaign holds the lock" >&2; exit 1; }
if pgrep -x afl-fuzz >/dev/null 2>&1; then
  echo "error: afl-fuzz is already running; avoid an unplanned parallel run" >&2
  exit 1
fi

# The current 12-20 MB corpus needs room for several seconds of transient APKs.
shm_kb="$(df -Pk /dev/shm | awk 'NR==2{print $4}')"
disk_kb="$(df -Pk "$ROOT" | awk 'NR==2{print $4}')"
[ "$shm_kb" -ge 5000000 ] || { echo "error: less than 5 GB free in /dev/shm" >&2; exit 1; }
[ "$disk_kb" -ge 10000000 ] || { echo "error: less than 10 GB free on output disk" >&2; exit 1; }

echo ">> building and testing the random mutator"
bash "$ROOT/scripts/run-random-mutator-tests.sh"
echo ">> validating clean APK seeds"
python3 "$ROOT/scripts/validate-corpus.py" --write-inputs
shopt -s nullglob
seeds=("$INPUT_ROOT"/*.txt)
[ "${#seeds[@]}" -gt 0 ] || { echo "error: no seeds" >&2; exit 1; }

echo ">> ${#seeds[@]} APKs, ${SECONDS_PER_APK}s each, serial; flips=$FLIPS gen_cap=$GEN_CAP"
echo ">> planned output: $OUT_ROOT"
if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "PREFLIGHT PASSED; no AFL campaign was started"
  exit 0
fi

[ ! -e "$OUT_ROOT" ] || { echo "error: output directory already exists: $OUT_ROOT" >&2; exit 1; }
mkdir -p "$OUT_ROOT"/{inputs,logs,patches,runs,source-snapshot}
{
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_head=$(git -C "$ROOT" rev-parse HEAD)"
  echo "mutator_sha256=$(sha256sum "$SO" | cut -d' ' -f1)"
  echo "seconds_per_apk=$SECONDS_PER_APK"
  echo "base_seed=$BASE_SEED"
  echo "flips=$FLIPS"
  echo "gen_cap=$GEN_CAP"
  echo "apk_count=${#seeds[@]}"
} > "$OUT_ROOT/config.txt"
git -C "$ROOT" status --short > "$OUT_ROOT/worktree-status.txt"
git -C "$ROOT" diff --binary > "$OUT_ROOT/worktree.diff"
cp "$ROOT/src/custom_mutators/v2/"*.c "$ROOT/src/custom_mutators/v2/"*.h \
   "$ROOT/afl/apk_pathfile_harness.py" "$ROOT/scripts/run-corpus-smoke.sh" \
   "$ROOT/scripts/run-random-campaign.sh" "$ROOT/scripts/run-random-mutator-tests.sh" \
   "$ROOT/scripts/validate-corpus.py" "$ROOT/src/compile_afl_mutator_variants.sh" \
   "$ROOT/scripts/reap-scratch.py" "$ROOT/scripts/apply-patch.py" \
   "$ROOT/scripts/triage-afl-output.py" "$OUT_ROOT/source-snapshot/"
printf 'apk\tseed\tduration_s\texecs_done\tcrashes\thangs\tpatches\n' > "$OUT_ROOT/summary.tsv"

statval() { awk -F: -v k="$2" '$1 ~ "^"k" *$"{gsub(/^[ \t]+/,"",$2); print $2; exit}' "$1"; }
idx=0
for seed_file in "${seeds[@]}"; do
  app="$(basename "$seed_file" .txt)"
  apk_path="$(tr -d '\r\n' < "$seed_file")"
  run_seed=$((BASE_SEED + idx))
  idx=$((idx + 1))
  mkdir -p "$OUT_ROOT/inputs/$app" "$OUT_ROOT/patches/$app"
  cp "$seed_file" "$OUT_ROOT/inputs/$app/"
  run_dir="$OUT_ROOT/runs/$app"
  log_file="$OUT_ROOT/logs/$app.log"
  echo ">> running $app for ${SECONDS_PER_APK}s (seed $run_seed); log: $log_file"
  if APKFUZZ_INPUT_DIR="$OUT_ROOT/inputs/$app" \
     APKFUZZ_SAVE_DIR="$OUT_ROOT/patches/$app" \
     APKFUZZ_AFL_SEED="$run_seed" \
     APKFUZZ_MAX_FLIPS="$FLIPS" APKFUZZ_GEN_CAP="$GEN_CAP" \
     bash "$ROOT/scripts/run-corpus-smoke.sh" "$SECONDS_PER_APK" "$SO" random-range "$run_dir" \
     > "$log_file" 2>&1; then :
  else
    echo "error: run failed for $app; last log lines:" >&2
    tail -30 "$log_file" >&2
    exit 1
  fi
  stats="$run_dir/default/fuzzer_stats"
  mutlog="$run_dir/apkfuzz_mutator.log"
  if ! grep -Fq "src=$apk_path " "$mutlog"; then
    echo "error: $app was loaded but never mutated" >&2
    exit 1
  fi
  success="$(grep -Ec 'status=(ok|fallback_to_origin|gen_cap_restart)' "$mutlog" || true)"
  patches="$(find "$OUT_ROOT/patches/$app" -maxdepth 1 -type f -name '*.patch' | wc -l | tr -d ' ')"
  [ "$success" -gt 0 ] && [ "$success" -eq "$patches" ] || {
    echo "error: mutation/patch count mismatch for $app ($success vs $patches)" >&2; exit 1; }
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$app" "$run_seed" "$SECONDS_PER_APK" \
    "$(statval "$stats" execs_done)" "$(statval "$stats" saved_crashes)" \
    "$(statval "$stats" saved_hangs)" "$patches" >> "$OUT_ROOT/summary.tsv"
  tail -14 "$log_file"
done

echo ">> campaign complete: $OUT_ROOT/summary.tsv"
