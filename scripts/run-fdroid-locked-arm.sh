#!/usr/bin/env bash
# Isolated F-Droid AFL++ arm. Usage: MODE DURATION_SECONDS SEED OUTPUT_DIR [--check]
# MODE is random-range, manifest-bitflip, manifest-onebit, manifest-valid-onebit,
# or manifest-axml-onebit.
set -euo pipefail

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ] || { [ "$#" -eq 5 ] && [ "$5" != --check ]; }; then
  echo "usage: $0 {random-range|manifest-bitflip|manifest-onebit|manifest-valid-onebit|manifest-axml-onebit} DURATION_SECONDS SEED OUTPUT_DIR [--check]" >&2
  exit 2
fi
mode="$1"; duration="$2"; seed="$3"; output="$4"
capture_limit="${APKFUZZ_CAPTURE_LIMIT_OVERRIDE:-3}"
[[ "$capture_limit" =~ ^[0-9]+$ ]] && [ "$capture_limit" -ge 1 ] && \
  [ "$capture_limit" -le 12 ] || { echo "error: capture limit must be 1..12" >&2; exit 2; }
case "$mode" in
  random-range|manifest-bitflip|manifest-valid-onebit|manifest-axml-onebit) effective_mode="$mode" ;;
  manifest-onebit)
    effective_mode="manifest-bitflip"
    [ -z "${APKFUZZ_MAX_FLIPS+x}" ] || {
      echo "error: manifest-onebit cannot use APKFUZZ_MAX_FLIPS override" >&2; exit 2; }
    ;;
  *) echo "error: unsupported locked mode: $mode" >&2; exit 2 ;;
esac
[[ "$duration" =~ ^[0-9]+$ ]] && [ "$duration" -gt 0 ] || { echo "error: duration must be a positive integer" >&2; exit 2; }
[[ "$seed" =~ ^[0-9]+$ ]] || { echo "error: seed must be a nonnegative integer" >&2; exit 2; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
apk="$root/Evaluation-SSBSE-2026/apk/F-Droid.apk"
mutator="$root/build/mutators/cm-ApkVulFuzz2-$mode.so"
output="$(realpath -m "$output")"
core_pattern="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || true)"
case "$core_pattern" in \|*) crash_reporter_pipe=1 ;; *) crash_reporter_pipe=0 ;; esac
source_files=(
  "$root/scripts/run-corpus-smoke.sh" "$root/scripts/run-fdroid-locked-arm.sh"
  "$root/scripts/run-fdroid-72h-sequence.sh" "$root/scripts/validate-corpus.py"
  "$root/scripts/reap-scratch.py" "$root/scripts/triage-afl-output.py"
  "$root/scripts/capture-runtime-candidates.py" "$root/scripts/inspect-runtime-candidates.py"
  "$root/scripts/report-run-stages.py"
  "$root/scripts/apply-patch.py" "$root/scripts/llmdroid-analysis-queue.py"
  "$root/scripts/probe-android-runtime.py" "$root/scripts/prepare-manifest-runtime-candidate.py"
  "$root/scripts/run-fdroid-agent-stage.py" "$root/scripts/run-llmdroid-smoke.py"
  "$root/scripts/export-llmdroid-trace.py"
  "$root/scripts/replay-llmdroid-trace.py" "$root/scripts/run-llmdroid-pair.py"
  "$root/scripts/compare-llmdroid-runs.py" "$root/scripts/llmdroid_runtime.py"
  "$root/scripts/llmdroid_elm.py" "$root/src/compile_afl_mutator_variants.sh"
  "$root/afl/apk_pathfile_harness.py" "$root/Evaluation-SSBSE-2026/corpus.csv"
  "$root/requirements-llmdroid.txt"
  "$root/src/custom_mutators/v2/"*.c "$root/src/custom_mutators/v2/"*.h
)
command -v afl-fuzz >/dev/null || { echo "error: afl-fuzz unavailable" >&2; exit 1; }
command -v flock >/dev/null || { echo "error: flock unavailable" >&2; exit 1; }
[ -f "$apk" ] && [ -f "$mutator" ] || { echo "error: APK or locked mutator missing" >&2; exit 1; }
[ ! -e "$output" ] || { echo "error: output already exists: $output" >&2; exit 1; }
exec 9>/tmp/apkvulfuzz-fdroid-arm.lock
flock -n 9 || { echo "error: another F-Droid arm is active" >&2; exit 1; }
if pgrep -x afl-fuzz >/dev/null; then
  echo "error: afl-fuzz already running" >&2; exit 1
fi
shm_kb="$(df -Pk /dev/shm | awk 'NR==2{print $4}')"
disk_kb="$(df -Pk "$(dirname "$output")" | awk 'NR==2{print $4}')"
disk_inodes="$(df -Pi "$(dirname "$output")" | awk 'NR==2{print $4}')"
[ "$shm_kb" -ge 5000000 ] && [ "$disk_kb" -ge 10000000 ] && \
  [ "$disk_inodes" -ge 2000000 ] || {
  echo "error: need at least 5 GB free tmpfs, 10 GB free disk, and 2 million free inodes" >&2; exit 1; }

echo "mode=$mode duration_s=$duration seed=$seed output=$output"
echo "apk_sha256=$(sha256sum "$apk" | cut -d' ' -f1)"
echo "mutator_sha256=$(sha256sum "$mutator" | cut -d' ' -f1)"
if [ "${5:-}" = --check ]; then
  echo "PREFLIGHT PASSED; AFL was not started"
  exit 0
fi

mkdir -p "$(dirname "$output")"
mkdir "$output"  # Atomic no-overwrite claim; keep all artifacts on failure.
mkdir "$output/seed-input" "$output/patches"
printf '%s\n' "$apk" > "$output/seed-input/F-Droid.txt"
{
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_head=$(git -C "$root" rev-parse HEAD)"
  echo "mode=$mode"
  echo "effective_mode=$effective_mode"
  echo "duration_s=$duration"
  echo "afl_seed=$seed"
  echo "apk_path=$apk"
  echo "apk_sha256=$(sha256sum "$apk" | cut -d' ' -f1)"
  echo "mutator_path=$mutator"
  echo "mutator_sha256=$(sha256sum "$mutator" | cut -d' ' -f1)"
  echo "afl_version=$(afl-fuzz -h 2>&1 | sed -n '1p' || true)"
  python_path="$root/.venv/bin/python3"
  [ -x "$python_path" ] || python_path="$(command -v python3)"
  echo "harness_python=$python_path"
  echo "harness_python_version=$("$python_path" --version 2>&1)"
  echo "host_kernel=$(uname -srmo)"
  echo "core_pattern=$core_pattern"
  echo "crash_reporter_pipe=$crash_reporter_pipe"
  echo "missing_crashes_override=1"
  echo "python_afl_signal=SIGUSR1"
  echo "afl_saved_crash_scope=unhandled_python_harness_exceptions"
  echo "max_flips_override=${APKFUZZ_MAX_FLIPS:-unset}"
  echo "gen_cap_override=${APKFUZZ_GEN_CAP:-unset}"
  echo "segment_offset_override=${APKFUZZ_SEGMENT_OFFSET:-unset}"
  echo "segment_size_override=${APKFUZZ_SEGMENT_SIZE:-unset}"
  echo "field_pattern_override=${APKFUZZ_FIELD_PATTERN:-unset}"
  echo "field_target_override=${APKFUZZ_FIELD_TARGET:-unset}"
  echo "no_dedup_override=${APKFUZZ_NO_DEDUP:-unset}"
  echo "capture_limit=$capture_limit"
  echo "capture_sample_seed=$seed"
  echo "initial_tmpfs_free_kb=$shm_kb"
  echo "initial_disk_free_kb=$disk_kb"
  echo "initial_disk_free_inodes=$disk_inodes"
} > "$output/config.txt"
git -C "$root" status --short > "$output/worktree-status.txt"
sha256sum "${source_files[@]}" > "$output/source-sha256.txt"
sha256sum "$apk" "$mutator" > "$output/input-sha256.txt"

run_rc=0
APKFUZZ_INPUT_DIR="$output/seed-input" APKFUZZ_SAVE_DIR="$output/patches" \
  APKFUZZ_CAPTURE_LIMIT="$capture_limit" APKFUZZ_CAPTURE_SAMPLE_SEED="$seed" \
  APKFUZZ_AFL_SEED="$seed" \
  bash "$root/scripts/run-corpus-smoke.sh" "$duration" "$mutator" "$mode" "$output/afl" \
  > "$output/run.log" 2>&1 || run_rc=$?
echo "run_exit_code=$run_rc" > "$output/outcome.txt"
if [ ! -f "$output/afl/apkfuzz_mutator.log" ] || \
   ! grep -Eq "effective_mode=$effective_mode .*locked=1 " "$output/afl/apkfuzz_mutator.log" || \
   ! grep -Fq "src=$apk " "$output/afl/apkfuzz_mutator.log"; then
  echo "error: locked mode and source APK were not both observed" | tee -a "$output/outcome.txt" >&2
  run_rc=1
fi
if [ -f "$output/afl/candidates/manifest.json" ]; then
  python3 -B "$root/scripts/inspect-runtime-candidates.py" \
    --capture-manifest "$output/afl/candidates/manifest.json" \
    --output "$output/candidate-preflight.json" > "$output/preflight.log" 2>&1 || run_rc=1
else
  echo "error: candidate capture manifest missing" | tee -a "$output/outcome.txt" >&2
  run_rc=1
fi
if [ -f "$output/candidate-preflight.json" ]; then
  python3 -B "$root/scripts/report-run-stages.py" --arm-dir "$output" \
    --output "$output/stage-summary.json" > "$output/stage-summary.log" 2>&1 || run_rc=1
fi
sha256sum "${source_files[@]}" > "$output/source-sha256-final.txt"
sha256sum "$apk" "$mutator" > "$output/input-sha256-final.txt"
if ! cmp -s "$output/source-sha256.txt" "$output/source-sha256-final.txt"; then
  echo "source_drift=1" >> "$output/outcome.txt"
  echo "error: run-critical source changed during the arm" >&2
  run_rc=1
else
  echo "source_drift=0" >> "$output/outcome.txt"
fi
if ! cmp -s "$output/input-sha256.txt" "$output/input-sha256-final.txt"; then
  echo "input_drift=1" >> "$output/outcome.txt"
  echo "error: APK or mutator changed during the arm" >&2
  run_rc=1
else
  echo "input_drift=0" >> "$output/outcome.txt"
fi
echo "final_exit_code=$run_rc" >> "$output/outcome.txt"
echo "output=$output exit=$run_rc"
exit "$run_rc"
