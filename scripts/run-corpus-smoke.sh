#!/usr/bin/env bash
# run-corpus-smoke.sh
#
# Bounded AFL run with a selectable custom mutator/strategy and input directory.
# Per-iteration logging reports the mutator's *effective* mode
# (which a locked variant .so decides, not the environment).
#
# Transient mutants are written to tmpfs and reaped continuously, so a long run
# costs almost no physical disk I/O. Real bytes written are measured from
# /proc/diskstats and printed in the summary.
#
# Usage:
#   scripts/run-corpus-smoke.sh [DURATION_SECONDS] [MUTATOR_SO] [MODE] [OUTPUT_DIR]
# Env:
#   APKFUZZ_SAVE_DIR=dir   keep a tiny patch per mutant for post-run analysis
#   APKFUZZ_INPUT_DIR=dir  use a prepared subset of path-file seeds
set -euo pipefail

DURATION="${1:-20}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DEFAULT_INPUT_DIR="$PROJECT_ROOT/Evaluation-SSBSE-2026/input"
INPUT_DIR="${APKFUZZ_INPUT_DIR:-$DEFAULT_INPUT_DIR}"
APK_DIR="$PROJECT_ROOT/Evaluation-SSBSE-2026/apk"
HARNESS="$PROJECT_ROOT/afl/apk_pathfile_harness.py"
PYTHON="$PROJECT_ROOT/.venv/bin/python3"
[ -x "$PYTHON" ] || PYTHON="$(command -v python3)"

DEFAULT_MUT="$PROJECT_ROOT/build/cm-ApkVulFuzz2.so"
[ -f "$DEFAULT_MUT" ] || DEFAULT_MUT="$PROJECT_ROOT/build/cm-ApkVulFuzz.so"
MUTATOR="${2:-$DEFAULT_MUT}"
MODE="${3:-manifest-bitflip}"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUTPUT_DIR="${4:-$PROJECT_ROOT/afl-corpus-smoke-$STAMP}"
LOG_FILE="$OUTPUT_DIR/apkfuzz_mutator.log"

# Transient mutants live on tmpfs (RAM), never the SSD. A reaper prunes them.
SCRATCH_BASE="/dev/shm"; [ -w "$SCRATCH_BASE" ] || SCRATCH_BASE="$OUTPUT_DIR"
SCRATCH_DIR="$SCRATCH_BASE/apkfuzz-scratch-$$"
REAPER_PID=""
WATCHDOG_PID=""
AFL_PID=""

cleanup() {
  [ -n "$WATCHDOG_PID" ] && kill "$WATCHDOG_PID" 2>/dev/null || true
  [ -n "$AFL_PID" ] && kill "$AFL_PID" 2>/dev/null || true
  if [ -n "$REAPER_PID" ]; then
    kill "$REAPER_PID" 2>/dev/null || true
    wait "$REAPER_PID" 2>/dev/null || true
  fi
  rm -rf "$SCRATCH_DIR" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

command -v afl-fuzz >/dev/null 2>&1 || { echo "error: afl-fuzz not in PATH" >&2; exit 1; }
[ -f "$MUTATOR" ] || { echo "error: mutator not found: $MUTATOR (build it first)" >&2; exit 1; }
[ -d "$INPUT_DIR" ] || { echo "error: input dir not found: $INPUT_DIR" >&2; exit 1; }

# Validate + (re)generate path-files for the current corpus first.
if [ "$INPUT_DIR" = "$DEFAULT_INPUT_DIR" ] && [ -f "$SCRIPT_DIR/validate-corpus.py" ]; then
  echo ">> validating corpus and regenerating path-files"
  "$PYTHON" "$SCRIPT_DIR/validate-corpus.py" --write-inputs || {
    echo "error: corpus validation failed; fix the APKs above before smoke testing" >&2; exit 1; }
fi

seed_count=$(find "$INPUT_DIR" -maxdepth 1 -name '*.txt' | wc -l | tr -d ' ')
[ "$seed_count" -gt 0 ] || { echo "error: no path-file seeds in $INPUT_DIR" >&2; exit 1; }
echo ">> seeds (path-files): $seed_count"
echo ">> mutator: $MUTATOR"
echo ">> requested mode (env): $MODE   (a locked .so overrides this; see summary)"
echo ">> duration: ${DURATION}s   scratch(tmpfs): $SCRATCH_DIR"

mkdir -p "$OUTPUT_DIR" "$SCRATCH_DIR"

export AFL_NO_UI=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_SKIP_BIN_CHECK=1
export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY="$MUTATOR"
export APKFUZZ_MUTATOR_MODE="$MODE"
export APKFUZZ_LOG=1
export APKFUZZ_LOG_FILE="$LOG_FILE"
export APKFUZZ_OUT_DIR="$SCRATCH_DIR"

# Normalize a relative SAVE dir against the caller's cwd before we cd away.
if [ -n "${APKFUZZ_SAVE_DIR:-}" ]; then
  case "$APKFUZZ_SAVE_DIR" in
    /*) : ;;
    *)  APKFUZZ_SAVE_DIR="$PWD/$APKFUZZ_SAVE_DIR" ;;
  esac
  mkdir -p "$APKFUZZ_SAVE_DIR"
  export APKFUZZ_SAVE_DIR
  echo ">> saving mutant patches to: $APKFUZZ_SAVE_DIR"
fi

# Physical write accounting. Best-effort and MUST NEVER abort the run: this is
# only a reported number. findmnt can append a [/subvol] suffix (btrfs subvolume
# or bind mount) that lsblk rejects, so strip it, and guard every step so a
# failure under set -e/pipefail can't kill the script before AFL even starts.
resolve_root_dev() {
  local src pk
  src="$(findmnt -nro SOURCE -T "$OUTPUT_DIR" 2>/dev/null | sed 's/\[.*//')" || true
  [ -n "$src" ] || { printf ''; return 0; }
  pk="$(lsblk -no PKNAME "$src" 2>/dev/null | awk 'NF{print; exit}')" || true
  [ -n "$pk" ] || pk="$(basename "$src" 2>/dev/null)" || true
  printf '%s' "$pk"
}
root_dev="$(resolve_root_dev)"
sectors_written() { [ -n "$root_dev" ] && awk -v d="$root_dev" '$3==d{print $10; exit}' /proc/diskstats; }
w0="$(sectors_written || true)"; [ -n "$w0" ] || w0=0

# Reap transient mutants continuously so tmpfs never fills. Short grace: a mutant
# is consumed by the harness synchronously, so anything a couple of seconds old
# and not referenced by the queue is dead.
"$PYTHON" "$SCRIPT_DIR/reap-scratch.py" --scratch "$SCRATCH_DIR" --output "$OUTPUT_DIR" \
  --grace 2 --interval 1 --max-bytes 4e9 >"$OUTPUT_DIR/reaper.log" 2>&1 &
REAPER_PID=$!

cd "$PROJECT_ROOT"
# A pinned seed makes the run reproducible (the mutator's RNG is derived from it).
# Set APKFUZZ_AFL_SEED for campaigns so every run is attributable and repeatable.
seed_args=()
if [ -n "${APKFUZZ_AFL_SEED:-}" ]; then
  seed_args=(-s "$APKFUZZ_AFL_SEED")
  echo ">> afl seed: $APKFUZZ_AFL_SEED"
fi
watchdog_error="$OUTPUT_DIR/watchdog-error.txt"
afl-fuzz -V "$DURATION" -m none "${seed_args[@]}" -i "$INPUT_DIR" -o "$OUTPUT_DIR" -- \
  "$PYTHON" "$HARNESS" @@ &
AFL_PID=$!
watchdog() {
  while kill -0 "$AFL_PID" 2>/dev/null; do
    if ! kill -0 "$REAPER_PID" 2>/dev/null; then
      echo "scratch reaper stopped unexpectedly" > "$watchdog_error"
      break
    fi
    if [ -f "$LOG_FILE" ] && tail -n 200 "$LOG_FILE" | grep -Eq 'status=(write_failed|load_failed)'; then
      echo "mutator reported a write/load failure" > "$watchdog_error"
      break
    fi
    free_shm_kb="$(df -Pk /dev/shm 2>/dev/null | awk 'NR==2{print $4}' || true)"
    if ! [[ "$free_shm_kb" =~ ^[0-9]+$ ]] || [ "$free_shm_kb" -lt 1000000 ]; then
      echo "less than 1 GB free in /dev/shm" > "$watchdog_error"
      break
    fi
    free_disk_kb="$(df -Pk "$OUTPUT_DIR" 2>/dev/null | awk 'NR==2{print $4}' || true)"
    if ! [[ "$free_disk_kb" =~ ^[0-9]+$ ]] || [ "$free_disk_kb" -lt 2000000 ]; then
      echo "less than 2 GB free on the output disk" > "$watchdog_error"
      break
    fi
    sleep 5
  done
  if [ -s "$watchdog_error" ]; then kill -TERM "$AFL_PID" 2>/dev/null || true; fi
}
watchdog &
WATCHDOG_PID=$!
afl_rc=0
wait "$AFL_PID" || afl_rc=$?
AFL_PID=""
kill "$WATCHDOG_PID" 2>/dev/null || true
wait "$WATCHDOG_PID" 2>/dev/null || true
WATCHDOG_PID=""
if [ -s "$watchdog_error" ]; then
  echo "ERROR: $(cat "$watchdog_error")" >&2
  afl_rc=1
fi

w1="$(sectors_written || true)"; [ -n "$w1" ] || w1="$w0"
phys_mb=$(awk -v a="$w0" -v b="$w1" 'BEGIN{printf "%.1f", (b-a)*512/1e6}')

echo
echo "================ smoke summary ================"
STATS="$OUTPUT_DIR/default/fuzzer_stats"
if [ ! -f "$STATS" ]; then
  echo "ERROR: afl-fuzz produced no fuzzer_stats (exit=$afl_rc)." >&2
  echo "       Setup failed (bad mutator, invalid seeds, or harness crash)." >&2
  exit 1
fi
grep -E 'execs_done|execs_per_sec|corpus_count|saved_crashes|saved_hangs|cycles_done' "$STATS"

echo
echo "-- effective mode (from the mutator, authoritative) --"
if [ -f "$LOG_FILE" ]; then
  eff="$(grep -oE -m1 'effective_mode=[^ ]+' "$LOG_FILE" | cut -d= -f2 || true)"
  comp="$(grep -oE -m1 'compiled_mode=[^ ]+' "$LOG_FILE" | cut -d= -f2 || true)"
  lock="$(grep -oE -m1 'locked=[0-9]' "$LOG_FILE" | cut -d= -f2 || true)"
  echo "effective_mode=${eff:-?}  compiled_mode=${comp:-?}  locked=${lock:-?}  requested(env)=$MODE"
  echo
  echo "-- original APKs actually mutated (descendants excluded) --"
  originals="$(grep -oE 'src=[^ ]+' "$LOG_FILE" | cut -d= -f2- | awk -v d="$APK_DIR/" 'index($0,d)==1' | sort -u || true)"
  if [ -n "$originals" ]; then printf '%s\n' "$originals"; else echo "(none observed)"; fi
  echo
  echo "-- status breakdown --"
  grep -oE 'status=[a-z_]+' "$LOG_FILE" | sort | uniq -c
else
  echo "(no mutator log; APKFUZZ_LOG may not have been honored)"
fi

echo
echo "-- physical disk I/O during the run --"
if [ -n "$root_dev" ]; then
  echo "system-wide bytes written to /dev/$root_dev: ${phys_mb} MB over ${DURATION}s"
else
  echo "device unknown (could not resolve from mount); skipping byte count"
fi
echo "output dir: $OUTPUT_DIR"

# AFL stores path-files for findings. Preserve their APK bytes while scratch is
# still available, or rebuild from patches when the reaper has removed them.
triage_rc=0
triage_args=("$OUTPUT_DIR" --collect "$OUTPUT_DIR/findings" --queue-index "$OUTPUT_DIR/queue-index.tsv")
if [ -n "${APKFUZZ_SAVE_DIR:-}" ]; then triage_args+=(--patch-dir "$APKFUZZ_SAVE_DIR"); fi
"$PYTHON" "$SCRIPT_DIR/triage-afl-output.py" "${triage_args[@]}" \
  > "$OUTPUT_DIR/triage.txt" 2>&1 || triage_rc=$?
if [ "$triage_rc" -eq 4 ] || [ "$triage_rc" -eq 1 ] || [ "$triage_rc" -eq 2 ]; then
  echo "ERROR: crash/hang collection failed; see $OUTPUT_DIR/triage.txt" >&2
  exit 1
fi
if [ "$triage_rc" -eq 3 ]; then
  echo "crash/hang input(s) collected: $OUTPUT_DIR/findings"
fi

if [ -f "$LOG_FILE" ] && grep -Eq 'status=(write_failed|load_failed)' "$LOG_FILE"; then
  echo "ERROR: mutator reported write/load failures; see $LOG_FILE" >&2
  exit 1
fi

if [ "$afl_rc" -ne 0 ]; then
  echo "ERROR: afl-fuzz exited non-zero (exit=$afl_rc). Smoke test FAILED." >&2
  exit "$afl_rc"
fi
