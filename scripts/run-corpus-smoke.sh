#!/usr/bin/env bash
# run-corpus-smoke.sh
#
# Short smoke test over the WHOLE corpus with a selectable custom mutator/strategy.
# Per-iteration logging is on, so one run proves multi-APK cycling and
# custom-mutator-only operation, and reports the mutator's *effective* mode
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
set -euo pipefail

DURATION="${1:-20}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

INPUT_DIR="$PROJECT_ROOT/Evaluation-SSBSE-2026/input"
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
RUN_MARKER="$(mktemp)"
REAPER_PID=""

cleanup() {
  [ -n "$REAPER_PID" ] && kill "$REAPER_PID" 2>/dev/null || true
  rm -rf "$SCRATCH_DIR" 2>/dev/null || true
  if [ -d "$APK_DIR" ]; then
    find "$APK_DIR" -maxdepth 1 -regextype posix-extended -type f \
      -name '*.apk' -newer "$RUN_MARKER" \
      -regex '.*/.*_[0-9]+_[0-9]+\.apk' -delete 2>/dev/null || true
  fi
  rm -f "$RUN_MARKER"
}
trap cleanup EXIT

command -v afl-fuzz >/dev/null 2>&1 || { echo "error: afl-fuzz not in PATH" >&2; exit 1; }
[ -f "$MUTATOR" ] || { echo "error: mutator not found: $MUTATOR (build it first)" >&2; exit 1; }
[ -d "$INPUT_DIR" ] || { echo "error: input dir not found: $INPUT_DIR" >&2; exit 1; }

# Validate + (re)generate path-files for the current corpus first.
if [ -f "$SCRIPT_DIR/validate-corpus.py" ]; then
  echo ">> validating corpus and regenerating path-files"
  "$PYTHON" "$SCRIPT_DIR/validate-corpus.py" --write-inputs || {
    echo "error: corpus validation failed; fix the APKs above before smoke testing" >&2; exit 1; }
fi

seed_count=$(find "$INPUT_DIR" -maxdepth 1 -name '*.txt' | wc -l | tr -d ' ')
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

# Physical write accounting (root block device).
root_dev="$(lsblk -no PKNAME "$(findmnt -no SOURCE -T "$OUTPUT_DIR")" 2>/dev/null | head -1)"
[ -n "$root_dev" ] || root_dev="nvme0n1"
sectors_written() { awk -v d="$root_dev" '$3==d{print $10; exit}' /proc/diskstats; }
w0="$(sectors_written || echo 0)"; [ -n "$w0" ] || w0=0

# Reap transient mutants continuously so tmpfs never fills. Short grace: a mutant
# is consumed by the harness synchronously, so anything a couple of seconds old
# and not referenced by the queue is dead.
"$PYTHON" "$SCRIPT_DIR/reap-scratch.py" --scratch "$SCRATCH_DIR" --output "$OUTPUT_DIR" \
  --grace 2 --interval 1 --max-bytes 4e9 >"$OUTPUT_DIR/reaper.log" 2>&1 &
REAPER_PID=$!

cd "$PROJECT_ROOT"
afl_rc=0
afl-fuzz -V "$DURATION" -m none -i "$INPUT_DIR" -o "$OUTPUT_DIR" -- \
  "$PYTHON" "$HARNESS" @@ || afl_rc=$?

w1="$(sectors_written || echo "$w0")"; [ -n "$w1" ] || w1="$w0"
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
  eff="$(grep -oE 'effective_mode=[^ ]+' "$LOG_FILE" | head -1 | cut -d= -f2)"
  comp="$(grep -oE 'compiled_mode=[^ ]+' "$LOG_FILE" | head -1 | cut -d= -f2)"
  lock="$(grep -oE 'locked=[0-9]' "$LOG_FILE" | head -1 | cut -d= -f2)"
  echo "effective_mode=${eff:-?}  compiled_mode=${comp:-?}  locked=${lock:-?}  requested(env)=$MODE"
  echo
  echo "-- multi-APK evidence (distinct src= in mutator log) --"
  grep -oE 'src=[^ ]+' "$LOG_FILE" | sort -u
  echo "distinct seeds mutated: $(grep -oE 'src=[^ ]+' "$LOG_FILE" | sort -u | wc -l | tr -d ' ')"
  echo
  echo "-- status breakdown --"
  grep -oE 'status=[a-z_]+' "$LOG_FILE" | sort | uniq -c
else
  echo "(no mutator log; APKFUZZ_LOG may not have been honored)"
fi

echo
echo "-- physical disk I/O during the run --"
echo "bytes written to /dev/$root_dev: ${phys_mb} MB over ${DURATION}s"
echo "output dir: $OUTPUT_DIR"

if [ "$afl_rc" -ne 0 ]; then
  echo "ERROR: afl-fuzz exited non-zero (exit=$afl_rc). Smoke test FAILED." >&2
  exit "$afl_rc"
fi
