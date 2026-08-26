#!/usr/bin/env bash
# campaign-lib.sh - shared helpers for the two campaign drivers.
# Sourced, not executed. Provides:
#   capture_machine_state FILE
#   csv_init FILE
#   run_and_record RUN_ID ARM REPEAT MUTATOR MODE SEED SECONDS OUT_ROOT CSV
#
# Every run goes through run-corpus-smoke.sh with an explicit output dir (no
# "find the newest dir" race) and a pinned AFL seed (reproducible + attributable).

CAMPAIGN_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAMPAIGN_ROOT_DIR="$(cd "$CAMPAIGN_LIB_DIR/.." && pwd)"

capture_machine_state() {
  local out="$1"
  {
    echo "captured   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "git_sha    : $(git -C "$CAMPAIGN_ROOT_DIR" rev-parse HEAD 2>/dev/null || echo '?')"
    echo "kernel     : $(uname -sr)"
    echo "afl_fuzz   : $(afl-fuzz --version 2>&1 | head -1)"
    echo "clang      : $(clang --version 2>&1 | head -1)"
    echo "loadavg    : $(cut -d' ' -f1-3 /proc/loadavg)"
    echo "nproc      : $(nproc)"
    local gov; gov="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo '?')"
    echo "cpu_gov    : $gov"
    local temp; temp="$(sensors 2>/dev/null | awk '/Package id 0/{print $4; exit}')"
    echo "cpu_temp   : ${temp:-n/a}"
    echo "mem_free   : $(free -h | awk 'NR==2{print $7}')"
    echo "shm_free   : $(df -h /dev/shm | awk 'NR==2{print $4}')"
  } > "$out"
}

# Short machine-state one-liner for the CSV.
machine_oneliner() {
  local load gov
  load="$(cut -d' ' -f1 /proc/loadavg)"
  gov="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo '?')"
  echo "load=${load};gov=${gov}"
}

csv_init() {
  local csv="$1"
  [ -f "$csv" ] || echo "run_id,arm,repeat,mutator,effective_mode,seed,duration_s,execs_done,execs_per_sec,corpus_count,corpus_found,bitmap_cvg,saved_crashes,saved_hangs,fallback_count,machine_state,git_sha" > "$csv"
}

# Pull one value from a fuzzer_stats file.
_stat() { awk -F: -v k="$2" '$1 ~ "^"k" *$"{gsub(/^[ \t]+/,"",$2); print $2; exit}' "$1"; }

run_and_record() {
  local run_id="$1" arm="$2" repeat="$3" mutator="$4" mode="$5" seed="$6" secs="$7" out_root="$8" csv="$9"
  local out_dir="$out_root/$run_id"
  local save_dir="$out_root/patches/$run_id"

  echo
  echo ">>> run_id=$run_id arm=$arm repeat=$repeat mode=$mode seed=$seed secs=$secs"
  echo ">>> mutator=$(basename "$mutator")"
  mkdir -p "$save_dir"

  APKFUZZ_AFL_SEED="$seed" APKFUZZ_SAVE_DIR="$save_dir" \
    bash "$CAMPAIGN_LIB_DIR/run-corpus-smoke.sh" "$secs" "$mutator" "$mode" "$out_dir" \
    || { echo "!! run $run_id failed" >&2; return 1; }

  local stats="$out_dir/default/fuzzer_stats"
  local log="$out_dir/apkfuzz_mutator.log"
  local eff; eff="$(grep -oE -m1 'effective_mode=[^ ]+' "$log" 2>/dev/null | cut -d= -f2)"
  local fb;  fb="$(grep -c 'status=fallback_to_origin' "$log" 2>/dev/null || true)"; fb="${fb:-0}"
  local sha; sha="$(git -C "$CAMPAIGN_ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$run_id" "$arm" "$repeat" "$(basename "$mutator")" "${eff:-?}" "$seed" "$secs" \
    "$(_stat "$stats" execs_done)" "$(_stat "$stats" execs_per_sec)" \
    "$(_stat "$stats" corpus_count)" "$(_stat "$stats" corpus_found)" \
    "$(_stat "$stats" bitmap_cvg)" "$(_stat "$stats" saved_crashes)" \
    "$(_stat "$stats" saved_hangs)" "$fb" "$(machine_oneliner)" "$sha" >> "$csv"
}
