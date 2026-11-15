#!/usr/bin/env bash
# Build the test driver and run the mutator test suite:
#   1. reproducibility  (same seed -> same sequence; collision bug gone)
#   2. variant sanity   (each locked .so only touches its declared structure)
# Fast (< a few seconds) and exits non-zero on any failure, so it can gate a
# build before a long campaign.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
V2_DIR="$PROJECT_ROOT/src/custom_mutators/v2"
TEST_DIR="$PROJECT_ROOT/tests"
BUILD_DIR="$PROJECT_ROOT/build/tests"
DRIVER="$BUILD_DIR/mutator_driver"
CC="${CC:-clang}"
PYTHON="${PYTHON:-python3}"

mkdir -p "$BUILD_DIR"
echo ">> building test driver"
"$CC" -O1 -Wall -I"$V2_DIR" \
  "$TEST_DIR/mutator_driver.c" "$V2_DIR/zip2.c" \
  -o "$DRIVER" -ldl

export DRIVER
rc=0
echo; echo ">> reproducibility"
bash "$TEST_DIR/test_reproducibility.sh" || rc=1
echo; echo ">> variant sanity"
bash "$TEST_DIR/test_variant_sanity.sh" || rc=1
echo; echo ">> patch lineage"
bash "$TEST_DIR/test_patch_lineage.sh" || rc=1
echo; echo ">> scratch reaper"
"$PYTHON" -B "$TEST_DIR/test_reaper.py" || rc=1
echo; echo ">> candidate capture and preflight"
"$PYTHON" -B "$TEST_DIR/test_candidate_capture.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_live_mutation_sample.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_manifest_valid_onebit.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_axml_structure.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_apk_pathfile_harness.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_fdroid_agent_stage.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_runtime_candidate_preflight.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_run_stage_report.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_android_runtime_probe.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_manifest_runtime_prepare.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_llmdroid_trace_export.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_llmdroid_runtime.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_llmdroid_pair_timeout.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_llmdroid_replay.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_llmdroid_comparison.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_llmdroid_queue.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_llmdroid_elm.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_llmdroid_smoke.py" || rc=1
"$PYTHON" -B "$TEST_DIR/test_apk_tool_classification.py" || rc=1

echo
[ "$rc" -eq 0 ] && echo "ALL TESTS PASSED" || echo "TESTS FAILED"
exit "$rc"
