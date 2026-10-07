#!/usr/bin/env bash
# Build and test only the locked random-range custom mutator.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
V2="$ROOT/src/custom_mutators/v2"
SO="$ROOT/build/mutators/cm-ApkVulFuzz2-random-range.so"
DRIVER="$ROOT/build/tests/mutator_driver"
APK="${APK:-$ROOT/Evaluation-SSBSE-2026/apk/F-Droid.apk}"
PYTHON="${PYTHON:-python3}"
CC="${CC:-clang}"

APKFUZZ_ONLY_VARIANT=random-range bash "$ROOT/src/compile_afl_mutator_variants.sh"
mkdir -p "$(dirname "$DRIVER")"
"$CC" -O1 -Wall -I"$V2" "$ROOT/tests/mutator_driver.c" "$V2/zip2.c" -o "$DRIVER" -ldl

SO="$SO" APK="$APK" DRIVER="$DRIVER" bash "$ROOT/tests/test_reproducibility.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/apkfuzz-random-window.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
APKFUZZ_OUT_DIR="$WORK" "$DRIVER" "$SO" "$APK" 8 5 | \
  "$PYTHON" "$ROOT/tests/check_variant_window.py" random-range
TEST_MODE=random-range APK="$APK" PYTHON="$PYTHON" bash "$ROOT/tests/test_patch_lineage.sh"
"$PYTHON" "$ROOT/tests/test_triage_collection.py"
"$PYTHON" "$ROOT/tests/test_reaper.py"
echo "RANDOM MUTATOR TESTS PASSED"
