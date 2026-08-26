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

echo
[ "$rc" -eq 0 ] && echo "ALL TESTS PASSED" || echo "TESTS FAILED"
exit "$rc"
