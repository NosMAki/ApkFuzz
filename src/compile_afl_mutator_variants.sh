#!/usr/bin/env bash
# Build several locked v2 AFL++ custom-mutator variants.
#
# Each output .so is compiled with a fixed default strategy, so long campaigns can
# compare "one mutator per AFL run" without changing modes halfway through a run.
set -euo pipefail

AFLPP_DIR="${AFLPP_DIR:-$HOME/AFLplusplus}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MUTATOR_DIR="$SCRIPT_DIR/custom_mutators/v2"
BUILD_DIR="$PROJECT_ROOT/build/mutators"
OBJ_ROOT="$PROJECT_ROOT/build/v2-variant-obj"

if [ ! -f "$AFLPP_DIR/include/afl-fuzz.h" ] || [ ! -f "$AFLPP_DIR/src/afl-performance.c" ]; then
  echo "error: AFL++ source not found under AFLPP_DIR=$AFLPP_DIR" >&2
  echo "       set AFLPP_DIR=/path/to/AFLplusplus" >&2
  exit 1
fi

CC="${CC:-clang}"
mkdir -p "$BUILD_DIR" "$OBJ_ROOT"

build_variant() {
  local label="$1"
  local mode="$2"
  local flips="${3:--1}"
  local seg_offset="${4:--1}"
  local seg_size="${5:--1}"
  local obj_dir="$OBJ_ROOT/$label"
  local so="$BUILD_DIR/cm-ApkVulFuzz2-$label.so"

  mkdir -p "$obj_dir"

  local cflags=(
    -fPIC -Wall -O2
    -I"$AFLPP_DIR/include"
    -I"$MUTATOR_DIR"
    -D AFL_CM
    -D APKFUZZ_LOCK_COMPILED_MODE=1
    "-DAPKFUZZ_COMPILED_MODE=\"$mode\""
    "-DAPKFUZZ_COMPILED_MAX_FLIPS=$flips"
    "-DAPKFUZZ_COMPILED_SEGMENT_OFFSET=$seg_offset"
    "-DAPKFUZZ_COMPILED_SEGMENT_SIZE=$seg_size"
  )

  "$CC" -c "${cflags[@]}" "$MUTATOR_DIR/zip2.c"           -o "$obj_dir/zip2.o"
  "$CC" -c "${cflags[@]}" "$MUTATOR_DIR/strategies.c"     -o "$obj_dir/strategies.o"
  "$CC" -c "${cflags[@]}" "$MUTATOR_DIR/cm_ApkVulFuzz2.c" -o "$obj_dir/cm_ApkVulFuzz2.o"
  "$CC" -c -fPIC -Wall -O2 -I"$AFLPP_DIR/include" \
    "$AFLPP_DIR/src/afl-performance.c" -o "$obj_dir/afl-performance.o"

  "$CC" -shared -o "$so" \
    "$obj_dir/afl-performance.o" "$obj_dir/zip2.o" \
    "$obj_dir/strategies.o" "$obj_dir/cm_ApkVulFuzz2.o"

  nm -D "$so" | grep -q 'afl_custom_fuzz' || {
    echo "error: expected afl_custom_* symbols missing in $so" >&2
    exit 1
  }
  printf '>> built %-42s mode=%s flips=%s segment=[%s,%s)\n' \
    "$so" "$mode" "$flips" "$seg_offset" "$seg_size"
}

build_variant manifest-bitflip       manifest-bitflip       16
build_variant manifest-start         manifest-start         16
build_variant manifest-middle        manifest-middle        16
build_variant manifest-end           manifest-end           16
build_variant manifest-segment-0-256 manifest-segment       16 0 256
build_variant manifest-segment-256-512 manifest-segment     16 256 512
build_variant zip-local-header       zip-local-header       8
build_variant zip-central-directory  zip-central-directory  8
build_variant crc-fields             crc-fields             -1
build_variant size-fields            size-fields            -1
build_variant random-range           random-range           16

echo
echo "Built variants under: $BUILD_DIR"
