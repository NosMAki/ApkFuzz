#!/usr/bin/env bash
# Reconstruct a second-generation mutant after its transient parent APK is gone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${APK:-$ROOT/Evaluation-SSBSE-2026/apk/F-Droid.apk}"
PYTHON="${PYTHON:-python3}"
[ -f "$APK" ] || { echo "SKIP  patch lineage: test APK missing"; exit 0; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/apkfuzz-patch-lineage.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
MUTATOR="$WORK/mutator"
"${CC:-clang}" -Wall -O2 -D APKFUZZ_STANDALONE \
  "$ROOT/src/custom_mutators/v2/zip2.c" \
  "$ROOT/src/custom_mutators/v2/strategies.c" \
  "$ROOT/src/custom_mutators/v2/cm_ApkVulFuzz2.c" -o "$MUTATOR"
export APKFUZZ_OUT_DIR="$WORK/mutants"
export APKFUZZ_SAVE_DIR="$WORK/patches"
export APKFUZZ_MUTATOR_MODE="${TEST_MODE:-manifest-bitflip}"
mkdir -p "$APKFUZZ_OUT_DIR" "$APKFUZZ_SAVE_DIR"

parent="$("$MUTATOR" "$APK" 123 2>"$WORK/parent.log")"
child="$("$MUTATOR" "$parent" 456 2>"$WORK/child.log")"
patch="$APKFUZZ_SAVE_DIR/$(basename "$child").patch"
rg -q '^gen 2$' "$patch"
rg -q '^parent ' "$patch"
rm -f "$parent" "$parent.meta"
"$PYTHON" "$ROOT/scripts/apply-patch.py" "$patch" -o "$WORK/reconstructed.apk" >"$WORK/reconstruction.log"
cmp "$child" "$WORK/reconstructed.apk"
echo "PASS  $APKFUZZ_MUTATOR_MODE second-generation patch reconstructs exact APK without transient parent"

# A malformed descendant must restart from the pristine APK and save a
# first-generation patch with no parent reference.
printf 'broken apk' > "$WORK/broken.apk"
printf 'origin %s\ngen 1\n' "$APK" > "$WORK/broken.apk.meta"
fallback="$("$MUTATOR" "$WORK/broken.apk" 789 2>"$WORK/fallback.log")"
fallback_patch="$APKFUZZ_SAVE_DIR/$(basename "$fallback").patch"
rg -q '^gen 1$' "$fallback_patch"
rg -q '^status fallback_to_origin$' "$fallback_patch"
if rg -q '^parent ' "$fallback_patch"; then
  echo "FAIL  fallback patch incorrectly references a parent" >&2
  exit 1
fi
"$PYTHON" "$ROOT/scripts/apply-patch.py" "$fallback_patch" -o "$WORK/reconstructed-fallback.apk" >"$WORK/fallback-reconstruction.log"
cmp "$fallback" "$WORK/reconstructed-fallback.apk"
echo "PASS  $APKFUZZ_MUTATOR_MODE fallback patch reconstructs exact APK from origin"

# A failed patch save must not hand AFL an input that cannot be reconstructed.
printf 'not a directory' > "$WORK/unwritable-save-target"
if APKFUZZ_SAVE_DIR="$WORK/unwritable-save-target" \
   "$MUTATOR" "$APK" 987 >"$WORK/write-failure.out" 2>"$WORK/write-failure.err"; then
  echo "FAIL  mutator accepted an input without its required patch" >&2
  exit 1
fi
if [ -e "$APKFUZZ_OUT_DIR/$(basename "$APK" .apk)_987_1.apk" ]; then
  echo "FAIL  failed patch save left a mutant APK behind" >&2
  exit 1
fi
echo "PASS  $APKFUZZ_MUTATOR_MODE failed patch save rejects the input"
