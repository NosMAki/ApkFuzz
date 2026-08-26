#!/usr/bin/env bash
# Sanity-check every locked variant .so: assert it only edits the ZIP structure
# its name promises. A mis-compiled variant (wrong region, wrong field, wrong
# target) would otherwise silently burn a whole campaign run. The expected window
# is computed independently from the ZIP layout (via the driver's own zip2), not
# from the mutator's log, so a lying mutator cannot pass itself.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DRIVER="${DRIVER:-$PROJECT_ROOT/build/tests/mutator_driver}"
MUT_DIR="${MUT_DIR:-$PROJECT_ROOT/build/mutators}"
APK="${APK:-$PROJECT_ROOT/Evaluation-SSBSE-2026/apk/F-Droid.apk}"
PYTHON="$PROJECT_ROOT/.venv/bin/python3"; [ -x "$PYTHON" ] || PYTHON="$(command -v python3)"
WORK="$(mktemp -d "${TMPDIR:-/dev/shm}/apkfuzz-sanity.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
export APKFUZZ_OUT_DIR="$WORK/out"; mkdir -p "$APKFUZZ_OUT_DIR"

[ -x "$DRIVER" ] || { echo "FAIL: driver not built at $DRIVER" >&2; exit 1; }
[ -f "$APK" ]    || { echo "SKIP: no test APK at $APK (corpus not populated)"; exit 0; }
shopt -s nullglob
sos=("$MUT_DIR"/cm-ApkVulFuzz2-*.so)
[ "${#sos[@]}" -gt 0 ] || { echo "FAIL: no variants in $MUT_DIR (build them first)" >&2; exit 1; }

fail=0
for so in "${sos[@]}"; do
  label="$(basename "$so" .so)"; label="${label#cm-ApkVulFuzz2-}"
  out="$("$DRIVER" "$so" "$APK" 8 5)"
  if ! "$PYTHON" "$SCRIPT_DIR/check_variant_window.py" "$label" <<<"$out"; then
    fail=1
  fi
done

[ "$fail" -eq 0 ] && echo "== variant sanity OK (${#sos[@]} variants) ==" \
                   || { echo "== variant sanity FAILED =="; exit 1; }
