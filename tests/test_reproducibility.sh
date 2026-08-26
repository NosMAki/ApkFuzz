#!/usr/bin/env bash
# Prove the mutator is reproducible from AFL's seed and free of the seed-collision
# bug: same seed -> identical mutation sequence; different seed -> different; and
# both hold even with ASLR disabled (setarch -R), which used to force a collision.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DRIVER="${DRIVER:-$PROJECT_ROOT/build/tests/mutator_driver}"
SO="${SO:-$PROJECT_ROOT/build/cm-ApkVulFuzz2.so}"
APK="${APK:-$PROJECT_ROOT/Evaluation-SSBSE-2026/apk/F-Droid.apk}"
WORK="$(mktemp -d "${TMPDIR:-/dev/shm}/apkfuzz-repro.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
export APKFUZZ_OUT_DIR="$WORK/out"
mkdir -p "$APKFUZZ_OUT_DIR"

[ -x "$DRIVER" ] || { echo "FAIL: driver not built at $DRIVER" >&2; exit 1; }
[ -f "$SO" ]     || { echo "FAIL: mutator not built at $SO" >&2; exit 1; }
[ -f "$APK" ]    || { echo "SKIP: no test APK at $APK (corpus not populated)"; exit 0; }

run() { "$DRIVER" "$SO" "$APK" 6 "$1" | grep '^R'; }

a="$(run 12345)"; b="$(run 12345)"; c="$(run 999)"

fail=0
if [ "$a" = "$b" ]; then echo "PASS  same seed -> identical sequence"
else echo "FAIL  same seed produced different sequences"; fail=1; fi
if [ "$a" != "$c" ]; then echo "PASS  different seed -> different sequence"
else echo "FAIL  different seeds produced the same sequence"; fail=1; fi

if command -v setarch >/dev/null 2>&1; then
  d="$(setarch -R "$DRIVER" "$SO" "$APK" 4 111 | grep '^R')"
  e="$(setarch -R "$DRIVER" "$SO" "$APK" 4 222 | grep '^R')"
  if [ "$d" != "$e" ]; then echo "PASS  ASLR off: different seeds still differ (collision bug gone)"
  else echo "FAIL  ASLR off: different seeds collided"; fail=1; fi
else
  echo "SKIP  setarch not available; cannot test the ASLR-off collision path"
fi

[ "$fail" -eq 0 ] && echo "== reproducibility OK ==" || { echo "== reproducibility FAILED =="; exit 1; }
