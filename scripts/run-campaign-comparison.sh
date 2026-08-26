#!/usr/bin/env bash
# DEPRECATED. This script mixed two different research questions into one run and
# defaulted to the UNLOCKED mutator (so it never actually used the locked
# variants). It has been split:
#
#   scripts/run-duration-comparison.sh   one long run vs many short runs
#   scripts/run-mutator-comparison.sh    which strategy is best (loops variants)
#
# See README_FUZZING.md and docs/NEXT_MEETING_STATUS.md.
set -euo pipefail
echo "run-campaign-comparison.sh is deprecated; use:" >&2
echo "  scripts/run-duration-comparison.sh   (long vs split budget)" >&2
echo "  scripts/run-mutator-comparison.sh    (strategy comparison)" >&2
exit 2
