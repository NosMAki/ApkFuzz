#!/usr/bin/env bash
# Prompt locally and store the ELM API key outside tracked source files.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="$ROOT/results/llmdroid-credentials"
KEY_FILE="$KEY_DIR/elm.key"
umask 077
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
read -r -s -p 'ELM API key (input hidden): ' APKVULFUZZ_KEY
printf '\n'
if [[ -z "$APKVULFUZZ_KEY" ]]; then
  echo 'No key was saved.' >&2
  exit 1
fi
printf '%s' "$APKVULFUZZ_KEY" > "$KEY_FILE"
chmod 600 "$KEY_FILE"
unset APKVULFUZZ_KEY
echo 'ELM key saved locally for LLMDroid.'
