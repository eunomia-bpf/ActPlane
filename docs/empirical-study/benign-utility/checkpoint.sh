#!/usr/bin/env bash
# Freeze small result files while the host exporter is idle. Analysis stays remote.
set -euo pipefail
ROOT=/workspaces/exp/benign-utility
cd "$ROOT/src"
exec 7>"$ROOT/results/.checkpoint.lock"
flock -x 7
exec 8>"$ROOT/benchmark/expanded/results/.export.lock"
flock -s 8
fingerprint=$({ find "$ROOT/benchmark/expanded/results" -maxdepth 1 -type f \( -name '*.csv' -o -name '*.json' -o -name '*.md' \) -print0 | sort -z | xargs -0 sha256sum; sha256sum report.py chronology.py; } | sha256sum | cut -d' ' -f1)
BASE="$ROOT/checkpoint"
SNAPSHOT="$BASE/$fingerprint"
if [[ "${1:-}" != --force && -f "$SNAPSHOT/fingerprint.txt" && -f "$BASE/fingerprint.txt" && "$(cat "$BASE/fingerprint.txt")" == "$fingerprint" ]]; then
  echo CHECKPOINT_UNCHANGED
  echo "CHECKPOINT_FINGERPRINT $fingerprint"
  exit 0
fi
bash refresh.sh
if [[ ! -f "$SNAPSHOT/fingerprint.txt" ]]; then
  mkdir -p "$SNAPSHOT/results" "$SNAPSHOT/benchmark/expanded/results"
  for path in "$ROOT/results"/*.csv "$ROOT/results"/*.md "$ROOT/results"/*.pdf; do
    [[ ! -f "$path" ]] || cp "$path" "$SNAPSHOT/results/"
  done
  for path in "$ROOT/benchmark/expanded/results"/*.csv "$ROOT/benchmark/expanded/results"/*.json "$ROOT/benchmark/expanded/results"/*.md; do
    [[ ! -f "$path" ]] || cp "$path" "$SNAPSHOT/benchmark/expanded/results/"
  done
  printf '%s\n' "$fingerprint" > "$SNAPSHOT/fingerprint.txt"
fi
printf '%s\n' "$fingerprint" > "$BASE/fingerprint.txt"
echo CHECKPOINT_UPDATED
echo "CHECKPOINT_FINGERPRINT $fingerprint"
