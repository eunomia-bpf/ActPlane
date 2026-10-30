#!/usr/bin/env bash
# Keep remote reports current even when the Windows/control connection is lost.
set -uo pipefail
ROOT=/workspaces/exp/benign-utility
RAW="$ROOT/raw/benchmark/expanded-recovery"
cd "$ROOT/src"
exec 6>"$RAW/checkpoint-loop.lock"
flock -n 6 || exit 0
printf '%s\n' "$$" > "$RAW/checkpoint-loop.pid"
trap 'rm -f -- "$RAW/checkpoint-loop.pid"' EXIT
deadline=$(date -u -d '2026-10-30 20:00:00 UTC' +%s)
while [[ $(date -u +%s) -lt "$deadline" ]]; do
  bash checkpoint.sh || printf 'CHECKPOINT_RETRY %s\n' "$(date -u +%FT%TZ)"
  sleep 60
done
