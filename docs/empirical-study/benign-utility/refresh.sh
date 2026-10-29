#!/usr/bin/env bash
# Recompute one coherent expanded-study snapshot; workers keep running.
set -euo pipefail
ROOT=/workspaces/exp/benign-utility
exec 9>"$ROOT/benchmark/expanded/results/.export.lock"
flock -s 9
UV_CACHE_DIR=/tmp/benign-utility-figure-cache \
  "$ROOT/raw/benchmark/dependencies/bin/uv" run --no-project --with matplotlib==3.11.2 \
  python report.py --benchmark "$ROOT/benchmark/results" \
  --expanded "$ROOT/benchmark/expanded/results" \
  --network "$ROOT/benchmark/network/results" \
  --replay "$ROOT/replay/results" --out "$ROOT/results"
python3 chronology.py --benchmark "$ROOT/benchmark/results" \
  --expanded "$ROOT/benchmark/expanded/results" \
  --network "$ROOT/benchmark/network/results" \
  --replay "$ROOT/replay/results" --raw-replay "$ROOT/raw/replay" --out "$ROOT/results"
