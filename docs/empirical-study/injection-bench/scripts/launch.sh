#!/usr/bin/env bash
# Detached workers use an immutable copy, because ws.sh sync overwrites src.
set -euo pipefail
snapshot_id=$(sha256sum scripts/benchmark_runner.py scripts/model_backend.py scripts/actplane_adapter.py | sha256sum | cut -d' ' -f1)
snapshot="$WS_RAW/code/$snapshot_id"
mkdir -p "$snapshot"
for script in benchmark_runner.py model_backend.py actplane_adapter.py; do
  if [ ! -f "$snapshot/$script" ]; then
    cp "scripts/$script" "$snapshot/$script"
    chmod 444 "$snapshot/$script"
  fi
done
printf 'Immutable runner snapshot: %s\n' "$snapshot"
exec "$WS_RAW/venv/bin/python" -u "$snapshot/benchmark_runner.py" "$@"
