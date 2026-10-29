#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = --after ]; then
  tail --pid="$2" -f /dev/null
  shift 2
fi
for argument in "$@"; do
  if [ "$argument" = --cache-tmpfs ]; then
    exec unshare --mount --propagation private -- /workspaces/.agent-state/actplane-trajectory-indirect/venv/bin/python replay/run.py "$@"
  fi
done
exec /workspaces/.agent-state/actplane-trajectory-indirect/venv/bin/python replay/run.py "$@"
