#!/usr/bin/env bash
# Preserve the active native cell/coordinator; resume remaining cells afterwards.
set -euo pipefail
cd /workspaces/exp/benign-utility/src
RAW=/workspaces/exp/benign-utility/raw/benchmark/expanded-recovery
echo "WAITING_FOR_EXISTING_COORDINATOR $(date -u +%FT%TZ)"
flock --exclusive "$RAW/matrix.lock" true
echo "RESUMING_UNFINISHED_FROZEN_CELLS $(date -u +%FT%TZ)"
exec python3 -B -m benchmark.expanded.matrix
