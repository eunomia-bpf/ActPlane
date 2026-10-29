#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/exp/benign-utility/src
RAW=/workspaces/exp/benign-utility/raw/benchmark/expanded-vm
export BU_EXPANDED_RAW="$RAW" BU_DOCKER_HOST=unix:///var/run/docker.sock DOCKER_HOST=unix:///var/run/docker.sock BU_EXPANDED_WORKER="$1"
source "$RAW/model.env"
worker=$1 task=$2 condition=$3 attempt=$4 mode=$5
if [ "$mode" = preflight ]; then
  exec "$RAW/venv/bin/python" -B -m benchmark.expanded.run "$task" "$condition" --attempt "$attempt" --preflight-only
fi
exec "$RAW/venv/bin/python" -B -m benchmark.expanded.run "$task" "$condition" --attempt "$attempt"
