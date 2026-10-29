#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/exp/benign-utility/src
ROOT=/workspaces/exp/benign-utility
worker=$1 port=$2
export BU_EXPANDED_RAW="$ROOT/raw/benchmark/expanded-recovery/workers/$worker" BU_EXPANDED_OUT="$ROOT/benchmark/expanded/recovery-worker-results/$worker" DOCKER_HOST=unix:///var/run/docker.sock
mkdir -p "$BU_EXPANDED_RAW" "$BU_EXPANDED_OUT"
python3 -B -m benchmark.expanded.enforcement_control --effect block
"$ROOT/raw/benchmark/expanded-vm/venv/bin/python" -B -m benchmark.expanded.amend capture-worker --worker "$worker" --ssh-port "$port"
