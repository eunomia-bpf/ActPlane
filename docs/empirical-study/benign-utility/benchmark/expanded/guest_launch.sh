#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/exp/benign-utility/src
RAW=/workspaces/exp/benign-utility/raw/benchmark/expanded-recovery
export BU_EXPANDED_RAW="$RAW" BU_DOCKER_HOST=unix:///var/run/docker.sock DOCKER_HOST=unix:///var/run/docker.sock
# This file is created mode0600 from the existing Workspace model environment;
# its contents are never printed, included in result exports or copied into tasks.
source "$RAW/model.env"
exec "$RAW/venv/bin/python" -B -m benchmark.expanded.matrix
