#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/exp/benign-utility/src
RAW=/workspaces/exp/benign-utility/raw/benchmark/expanded-recovery
mkdir -p "$RAW"
export BU_EXPANDED_RAW="$RAW" BU_DOCKER_HOST=unix:///var/run/docker.sock DOCKER_HOST=unix:///var/run/docker.sock
python3 -m benchmark.expanded.enforcement_control --effect block
python3 -m venv "$RAW/venv"
"$RAW/venv/bin/pip" install harbor==0.25.0 > "$RAW/pip-install.log" 2>&1
"$RAW/venv/bin/pip" freeze > "$RAW/pip-freeze.txt"
"$RAW/venv/bin/python" -m benchmark.expanded.amend freeze
