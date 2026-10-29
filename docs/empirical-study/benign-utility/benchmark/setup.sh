#!/usr/bin/env bash
set -euo pipefail
RAW=${WS_RAW:-/workspaces/exp/benign-utility/raw}/benchmark
mkdir -p "$RAW"
python3 -m venv "$RAW/venv"
"$RAW/venv/bin/pip" install harbor==0.25.0 > "$RAW/pip-install.log" 2>&1
"$RAW/venv/bin/harbor" --version
"$RAW/venv/bin/harbor" run --help > "$RAW/harbor-run-help.txt"
[ -d "$RAW/terminal-bench-2/.git" ] || git clone --depth 1 https://github.com/harbor-framework/terminal-bench-2.git "$RAW/terminal-bench-2"
"$RAW/venv/bin/python" benchmark/install_compose.py
bash benchmark/prepare_run.sh
"$RAW/venv/bin/python" benchmark/registry.py
"$RAW/venv/bin/python" benchmark/task_manifest.py
"$RAW/venv/bin/pip" freeze > "$RAW/pip-freeze.txt"
mkdir -p "$RAW/engine"
cp /workspaces/.agent-state/actplane-research/raw/translation-models-20261028/bounded-loader/process "$RAW/engine/process"
sha256sum "$RAW/engine/process" > "$RAW/engine/sha256.txt"
