#!/usr/bin/env bash
set -euo pipefail
RAW=/workspaces/exp/benign-utility/raw/benchmark
mkdir -p "$RAW/expanded"
if ! command -v bpftrace >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq bpftrace strace > "$RAW/expanded/apt-install.log" 2>&1
fi
if [ ! -x "$RAW/expanded/venv/bin/python" ]; then
  python3 -m venv "$RAW/expanded/venv"
fi
"$RAW/expanded/venv/bin/pip" install harbor==0.25.0 > "$RAW/expanded/pip-install.log" 2>&1
"$RAW/expanded/venv/bin/python" -m pip freeze > "$RAW/expanded/pip-freeze.txt"
"$RAW/expanded/venv/bin/python" benchmark/install_compose.py
bash benchmark/prepare_run.sh
"$RAW/expanded/venv/bin/python" -m benchmark.dependencies
bpftrace --version
strace --version | head -1
"$RAW/expanded/venv/bin/harbor" --version
