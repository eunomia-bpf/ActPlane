#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/exp/benign-utility/src
RAW=/workspaces/exp/benign-utility/raw/benchmark/expanded-recovery
mkdir -p "$RAW"
# Reuse the exact already-installed public Python dependency environment. Its
# interpreter points at the same Debian Python version in the recovery guest.
if [ ! -x "$RAW/venv/bin/python" ]; then
  cp -a /workspaces/exp/benign-utility/raw/benchmark/expanded-vm/venv "$RAW/venv"
fi
"$RAW/venv/bin/python" -c 'import importlib.metadata; assert importlib.metadata.version("harbor")=="0.25.0"'
bash benchmark/expanded/guest_control.sh worker1 2247
