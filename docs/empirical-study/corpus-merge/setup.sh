#!/usr/bin/env bash
set -euo pipefail
python3 -m venv /workspaces/exp/corpus-merge/.venv
/workspaces/exp/corpus-merge/.venv/bin/pip install numpy==2.5.4 matplotlib==3.11.2 PyYAML==6.0.3
if ! command -v pdffonts >/dev/null; then
    sudo -n apt-get update -qq
    sudo -n apt-get install -y poppler-utils
fi
