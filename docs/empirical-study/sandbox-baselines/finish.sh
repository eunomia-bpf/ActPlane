#!/usr/bin/env bash
set -euo pipefail
while pgrep -f '^python3 fidelity_effects.py$' >/dev/null; do sleep 2; done
python3 provenance.py
python3 analyze.py > "$WS_RAW/final-analysis.log"
python3 report.py
python3 verify_artifacts.py
df -h /workspaces
