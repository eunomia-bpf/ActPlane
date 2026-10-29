#!/usr/bin/env bash
set -euo pipefail
while pgrep -f '^python3 study.py --systems control --tag final$' >/dev/null; do sleep 2; done
python3 fidelity_effects.py
