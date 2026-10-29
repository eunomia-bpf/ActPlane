#!/usr/bin/env bash
set -euo pipefail
while pgrep -f '^python3 study.py --systems docker --tag main$' >/dev/null; do sleep 2; done
SANDBOX_RUN_TAG=main python3 analyze.py > "$WS_RAW/initial-analysis.log"
mkdir -p /workspaces/exp/sandbox-baselines/initial-results
cp /workspaces/exp/sandbox-baselines/results/*.csv /workspaces/exp/sandbox-baselines/initial-results/
python3 compress.py main
# Remove only this lane's failed build container and obsolete build image.
docker rm e326cae45695 >/dev/null 2>&1 || true
docker image rm d97c9f8f09b7 >/dev/null 2>&1 || true
bash dependencies.sh
df -h /workspaces
bash run.sh final
python3 compress.py final
