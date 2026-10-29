#!/usr/bin/env bash
set -euo pipefail
apt-get install -y python3-pytest python3-matplotlib poppler-utils > "$WS_RAW/analysis-deps.log" 2>&1
docker build --network host -t actplane-sandbox-baselines:trixie -f Dockerfile . > "$WS_RAW/docker-build-pytest.log" 2>&1
python3 provenance.py
