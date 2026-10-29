#!/usr/bin/env bash
set -euo pipefail
R=/workspaces/exp/sandbox-baselines
mkdir -p "$WS_RAW/docker" "$WS_RAW/home" "$R/results" "$R/vendor"
ln -sfn "$(readlink -f "$HOME/.local/bin/codex")" "$WS_RAW/codex-real"
apt-get update > "$WS_RAW/apt.log" 2>&1
apt-get install -y ripgrep python3-pytest python3-matplotlib poppler-utils >> "$WS_RAW/apt.log" 2>&1
T=/workspaces/lanes/translation-models/docs/empirical-study/translation-models
cp "$T/replay.py" "$T/prepare.py" "$T/pack_fixtures.py" "$R/vendor/"
cp "$T"/replay-*.csv "$T/summary.csv" "$R/results/"
cp -a "$R/vendor" .
if ! docker info >/dev/null 2>&1; then
  nohup dockerd --data-root "$WS_RAW/docker" --pidfile "$WS_RAW/dockerd.pid" > "$WS_RAW/dockerd.log" 2>&1 < /dev/null &
  for i in $(seq 1 45); do docker info >/dev/null 2>&1 && break; sleep 1; done
fi
docker version > "$R/results/docker-version.txt"
docker info > "$R/results/docker-info.txt"
docker build --network host -t actplane-sandbox-baselines:trixie -f Dockerfile . > "$WS_RAW/docker-build-host.log" 2>&1
docker image inspect actplane-sandbox-baselines:trixie > "$R/results/docker-image.json"
cd "$WS_RAW/probe"
HOME="$WS_RAW/home" "$WS_RAW/tools/node_modules/.bin/srt" -- bash -c 'echo SRT_STARTED; echo x > srt-default-write' 2>&1 || true
HOME="$WS_RAW/home" "$WS_RAW/tools/node_modules/.bin/srt" --version
df -h /workspaces
