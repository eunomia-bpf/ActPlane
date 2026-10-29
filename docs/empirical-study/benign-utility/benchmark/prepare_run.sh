#!/usr/bin/env bash
set -euo pipefail
RAW=${WS_RAW:-/workspaces/exp/benign-utility/raw}/benchmark
export DOCKER_HOST=unix://$RAW/docker.sock
if ! docker info > "$RAW/docker-info.txt" 2>&1; then
nohup dockerd --data-root "$RAW/docker" --exec-root "$RAW/docker-exec" --pidfile "$RAW/docker.pid" --host "$DOCKER_HOST" --storage-driver overlay2 --bip 172.29.77.1/24 > "$RAW/dockerd.log" 2>&1 < /dev/null &
for i in $(seq 1 40); do
 sleep 1
 docker info > "$RAW/docker-info.txt" 2>&1 && break
done
fi
docker info --format '{{json .}}' > "$RAW/docker-info.json"
git -C "$RAW/terminal-bench-2" fetch --depth 1 origin 69671fbaac6d67a7ef0dfec016cc38a64ef7a77c
git -C "$RAW/terminal-bench-2" checkout --detach 69671fbaac6d67a7ef0dfec016cc38a64ef7a77c
