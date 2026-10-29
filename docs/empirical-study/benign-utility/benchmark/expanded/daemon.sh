#!/usr/bin/env bash
set -euo pipefail
RAW=/workspaces/exp/benign-utility/raw/benchmark
export DOCKER_HOST=unix://$RAW/docker.sock
DATA=/tmp/benign-utility-expanded-docker
if docker info >/dev/null 2>&1; then
  actual=$(docker info --format '{{.DockerRootDir}}')
  if [ "$actual" != "$DATA" ]; then
    [ "$actual" = "$RAW/docker" ]
    [ -z "$(docker ps -q)" ]
    pid=$(cat "$RAW/docker.pid")
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -F -- "--data-root $RAW/docker"
    kill -TERM "$pid"
    for i in $(seq 1 60); do
      if ! kill -0 "$pid" 2>/dev/null; then break; fi
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then echo 'Own empty daemon did not stop'; exit 1; fi
  fi
fi
if ! docker info >/dev/null 2>&1; then
  nohup dockerd --data-root "$DATA" --exec-root "$RAW/docker-exec" --pidfile "$RAW/docker.pid" --host "$DOCKER_HOST" --storage-driver vfs --bip 172.29.77.1/24 >> "$RAW/expanded/dockerd.log" 2>&1 < /dev/null &
  for i in $(seq 1 60); do
    if docker info >/dev/null 2>&1; then break; fi
    sleep 1
  done
fi
[ "$(docker info --format '{{.DockerRootDir}}')" = "$DATA" ]
[ "$(docker info --format '{{.Driver}}')" = vfs ]
docker info --format '{{json .}}' > "$RAW/expanded/docker-info.json"
df -h / /workspaces > "$RAW/expanded/storage-backing.txt"
cat "$RAW/expanded/storage-backing.txt"
