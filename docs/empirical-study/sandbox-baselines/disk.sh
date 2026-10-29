#!/usr/bin/env bash
set -eu
df -h /workspaces
du -sh "$WS_RAW" "$WS_RAW"/* /workspaces/exp/* 2>/dev/null | sort -h
docker ps -a --format '{{.ID}} {{.Status}} {{.Image}} {{.Names}}'
docker images --format '{{.ID}} {{.Size}} {{.Repository}} {{.Tag}}'
find "$WS_RAW" -maxdepth 2 -type f -size +100M -printf '%s %p\n'
