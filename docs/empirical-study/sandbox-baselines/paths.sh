#!/usr/bin/env bash
set -eu
type -a codex
sed -n '1,30p' /usr/local/bin/codex
find /opt /usr/local/lib/node_modules -name codex -type f 2>/dev/null | head -20
docker image inspect debian:trixie-slim --format '{{json .RepoDigests}}'
