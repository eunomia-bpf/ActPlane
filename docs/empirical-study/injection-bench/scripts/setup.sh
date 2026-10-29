#!/usr/bin/env bash
set -euo pipefail
upstream="$WS_RAW/upstream/RepoGuardBench"
if [ ! -d "$upstream/.git" ]; then
  mkdir -p "$upstream"
  git -C "$upstream" init
  git -C "$upstream" remote add origin https://github.com/DaoyuanLi2816/RepoGuardBench.git
  git -C "$upstream" fetch --depth 1 origin 49d6e51b5189f1f49a948bf360ed73d9487548a3
  git -C "$upstream" checkout --detach FETCH_HEAD
fi
test "$(git -C "$upstream" rev-parse HEAD)" = 49d6e51b5189f1f49a948bf360ed73d9487548a3
if [ ! -x "$WS_RAW/venv/bin/python" ]; then
  python3 -m venv "$WS_RAW/venv"
fi
"$WS_RAW/venv/bin/python" -m pip install -q -e "$upstream" 'matplotlib>=3.7' 'pytest>=7.4'
"$WS_RAW/venv/bin/python" -m pip freeze > "$WS_RAW/environment.txt"
df -h /workspaces
