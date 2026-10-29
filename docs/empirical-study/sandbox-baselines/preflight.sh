#!/usr/bin/env bash
set -euo pipefail
ln -sfn "$(readlink -f "$HOME/.local/bin/codex")" "$WS_RAW/codex-real"
docker build --network host -t actplane-sandbox-baselines:trixie -f Dockerfile . > "$WS_RAW/docker-build-host.log" 2>&1
python3 study.py --tag preflight-v2 --limit 5 --systems control,codex,srt,srt-cwd,docker,original
python3 - <<'PY'
import pathlib,json
root=pathlib.Path('/workspaces/exp/sandbox-baselines/raw/preflight-v2')
for system in root.iterdir():
 for p in sorted(system.glob('*/*/*/tools.jsonl')):
  print(system.name,p.parent.name,p.read_text()[:1200])
 for p in system.glob('*/*/*/failure.json'):
  print('FAILURE',system.name,p.read_text())
 for p in system.glob('*/*/*/stderr.txt'):
  if p.read_text(): print('STDERR',system.name,p.read_text()[:1000])
PY
