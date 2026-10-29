#!/usr/bin/env bash
set -euo pipefail
R=/workspaces/exp/sandbox-baselines
T=/workspaces/lanes/translation-models/docs/empirical-study/translation-models
mkdir -p "$R/vendor" "$R/results" "$WS_RAW/tools" "$WS_RAW/codex-home"
cp "$T/replay.py" "$T/prepare.py" "$T/pack_fixtures.py" "$R/vendor/"
sha256sum "$R"/vendor/*.py > "$R/results/replayer-sha256.txt"
python3 - <<'PY'
import json,pathlib
r=pathlib.Path('/workspaces/.agent-state/actplane-research/raw/translation-models-20261028')
print('RAW',r.exists())
for s in sorted((r/'artifact/docs/corpus-test').glob('*/*/statement.json')):
 print('\nPOLICY',s.parent.parent.name,s.parent.name,(s.parent/'rule.yaml').read_text())
 for name in json.loads(s.read_text())['trace_files']:
  records=[json.loads(x) for x in (s.parent/name).read_text().splitlines()]
  print(name,json.dumps([t for rec in records if rec.get('type')=='assistant' for t in rec.get('content',[]) if t.get('type')=='tool_use']))
PY
npm install --prefix "$WS_RAW/tools" @anthropic-ai/sandbox-runtime@0.0.81 > "$WS_RAW/npm-install.log" 2>&1
"$WS_RAW/tools/node_modules/.bin/srt" --help
mkdir -p "$WS_RAW/probe"
cd "$WS_RAW/probe"
CODEX_HOME="$WS_RAW/codex-home" codex sandbox -c 'sandbox_mode="workspace-write"' -- bash -c 'echo sandbox_ok; echo x > sandbox-test; python3 -c "import socket; socket.socket()"' || true
"$WS_RAW/tools/node_modules/.bin/srt" bash -c 'echo sandbox_ok; echo x > srt-test' || true
cat /etc/os-release
ls -l /workspaces/.agent-state/actplane-research/raw/translation-models-20261028/pythondeps/bin/python*