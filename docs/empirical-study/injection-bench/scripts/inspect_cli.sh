#!/usr/bin/env bash
# Read installed CLI and official benchmark transport; no task execution.
set -euo pipefail
if [ "${1:-}" = status ]; then
  for name in smoke/cli-identity.json channel-smoke/client.stdout channel-smoke/client.stderr; do
    path="$WS_RAW/cli-inspection/$name"
    if [ -f "$path" ]; then printf '%s\n' "$name"; cat "$path"; fi
  done
  exit 0
fi
mkdir -p "$WS_RAW/cli-inspection"
printf 'Workspace: '; pwd
sed -n '1,280p' "$WS_RAW/upstream/RepoGuardBench/repoguard/agents/claude_cli_backend.py" | tee "$WS_RAW/cli-inspection/official-claude-backend.txt"
if command -v claude; then
  claude --version | tee "$WS_RAW/cli-inspection/version.txt"
  claude --help > "$WS_RAW/cli-inspection/help.txt"
  grep -nE -- '--tools|--allowedTools|--model|--setting|--session|--output|--permission' "$WS_RAW/cli-inspection/help.txt" || true
  claude auth status > "$WS_RAW/cli-inspection/auth.json" 2> "$WS_RAW/cli-inspection/auth.stderr" || true
  python3 - <<'PY'
import json, os
from pathlib import Path
p=Path(os.environ['WS_RAW'])/'cli-inspection/auth.json'
try:
    d=json.loads(p.read_text())
    print(json.dumps({k:d[k] for k in ('loggedIn','authMethod','apiProvider','subscriptionType') if k in d}))
except Exception:
    print('auth status not available as JSON; raw status retained remotely')
PY
else
  printf 'claude CLI missing\n'
fi
if [ "${1:-}" = smoke ]; then
  "$WS_RAW/venv/bin/python" - <<'PY'
import json, os, sys
from pathlib import Path
sys.path.insert(0,str(Path(os.environ['WS_RAW'])/'upstream/RepoGuardBench'))
sys.path.insert(0,'scripts')
from inference_transport import make_cli_backend
backend=make_cli_backend('claude-cli:opus',Path(os.environ['WS_RAW'])/'cli-inspection/smoke')
response=backend.chat([{'role':'user','content':'Reply with exactly: ok'}])
print(json.dumps({'text':response.text,'prompt_tokens':response.prompt_tokens,
  'completion_tokens':response.completion_tokens,'raw':response.raw}))
PY
fi
if [ "${1:-}" = channel-smoke ]; then
  "$WS_RAW/venv/bin/python" - <<'PY'
import json, os, subprocess, sys, tempfile
from pathlib import Path
root=Path(os.environ['WS_RAW'])
sys.path.insert(0,str(root/'upstream/RepoGuardBench'))
sys.path.insert(0,'scripts')
from inference_transport import InferenceServer
folder=root/'cli-inspection/channel-smoke'
with InferenceServer('zai/glm-5.3',folder) as channel:
    script='''import json,os,sys
from inference_transport import client_chat
r=client_chat(sys.argv[1],[{'role':'user','content':'Reply with exactly: ok'}])
print(json.dumps({'uid':os.getuid(),'text':r.text,'model':r.raw.get('model')}))
'''
    env={'PATH':'/usr/local/bin:/usr/bin:/bin','PYTHONPATH':str(Path('scripts').resolve())+':'+str(root/'upstream/RepoGuardBench')}
    p=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','--bounding-set=-all','--no-new-privs',sys.executable,'-c',script,str(channel)],capture_output=True,text=True,env=env)
    (folder/'client.stdout').write_text(p.stdout)
    (folder/'client.stderr').write_text(p.stderr)
    print(p.stdout,p.stderr)
    raise SystemExit(p.returncode)
PY
fi
