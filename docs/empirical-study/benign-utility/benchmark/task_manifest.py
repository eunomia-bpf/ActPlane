"""Freeze the purposive Terminal-Bench subset before model outcomes."""
import csv,hashlib,json,tomllib,importlib.metadata
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
OUT=Path(__file__).parent/'results'
TASKS=['cancel-async-tasks','git-leak-recovery','log-summary-date-ranges','openssl-selfsigned-cert','sanitize-git-repo','vulnerable-secret']
OUT.mkdir(exist_ok=True)
rows=[]
for index,name in enumerate(TASKS):
 p=RAW/'terminal-bench-2'/name
 t=tomllib.loads((p/'task.toml').read_text())
 rows.append(dict(task=name,dataset='terminal-bench@2.0',dataset_commit='69671fbaac6d67a7ef0dfec016cc38a64ef7a77c',condition_order=','.join(('a','b','c')[index%3:]+('a','b','c')[:index%3]),agent_timeout_sec=t['agent']['timeout_sec'],verifier_timeout_sec=t['verifier']['timeout_sec'],instruction_sha256=hashlib.sha256((p/'instruction.md').read_bytes()).hexdigest(),docker_image=t['environment']['docker_image']))
 print('Frozen',name)
with (OUT/'tasks.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
(OUT/'versions.json').write_text(json.dumps({'harbor':importlib.metadata.version('harbor'),'terminus_2':'2.0.0','dataset':'terminal-bench@2.0','commit':rows[0]['dataset_commit'],'model':'zai/glm-5.3','model_url':'Workspace LITELLM_BASE_URL','candidate_preflight_model':'qwen3.8-27b-nvfp4','seed':'unset official default','repetitions':1,'selection':'purposive software/data and secret-handling tasks, not a representative estimate of full benchmark'},indent=2)+'\n')
