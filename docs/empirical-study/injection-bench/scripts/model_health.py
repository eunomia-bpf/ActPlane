"""Check supplied model service liveness and documented transport timeout."""
import os
from pathlib import Path
import urllib.request
raw=Path(os.environ['WS_RAW'])
for line in (raw/'upstream/RepoGuardBench/repoguard/agents/ollama_backend.py').read_text().splitlines():
    if 'timeout' in line:print(line.strip())
for endpoint in ('health','v1/metrics'):
    try:
        with urllib.request.urlopen('http://qwen38-vllm.models.svc.cluster.local:8000/'+endpoint,timeout=10) as r:
            print(endpoint,r.status,r.read(120).decode(errors='replace'))
    except Exception as e:print(endpoint,type(e).__name__,str(e))
