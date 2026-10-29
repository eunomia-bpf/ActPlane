"""Small live run status without printing model inputs or credentials."""
from collections import Counter
import json
import os
from pathlib import Path
import urllib.request

raw=Path(os.environ['WS_RAW'])
for run in sorted((raw/'runs').glob('*')):
    if not run.is_dir():continue
    results=[json.loads(p.read_text()) for p in (run/'cases').glob('*/scored.json')]
    responses=list((run/'cases').glob('*/calls/*/*.response.json'))
    print(json.dumps({'run':run.name,'finished':len(results),
        'status':dict(Counter(r.get('run_status') for r in results)),
        'responses':len(responses),'utility':sum(bool(r.get('utility_pass')) for r in results),
        'completed_attacks':sum(bool(r.get('attack_completed')) for r in results),
        'errors':dict(Counter(r.get('error') for r in results if r.get('error')))}))
    if run.name.startswith('preflight'):
        for p in responses[:2]:
            r=json.loads(p.read_text());choice=r.get('choices',[{}])[0]
            print(json.dumps({'run':run.name,'returned_model':r.get('model'),
                'finish_reason':choice.get('finish_reason'),
                'content_length':len(choice.get('message',{}).get('content') or ''),
                'usage':r.get('usage')}))
try:
    req=urllib.request.Request('http://qwen38-vllm.models.svc.cluster.local:8000/metrics')
    with urllib.request.urlopen(req,timeout=10) as r:
        rows=[l for l in r.read().decode().splitlines() if not l.startswith('#') and
            any(k in l for k in ('num_requests_running','num_requests_waiting','gpu_cache_usage_perc'))]
    print(json.dumps({'qwen_metrics':rows}))
except Exception as e:print(json.dumps({'qwen_metrics_error':str(e)}))
