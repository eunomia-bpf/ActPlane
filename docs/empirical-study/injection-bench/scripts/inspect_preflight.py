"""Summarize actual setup records without dumping repository payloads."""
import json
import os
from pathlib import Path
raw=Path(os.environ['WS_RAW'])
for run in sorted((raw/'runs').glob('preflight-agplane*')):
    for path in sorted((run/'cases').glob('*/scored.json')):
        r=json.loads(path.read_text()); d=path.parent
        w=json.loads((d/'worker-result.json').read_text()) if (d/'worker-result.json').exists() else {}
        a=w.get('agent_result') or {}
        print(json.dumps({'run':run.name,'case':d.name,'system':r['defense'],
            'status':r['run_status'],'error':r.get('error'),'utility':r.get('utility_pass'),
            'policy_length':len((d/'generated-policy.dsl').read_text()) if (d/'generated-policy.dsl').exists() else None,
            'actions':[t.get('action_type') for t in a.get('turns',[])],
            'parser_failures':a.get('parser_failures'),
            'final_test_report':a.get('final_test_report'),
            'effect_errors':[e for e in w.get('effects',[]) if not e.get('success')]}))
