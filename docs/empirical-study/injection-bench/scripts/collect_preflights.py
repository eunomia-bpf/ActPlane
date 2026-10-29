"""Record setup attempts separately from the frozen benchmark matrix."""
import csv
import json
import os
from pathlib import Path
raw=Path(os.environ['WS_RAW'])
out=raw.parent/'results/preflights.csv'
rows=[]
for run in sorted((raw/'runs').glob('preflight*')):
    for path in sorted((run/'cases').glob('*/scored.json')):
        r=json.loads(path.read_text())
        rows.append(dict(run=run.name,task_id=r['task_id'],model=r['model'],
            system=r['defense'],no_attack=r['no_attack'],status=r['run_status'],
            error=r.get('error',''),utility_pass=r.get('utility_pass'),
            included_in_main=False,exclusion='setup preflight',
            note={'preflight-d0':'obsolete privilege setup and short transport timeout',
                  'preflight-v1':'obsolete short transport timeout',
                  'preflight-glm-v1':'successful uncensored setup calls; shorter-than-official deadline',
                  'preflight-qwen-v2':'official model transport deadline'}.get(run.name,'')))
out.parent.mkdir(exist_ok=True)
with out.open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else ['run']);w.writeheader();w.writerows(rows)
print(f'{len(rows)} setup cells recorded; none included in main results')
