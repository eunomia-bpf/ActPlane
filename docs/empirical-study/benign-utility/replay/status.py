"""Read-only replay progress and failure summary."""
import json,os
from pathlib import Path
root=Path(os.environ['WS_RAW'])/'replay'
for condition in ('none','broad','scoped'):
    directory=root/condition/'dynamic/runs'
    runs=[]
    for run in sorted(directory.glob('t*')):
        if (run/'done.json').exists():
            done=json.loads((run/'done.json').read_text())
            runs.append(done)
        else:
            calls=sum(1 for _ in (run/'calls.jsonl').open()) if (run/'calls.jsonl').exists() else 0
            print(condition,run.name,'running',calls,'calls')
    print(condition,'terminal',len(runs),'executed',sum(r['executed_calls'] for r in runs),'fatal',sum(bool(r['fatal']) for r in runs))
    for run in runs:
        if run['fatal']:print(condition,run['dynamic_id'],run['fatal'])
usage=os.statvfs(root)
print('workspace use percent',round(100*(1-usage.f_bavail/usage.f_blocks),2))
