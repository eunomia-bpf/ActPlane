"""Read-only replay progress and failure summary."""
import json,os,subprocess
from collections import Counter
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
    failures=Counter(run['fatal'].splitlines()[0] for run in runs if run['fatal'])
    for reason,count in failures.items():print(condition,'failure category',count,reason)
usage=os.statvfs(root)
print('workspace use percent',round(100*(1-usage.f_bavail/usage.f_blocks),2))
result=subprocess.run(['pgrep','-af','replay/(launch.sh|run.py)'],capture_output=True,text=True)
print(result.stdout)
