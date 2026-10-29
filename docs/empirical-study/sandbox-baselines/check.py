#!/usr/bin/env python3
import json
from pathlib import Path
R=Path('/workspaces/exp/sandbox-baselines/raw/preflight')
for s in sorted(R.iterdir()):
 p=next(s.glob('*/*/trace_visible_violation'),None)
 if p:
  print('\nSYSTEM',s.name)
  for n in ('execution.json','stderr.txt','setup.stderr','tools.jsonl'):
   f=p/n
   if f.exists(): print(n,f.read_text()[:4500])
print('\nDOCKER BUILD')
print(Path('/workspaces/exp/sandbox-baselines/raw/docker-build.log').read_text()[-3000:])
