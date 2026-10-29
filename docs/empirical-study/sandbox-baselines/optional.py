#!/usr/bin/env python3
from pathlib import Path
for root in ('/workspaces/exp/injection-bench','/workspaces/exp/benign-utility'):
 p=Path(root)
 print('LANE',root)
 if not p.exists():continue
 for q in sorted(p.glob('src/*')):
  if q.is_file():print(q.name,q.stat().st_size)
 for n in ('README.md','SUMMARY.md','PLAN.md','BLOCKED.md'):
  q=p/'src'/n
  if q.exists():print(n,q.read_text()[:6000])
