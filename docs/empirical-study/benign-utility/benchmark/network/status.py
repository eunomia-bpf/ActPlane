"""Read-only status of the separate follow-up and shared admission capacity."""
import csv,json,shutil
from datetime import datetime,timezone
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark/network')
OUT=BASE.parents[2]/'benchmark/network/results'
print('TIME',datetime.now(timezone.utc).isoformat(),'DISK',shutil.disk_usage('/workspaces'))
if (OUT/'trials.csv').exists():
 rows=list(csv.DictReader((OUT/'trials.csv').open()))
 print('SELECTED',[(r['task'],r['condition'],r['outcome_score'],r['coverage']) for r in rows if r['selected_for_comparison']=='1'])
for path in sorted((BASE/'jobs').glob('*/*/agent/calls.jsonl')):
 if (path.parent.parent/'result.json').exists():continue
 calls={}
 for line in path.read_text().splitlines():
  try:row=json.loads(line);calls.setdefault(row['index'],{}).update(row)
  except ValueError:pass
 print('ACTIVE_CALLS',path.parent.parent.name,len(calls))
for process in Path('/proc').glob('[0-9]*'):
 try:args=(process/'cmdline').read_bytes().split(b'\0')
 except OSError:continue
 if any(x in args for x in (b'benchmark.network.matrix',b'benchmark.network.run',b'benchmark/network/alias_control.py')):
  print('PROC',process.name,' '.join(x.decode(errors='replace') for x in args)[:240])
