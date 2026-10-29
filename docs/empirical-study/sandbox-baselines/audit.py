#!/usr/bin/env python3
import csv,json
from pathlib import Path
from study import RAW,LANE
from analyze import main
main()
with (LANE/'results/fidelity.csv').open() as f:
 rows=list(csv.DictReader(f))
 bad=[r for r in rows if r['tool_inputs_returns_bytes_equal']!='1']
 print('FIDELITY',len(rows)-len(bad),'/',len(rows))
 for r in bad:
  print(r)
  for s in ('control','original'):
   p=RAW/'main'/s/r['repo']/r['statement_id']/Path(r['trace']).stem/'tools.jsonl'
   print(s,p.read_text()[:2500] if p.exists() else 'missing')
with (LANE/'results/exclusions.csv').open() as f:
 for r in csv.DictReader(f):
  if r['system']=='control':print('EXCLUDED CONTROL',r['repo'],r['statement_id'],r['family'],r['effect_observed'],r['effect_evidence'])
print('MECHANISMS')
for system in ('codex','srt','srt-cwd'):
 p=next((RAW/'main'/system).glob('*/*/*/syscalls.log'))
 for line in p.read_text().splitlines():
  if 'execve(' in line and 'bwrap' in line:print(system,line[:1800]);break
