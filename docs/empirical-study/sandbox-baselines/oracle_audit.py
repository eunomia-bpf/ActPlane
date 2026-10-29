#!/usr/bin/env python3
"""Read-only audit of effect evidence and frozen violation-trace programs."""
import gzip
import json
from pathlib import Path
from effect_oracle import evaluate, _execs
R=Path('/workspaces/exp/sandbox-baselines/raw')
S=Path('/workspaces/.agent-state/actplane-research/raw/translation-models-20261028/artifact/docs/corpus-test')
def read(p):
 if p.exists(): return p.read_text()
 if Path(str(p)+'.gz').exists():
  with gzip.open(str(p)+'.gz','rt') as f:return f.read()
 return ''
def load(p):
 text=read(p)
 return json.loads(text) if text else None
for tag in ('main','final'):
 print('\nRUN',tag)
 for system in ('control','codex','srt','srt-cwd','docker'):
  counts={1:0,0:0,None:0}; unfinished=0; zeros=[]; unknown=[]
  for sd in sorted(S.glob('*/*/statement.json')):
   for name in json.loads(sd.read_text())['trace_files']:
    records=[json.loads(x) for x in (sd.parent/name).read_text().splitlines()]
    if not records[0]['violation']:continue
    out=R/tag/system/sd.parent.parent.name/sd.parent.name/Path(name).stem
    execution=load(out/'execution.json')
    if not execution or execution.get('returncode')!=0:
     unfinished+=1;continue
    ts=[json.loads(x) for x in read(out/'tools.jsonl').splitlines() if x.startswith('{')]
    syscalls=read(out/'syscalls.log')
    result=evaluate(sd.parent.parent.name,sd.parent.name,records,load(out/'before.json'),load(out/'after.json'),syscalls,ts)
    counts[result['effect_observed']]+=1
    if result['effect_observed']==0:
     zeros.append((sd.parent.parent.name,sd.parent.name,name,result['evidence']))
    if result['effect_observed'] is None:
     unknown.append((sd.parent.parent.name,sd.parent.name,name,result['evidence']))
  print(system,counts,'unfinished',unfinished)
  if system in ('control','docker'):
   print('ABSENT',json.dumps(zeros));print('UNKNOWN',json.dumps(unknown))