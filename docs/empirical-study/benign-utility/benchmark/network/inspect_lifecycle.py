"""Read-only, bounded lifecycle diagnostics from closed native trials."""
import csv,json,re
from pathlib import Path
OUT=Path('/workspaces/exp/benign-utility/benchmark/network/results')
for trial in csv.DictReader((OUT/'trials.csv').open()):
 if trial['coverage']!='partial_scope_or_dispatch_evidence':continue
 directory=Path(trial['raw_result']).parent/'agent'
 pane=(directory/'terminus_2.pane').read_text(errors='replace')
 print('TRIAL',trial['trial_id'])
 for index,line in enumerate(pane.splitlines(),1):
  if re.search(r'No such file|not found|asciinema: recording finished|error:|Permission denied|Traceback|exit "\$failed"|failed=',line):
   print('PANE',index,line[:240])
 calls={}
 for line in (directory/'calls.jsonl').read_text().splitlines():
  row=json.loads(line);calls.setdefault(row['index'],{}).update(row)
 for index,row in calls.items():
  code=row['keystrokes']
  critical=[line for line in code.splitlines() if re.search(r'exit\b|set [+-]e|/usr/bin/time|setsid|exec\b|pkill|kill\b|failed=',line)]
  print('CALL',index,'characters',len(code),'lifecycle_lines',critical)
