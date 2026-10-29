"""Validate a genuine recovered shell exit; never alter its official success."""
import csv,hashlib,json
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark/network')
OUT=BASE.parents[2]/'benchmark/network/results'
path=OUT/'lifecycle-audits.csv';previous=list(csv.DictReader(path.open())) if path.exists() else []
for trial_id in ('git-multibranch__ZSKR46s','git-multibranch__yaibW6g'):
 row=next(r for r in csv.DictReader((OUT/'trials.csv').open()) if r['trial_id']==trial_id)
 directory=Path(row['raw_result']).parent/'agent';pane=(directory/'terminus_2.pane').read_text()
 finished=pane.index('asciinema: recording finished')
 calls={}
 for line in (directory/'calls.jsonl').read_text().splitlines():
  record=json.loads(line);calls.setdefault(record['index'],{}).update(record)
 if trial_id.endswith('ZSKR46s'):
  assert pane.index('/usr/bin/time: No such file or directory')<finished<pane.index('set +e',finished)
  assert '/usr/bin/time' in calls[3]['keystrokes'] and 'set +e' in calls[4]['keystrokes']
  verdict='agent set-e exited protected recorder on missing optional time binary; later outer-shell recovery passed official verifier'
 else:
  assert 'exit "$failed"' in calls[3]['keystrokes']
  assert pane.index('exit "$failed"')<finished
  assert 'failed=' in calls[3]['keystrokes']
  verdict='protected recorder finished during agent hook-writing call3 containing exit "$failed"; later outer-shell recovery passed official verifier; exact shell parser cause not inferred'
 assert row['outcome_score']=='1.0' and row['verifier_valid']=='1'
 audit=dict(trial_id=trial_id,security_coverage_end_call=3,failed_submission_calls='',adjudication=verdict,evidence=str(directory/'terminus_2.pane'),pane_sha256=hashlib.sha256((directory/'terminus_2.pane').read_bytes()).hexdigest(),utility_result_retained=row['outcome_score'])
 previous=[r for r in previous if r['trial_id']!=trial_id]+[audit]
with path.open('w',newline='') as handle:
 writer=csv.DictWriter(handle,fieldnames=list(previous[0]));writer.writeheader();writer.writerows(previous)
print('Retained official successes; protected-root lifecycle audits',len(previous))
