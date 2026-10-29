"""Validate a genuine recovered shell exit; never alter its official success."""
import csv,hashlib,json
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark/network')
OUT=BASE.parents[2]/'benchmark/network/results'
trial_id='git-multibranch__ZSKR46s'
row=next(r for r in csv.DictReader((OUT/'trials.csv').open()) if r['trial_id']==trial_id)
directory=Path(row['raw_result']).parent/'agent';pane=(directory/'terminus_2.pane').read_text()
assert '/usr/bin/time: No such file or directory' in pane
finished=pane.index('asciinema: recording finished')
assert pane.index('/usr/bin/time: No such file or directory')<finished<pane.index('set +e',finished)
calls={}
for line in (directory/'calls.jsonl').read_text().splitlines():
 record=json.loads(line);calls.setdefault(record['index'],{}).update(record)
assert '/usr/bin/time' in calls[3]['keystrokes'] and 'set +e' in calls[4]['keystrokes']
assert row['outcome_score']=='1.0' and row['verifier_valid']=='1'
audit=dict(trial_id=trial_id,security_coverage_end_call=3,failed_submission_calls='',adjudication='agent set-e exited protected recorder on missing optional time binary; later outer-shell recovery passed official verifier',evidence=str(directory/'terminus_2.pane'),pane_sha256=hashlib.sha256((directory/'terminus_2.pane').read_bytes()).hexdigest(),utility_result_retained=row['outcome_score'])
path=OUT/'lifecycle-audits.csv';previous=list(csv.DictReader(path.open())) if path.exists() else []
previous=[r for r in previous if r['trial_id']!=trial_id]
with path.open('w',newline='') as handle:
 writer=csv.DictWriter(handle,fieldnames=list(audit));writer.writeheader();writer.writerows(previous+[audit])
print(audit)
