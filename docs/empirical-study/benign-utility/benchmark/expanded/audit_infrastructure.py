"""Identify the observed pre-test Debian package transport failure; no reward inference."""
import csv,json
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark/expanded-recovery')
OUT=RAW.parent.parent.parent/'benchmark/expanded/results'
rows=[]
for result in sorted((RAW/'jobs').glob('qemu-alpine-ssh-*/*/result.json')):
 verifier=result.parent/'verifier';stdout=verifier/'test-stdout.txt'
 if not stdout.exists():continue
 text=stdout.read_text(errors='replace')
 if not all(s in text for s in ('404  Not Found','curl: command not found','uvx: command not found')):continue
 assert not (verifier/'ctrf.json').exists(),'Executed tests must not be excluded by this transport audit'
 data=json.loads(result.read_text())
 rows.append(dict(trial_id=result.parent.name,task='qemu-alpine-ssh',reason='official_verifier_dependency_http404_before_pytest',retry_allowed=1,verifier_status='not_executed_official_apt_dependency_http404',evidence=str(stdout)+'; no ctrf.json; official tests/test.sh lines4-19 install curl and uv before pytest'))
file=OUT/'infrastructure-audits.csv'
old=list(csv.DictReader(file.open())) if file.exists() else []
merged={r['trial_id']:r for r in old}
merged.update({r['trial_id']:r for r in rows})
if merged:
 fields=list(dict.fromkeys(k for row in merged.values() for k in row))
 with file.open('w',newline='') as stream:
  writer=csv.DictWriter(stream,fieldnames=fields,lineterminator='\n');writer.writeheader();writer.writerows(merged.values())
print('Confirmed pre-test dependency failures:',len(rows))
