import json,subprocess,shutil,time
from pathlib import Path
raw=Path('/workspaces/exp/benign-utility/raw/benchmark')
print('TIME',time.strftime('%FT%TZ',time.gmtime()),'DISK',shutil.disk_usage('/workspaces'))
for p in sorted((raw/'jobs').glob('*')):
 results=list(p.glob('*/result.json'))
 print('JOB',p.name)
 for r in results:
  d=json.loads(r.read_text());print('RESULT',d.get('verifier_result'),(d.get('exception_info') or {}).get('exception_message','')[:300])
 for log in p.glob('*/trial.log'):
  print('LOG',log.read_text()[-800:])
 for log in p.glob('*/agent/observer.jsonl'):
  print('OBSERVER',log.read_text()[-800:])
 for log in p.glob('*/agent/calls.jsonl'):
  print('CALLS',len(log.read_text().splitlines()),log.read_text()[-300:])
 for log in p.glob('*/agent/*'):
  if log.is_file():print('ARTIFACT',log.name,log.stat().st_size)
for line in subprocess.check_output(['ps','-eo','pid,args'],text=True).splitlines():
 if any(x in line for x in ['benchmark.run','bpftrace','/engine/process','/bounded-loader/process']):print('PROC',line[:350])
