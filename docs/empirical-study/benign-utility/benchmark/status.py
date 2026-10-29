import json,subprocess,shutil,time
from pathlib import Path
raw=Path('/workspaces/exp/benign-utility/raw/benchmark')
print('TIME',time.strftime('%FT%TZ',time.gmtime()),'DISK',shutil.disk_usage('/workspaces'))
for p in sorted((raw/'jobs').glob('*')):
 results=list(p.glob('*/result.json'))
 print('JOB',p.name)
 for r in results:
  d=json.loads(r.read_text());print('RESULT',d.get('verifier_result'),(d.get('exception_info') or {}).get('exception_type',''))
 for log in p.glob('*/agent/calls.jsonl'):
  print('CALL_RECORDS',len(log.read_text().splitlines()))
 for log in p.glob('*/agent/scope.json'):
  d=json.loads(log.read_text());print('SCOPE',d.get('root_host_pid'),d.get('root_workspace_pid'),d.get('kernel_root_verified',False))
 for log in p.glob('*/agent/trajectory.json'):
  d=json.loads(log.read_text());print('METRICS',d.get('final_metrics'));print('ATIF_TOOL_CALLS',sum(len(s.get('tool_calls') or []) for s in d.get('steps',[])))
  for step in d.get('steps',[]):
   if step.get('tool_calls'):
    first=step['tool_calls'][0];print('ATIF_FORMAT',list(first),list((first.get('arguments') or {}).keys()));break
for line in subprocess.check_output(['ps','-eo','pid,args'],text=True).splitlines():
 if any(x in line for x in ['benchmark.run','bpftrace','/engine/process','/bounded-loader/process']):print('PROC',line[:350])
