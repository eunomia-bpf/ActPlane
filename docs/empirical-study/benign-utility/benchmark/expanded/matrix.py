"""Run predeclared groups concurrently with serialized shared metadata exports."""
import csv,fcntl,json,os,subprocess,sys,time,threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from benchmark.expanded.preflight import BASE,RAW,OUT,docker,receipt
from benchmark.expanded.prepare import prepare
RAW.mkdir(exist_ok=True)
lock=(RAW/'matrix.lock').open('a+');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
lock.seek(0);lock.truncate();lock.write(str(os.getpid()));lock.flush()
state=threading.RLock()
deadline=datetime.fromisoformat('2026-10-30T06:00:00+00:00').timestamp()

def export():
 with state:
  subprocess.run([sys.executable,'-B','benchmark/expanded/export.py'],check=True)
  return list(csv.DictReader((OUT/'trials.csv').open()))

def group(task):
 name=task['task']
 condition='';attempt=''
 try:
  rows=export()
  pending=[c for c in task['condition_order'].split(',') if not any(r['task']==name and r['condition']==c and r['selected_for_comparison']=='1' for r in rows)]
  if not pending or time.time()>=deadline:return
  with state:
   prepare(name)
   preflight=RAW/'instrumentation-preflights'
   if not list(preflight.glob('*/*/agent/instrumentation-preflight.json')):
    subprocess.run([sys.executable,'-B','-m','benchmark.expanded.run',name,'a','--attempt','setup-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()),'--preflight-only'],check=True)
    assert list(preflight.glob('*/*/agent/instrumentation-preflight.json'))
  for condition in task['condition_order'].split(','):
   rows=export()
   if any(r['task']==name and r['condition']==condition and r['selected_for_comparison']=='1' for r in rows):continue
   unresolved=[r for r in rows if r['task']==name and r['condition']==condition and r['outcome_valid']!='1' and r['verifier_valid']!='0']
   if unresolved:print('NEEDS_OUTCOME_AUDIT',name,condition,flush=True);continue
   if time.time()>=deadline:print('REPORTING_CUTOFF_PARTIAL',name,condition,flush=True);break
   attempts=[p.name for p in (RAW/'jobs').glob(f'{name}-{condition}-*')]
   attempt=('1' if condition=='a' else 'block-1') if not attempts else ('repair-' if condition=='a' else 'block-')+str(len(attempts)+1)
   receipt(name,'before_model_'+condition)
   print('MODEL_START',name,condition,attempt,time.strftime('%FT%TZ',time.gmtime()),flush=True)
   subprocess.run([sys.executable,'-B','-m','benchmark.expanded.run',name,condition,'--attempt',attempt],check=True)
   export()
 except Exception as error:
  print('TASK_INFRA_OR_AUDIT_PAUSE',name,repr(error),flush=True)
  with state:
   with (RAW/'matrix-errors.jsonl').open('a') as f:f.write(json.dumps(dict(task=name,condition=condition,attempt=attempt,utc=time.strftime('%FT%TZ',time.gmtime()),error=repr(error)))+'\n')
 finally:
  result=docker(['image','ls','-q',task['official_image']],capture_output=True,text=True)
  if result.stdout.strip():
   # Explicit tag removal never prunes another group's prepared image.
   subprocess.run(['docker','image','rm',task['official_image']],env={**os.environ,'DOCKER_HOST':'unix://'+str(BASE/'docker.sock'),'DOCKER_CONFIG':str(BASE/'docker-config')},check=False)

tasks=list(csv.DictReader((OUT/'tasks.csv').open()))
with ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(group,tasks))
rows=export();docker(['image','prune','-af']);docker(['builder','prune','-af'])
print('EXPANDED_MATRIX_STATUS',sum(r['selected_for_comparison']=='1' for r in rows),'of',54,flush=True)
