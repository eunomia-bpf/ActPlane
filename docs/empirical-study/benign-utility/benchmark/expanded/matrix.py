"""One host coordinator; each kernel runs one fixed matched task group at a time."""
import csv,fcntl,json,os,shlex,shutil,subprocess,sys,time,threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark');RAW=BASE/'expanded-recovery'
ROOT=BASE.parent.parent/'benchmark/expanded';OUT=ROOT/'results'
RAW.mkdir(exist_ok=True)
lock=(RAW/'matrix.lock').open('a+');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
lock.seek(0);lock.truncate();lock.write(str(os.getpid()));lock.flush()
state=threading.RLock();deadline=datetime.fromisoformat('2026-10-30T14:00:00+00:00').timestamp()
frozen=json.loads((ROOT/'environment-freeze.json').read_text())
assert set(frozen['workers'])=={'worker1'}
tasks=list(csv.DictReader((OUT/'tasks.csv').open()))
execution=list(csv.DictReader((OUT/'worker-assignment.csv').open()))
task_map={t['task']:t for t in tasks};tasks=[task_map[r['task']] for r in sorted(execution,key=lambda r:int(r['execution_rank']))]

def capacity(task,stage):
 disk=shutil.disk_usage('/workspaces')
 row=dict(task=task,stage=stage,utc=time.strftime('%FT%TZ',time.gmtime()),total_bytes=disk.total,used_bytes=disk.used,available_bytes=disk.free,used_fraction=disk.used/disk.total)
 file=OUT/'recovery-capacity.csv';exists=file.exists()
 with file.open('a',newline='') as stream:
  writer=csv.DictWriter(stream,fieldnames=list(row),lineterminator='\n')
  if not exists:writer.writeheader()
  writer.writerow(row)
 if row['used_fraction']>=.82:raise RuntimeError('No new cell at82% shared disk; retain headroom below85% and reclaim only rebuildable owned data')

def export():
 with state:
  subprocess.run([sys.executable,'-B','benchmark/expanded/export.py'],check=True)
  return list(csv.DictReader((OUT/'trials.csv').open()))

def remote(worker,args,**kwargs):
 port=str(frozen['workers'][worker]['ssh_port'])
 cmd=['ssh','-i','/tmp/benign-utility-vm/id_ed25519','-p',port,'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','root@127.0.0.1',shlex.join(args)]
 return subprocess.run(cmd,**kwargs)

def run_worker(worker):
 assigned=tasks
 for task in assigned:
  name=task['task']
  try:
   rows=export();pending=[c for c in task['condition_order'].split(',') if not any(r['task']==name and r['condition']==c and r['selected_for_comparison']=='1' for r in rows)]
   if not pending or time.time()>=deadline:continue
   capacity(name,'before_task_group')
   seal=json.loads((ROOT/'task-seals'/f'{name}.json').read_text());assert seal['worker_id']==worker
   preflight=RAW/'instrumentation-preflights'
   done=[]
   for receipt in preflight.glob(f'*-setup-{worker}-*/*/agent/instrumentation-preflight.json'):
    scope=json.loads((receipt.parent/'scope.json').read_text())
    if scope.get('runtime_worker_id')==worker and scope.get('boot_id')==frozen['workers'][worker]['boot_id'] and json.loads(receipt.read_text()).get('passed'):done.append(receipt)
   if not done:
    attempt='setup-'+worker+'-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
    remote(worker,['bash','/workspaces/exp/benign-utility/src/benchmark/expanded/guest_cell.sh',worker,name,'a',attempt,'preflight'],check=True)
    assert list(preflight.glob(f'{name}-a-{attempt}/*/agent/instrumentation-preflight.json'))
   for condition in task['condition_order'].split(','):
    rows=export()
    if any(r['task']==name and r['condition']==condition and r['selected_for_comparison']=='1' for r in rows):continue
    unresolved=[r for r in rows if r['task']==name and r['condition']==condition and r['outcome_valid']!='1' and r['verifier_valid']!='0']
    if unresolved:print('NEEDS_OUTCOME_AUDIT',name,condition,flush=True);continue
    if time.time()>=deadline:print('REPORTING_CUTOFF_PARTIAL',name,condition,flush=True);break
    capacity(name,'before_model_'+condition)
    attempts=[p.name for p in (RAW/'jobs').glob(f'{name}-{condition}-*')]
    attempt=('1' if condition=='a' else 'block-1') if not attempts else ('repair-' if condition=='a' else 'block-')+str(len(attempts)+1)
    print('MODEL_START',worker,name,condition,attempt,time.strftime('%FT%TZ',time.gmtime()),flush=True)
    remote(worker,['bash','/workspaces/exp/benign-utility/src/benchmark/expanded/guest_cell.sh',worker,name,condition,attempt,'model'],check=True)
    export()
  except Exception as error:
   print('TASK_INFRA_OR_AUDIT_PAUSE',worker,name,repr(error),flush=True)
   with state:
    with (RAW/'matrix-errors.jsonl').open('a') as f:f.write(json.dumps(dict(worker=worker,task=name,utc=time.strftime('%FT%TZ',time.gmtime()),error=repr(error)))+'\n')
  finally:
   remote(worker,['docker','image','rm',task['official_image']],check=False)
with ThreadPoolExecutor(max_workers=1) as pool:list(pool.map(run_worker,sorted(frozen['workers'])))
rows=export();print('EXPANDED_MATRIX_STATUS',sum(r['selected_for_comparison']=='1' for r in rows),'of',54,flush=True)
