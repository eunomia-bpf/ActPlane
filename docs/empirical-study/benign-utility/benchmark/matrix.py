"""Execute the frozen comparison, preserving failed cells and lane disk budget."""
import csv,fcntl,os,shutil,subprocess,sys,time
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
OUT=RAW.parent.parent/'benchmark/results'
lock=(RAW/'matrix.lock').open('a+')
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
lock.seek(0);lock.truncate()
lock.write(str(os.getpid()));lock.flush()

def export():
 subprocess.run([sys.executable,'-B','benchmark/analyze.py'],check=True)
 return list(csv.DictReader((OUT/'trials.csv').open()))
env={**os.environ,'DOCKER_HOST':'unix://'+str(RAW/'docker.sock'),'DOCKER_CONFIG':str(RAW/'docker-config')}
for task in csv.DictReader((OUT/'tasks.csv').open()):
 for condition in task['condition_order'].split(','):
  rows=export()
  if any(r['task']==task['task'] and r['condition']==condition and r['selected_for_comparison']=='1' for r in rows):
   print('SELECTED',task['task'],condition,flush=True);continue
  if any(r['task']==task['task'] and r['condition']==condition and r['comparison_cohort']=='corrected_uniform' and r['verifier_status']=='collection_error_requires_audit' for r in rows):
   print('NEEDS_COLLECTION_AUDIT',task['task'],condition,flush=True);continue
  prefix=f"{task['task']}-{condition}-"
  if not (RAW/'jobs'/(prefix+'1')).exists():attempt='1'
  else:
   previous=[int(p.name.split('-repair-')[-1]) for p in (RAW/'jobs').glob(prefix+'repair-*') if p.name.split('-repair-')[-1].isdigit()]
   attempt='repair-'+str(max(previous,default=0)+1)
  name=prefix+attempt
  disk=shutil.disk_usage('/workspaces')
  if disk.used/disk.total>=.85:raise RuntimeError('Workspace disk at >=85%; inspect shared usage before continuing')
  print('START',name,time.strftime('%FT%TZ',time.gmtime()),flush=True)
  subprocess.run([sys.executable,'-B','-m','benchmark.run',task['task'],condition,'--model','glm','--attempt',attempt],env=env,check=True)
  rows=export()
  for row in rows:
   if row['task']==task['task'] and row['condition']==condition and row['attempt']==attempt:
    print('RECORDED',name,row['verifier_status'],row['coverage'],'selected='+row['selected_for_comparison'],flush=True)
 # This socket owns only this lane's images/containers, other daemons untouched.
 subprocess.run(['docker','image','prune','-af'],env=env,check=True)
 subprocess.run(['docker','builder','prune','-af'],env=env,check=True)
rows=export();selected=sum(r['selected_for_comparison']=='1' for r in rows)
print('MATRIX_DONE' if selected==18 else 'MATRIX_INCOMPLETE',selected,'of',18,flush=True)
sys.exit(0 if selected==18 else 1)
