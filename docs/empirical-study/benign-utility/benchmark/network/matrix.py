"""Execute only the separately frozen natural-network cohort, preserving negatives."""
import csv,fcntl,json,os,shutil,subprocess,sys,time
from pathlib import Path
from benchmark.network.preflight import docker,pull,receipt
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark');RAW=BASE/'network'
ROOT=BASE.parent.parent/'benchmark/network';OUT=ROOT/'results'
lock=(RAW/'matrix.lock').open('a+');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
lock.seek(0);lock.truncate();lock.write(str(os.getpid()));lock.flush()

def export():
 subprocess.run([sys.executable,'-B','benchmark/network/export.py'],check=True)
 return list(csv.DictReader((OUT/'trials.csv').open()))

seal=json.loads((ROOT/'cohort-freeze.json').read_text());assert seal['cohort']=='network_exposure_followup'
for task in csv.DictReader((OUT/'tasks.csv').open()):
 rows=export();pending=[c for c in task['condition_order'].split(',') if not any(r['task']==task['task'] and r['condition']==c and r['selected_for_comparison']=='1' for r in rows)]
 if not pending:print('TASK_SELECTED',task['task'],flush=True);continue
 receipt(task['task'],'before_task_group')
 pull(task['task'],task['official_image'])
 info=json.loads(docker(['image','inspect',task['official_image']],capture_output=True,text=True).stdout)[0]
 assert info['Id']==task['image_id'],'Official image drifted since pre-outcome inventory'
 # The first native setup validates actual namespace mapping and ptrace without
 # entering Agent.run. Its intentional native setup exception is stored apart.
 preflight=RAW/'instrumentation-preflights'
 if not list(preflight.glob('*/*/agent/instrumentation-preflight.json')):
  attempt='setup-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
  subprocess.run([sys.executable,'-B','-m','benchmark.network.run',task['task'],'a','--attempt',attempt,'--preflight-only'],check=True)
  assert list(preflight.glob('*/*/agent/instrumentation-preflight.json')),'No successful native setup/trace calibration receipt; do not start model'
 for condition in task['condition_order'].split(','):
  rows=export()
  if any(r['task']==task['task'] and r['condition']==condition and r['selected_for_comparison']=='1' for r in rows):continue
  if any(r['task']==task['task'] and r['condition']==condition and r['comparison_cohort']=='network_exposure_followup' and r['outcome_valid']!='1' and r['verifier_valid']!='0' for r in rows):
   print('NEEDS_OUTCOME_AUDIT',task['task'],condition,flush=True);continue
  prefix=f"{task['task']}-{condition}-"
  attempts=[p.name[len(prefix):] for p in (RAW/'jobs').glob(prefix+'*')]
  if not attempts:attempt='1' if condition=='a' else 'block-1'
  elif condition=='a':attempt='repair-'+str(1+max([int(x.split('-')[-1]) for x in attempts if x.startswith('repair-')],default=0))
  else:attempt='block-'+str(1+max([int(x.split('-')[-1]) for x in attempts if x.startswith('block-')],default=0))
  receipt(task['task'],'before_model_'+condition)
  print('MODEL_START',task['task'],condition,attempt,time.strftime('%FT%TZ',time.gmtime()),flush=True)
  subprocess.run([sys.executable,'-B','-m','benchmark.network.run',task['task'],condition,'--attempt',attempt],check=True)
  export()
 docker(['image','prune','-af']);docker(['builder','prune','-af'])
rows=export();selected=sum(r['selected_for_comparison']=='1' for r in rows)
print('NETWORK_MATRIX_DONE' if selected==9 else 'NETWORK_MATRIX_INCOMPLETE',selected,'of',9,flush=True)
sys.exit(0 if selected==9 else 1)
