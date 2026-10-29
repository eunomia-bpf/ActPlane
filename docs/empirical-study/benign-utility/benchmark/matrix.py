"""Execute the frozen comparison, preserving failed cells and lane disk budget."""
import csv,os,shutil,subprocess,sys,time
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
OUT=Path(__file__).parent/'results'
env={**os.environ,'DOCKER_HOST':'unix://'+str(RAW/'docker.sock'),'DOCKER_CONFIG':str(RAW/'docker-config')}
for task in csv.DictReader((OUT/'tasks.csv').open()):
 for condition in task['condition_order'].split(','):
  name=f"{task['task']}-{condition}-1"
  if list((RAW/'jobs'/name).glob('*/result.json')):
   print('EXISTING',name,flush=True);continue
  disk=shutil.disk_usage('/workspaces')
  if disk.used/disk.total>=.85:raise RuntimeError('Workspace disk at >=85%; inspect shared usage before continuing')
  print('START',name,time.strftime('%FT%TZ',time.gmtime()),flush=True)
  subprocess.run([sys.executable,'-B','-m','benchmark.run',task['task'],condition,'--model','glm'],env=env,check=True)
 # This socket owns only this lane's images/containers, other daemons untouched.
 subprocess.run(['docker','image','prune','-af'],env=env,check=True)
 subprocess.run(['docker','builder','prune','-af'],env=env,check=True)
print('MATRIX_DONE',flush=True)
