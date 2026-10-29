"""Materialize one official image at a time and inventory it before agent outcomes."""
import argparse,csv,hashlib,json,os,shutil,signal,subprocess,time
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark')
RAW=Path(os.environ.get('BU_EXPANDED_RAW',str(BASE/'expanded-recovery')));OUT=Path(os.environ.get('BU_EXPANDED_OUT',str(BASE.parent.parent/'benchmark/expanded/results')))
HERE=Path(__file__).parent
RAW.mkdir(exist_ok=True);OUT.mkdir(parents=True,exist_ok=True)
ENV={**os.environ,'DOCKER_HOST':os.environ.get('BU_DOCKER_HOST','unix:///var/run/docker.sock'),'DOCKER_CONFIG':str(BASE/'docker-config')}

def receipt(task,stage):
 disk=shutil.disk_usage('/workspaces')
 row=dict(task=task,stage=stage,utc=time.strftime('%FT%TZ',time.gmtime()),total_bytes=disk.total,used_bytes=disk.used,available_bytes=disk.free,used_fraction=disk.used/disk.total)
 path=OUT/'preflight-capacity.csv';exists=path.exists()
 with path.open('a',newline='') as handle:
  writer=csv.DictWriter(handle,fieldnames=list(row))
  if not exists:writer.writeheader()
  writer.writerow(row)
 print('CAPACITY',json.dumps(row),flush=True)
 if row['used_fraction']>=.85:raise RuntimeError('Shared disk >=85%; no new materialization admitted')
 return disk

def docker(args,**kwargs):return subprocess.run(['docker',*args],env=ENV,check=True,**kwargs)

def pull(task,image):
 receipt(task,'before_pull')
 process=subprocess.Popen(['docker','pull',image],env=ENV)
 try:
  while process.poll() is None:
   time.sleep(2)
   disk=shutil.disk_usage('/workspaces')
   if disk.used/disk.total>=.85:
    process.send_signal(signal.SIGINT)
    try:process.wait(timeout=15)
    except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=15)
    raise RuntimeError('Stopped own image materialization at shared85% guard')
  if process.returncode:raise RuntimeError('Official image pull failed; preserve log and retry infrastructure later')
 finally:
  if process.poll() is None:process.terminate();process.wait(timeout=15)
 receipt(task,'after_pull')

