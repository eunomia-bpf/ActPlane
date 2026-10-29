"""Materialize one official image at a time and inventory it before agent outcomes."""
import argparse,csv,json,os,shutil,signal,subprocess,time
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark')
RAW=BASE/'network';OUT=BASE.parent.parent/'benchmark/network/results'
HERE=Path(__file__).parent
RAW.mkdir(exist_ok=True);OUT.mkdir(parents=True,exist_ok=True)
ENV={**os.environ,'DOCKER_HOST':'unix://'+str(BASE/'docker.sock'),'DOCKER_CONFIG':str(BASE/'docker-config')}

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

def export():
 images=[];files=[]
 for path in sorted((RAW/'inventory').glob('*/receipt.json')):
  row=json.loads(path.read_text());images.append(row)
  for item in json.loads((path.parent/'files.json').read_text()):files.append(dict(task=row['task'],**item))
 for name,rows in [('image-inventory.csv',images),('secret-inventory.csv',files)]:
  if rows:
   fields=list(dict.fromkeys(key for row in rows for key in row))
   with (OUT/name).open('w',newline='') as handle:
    writer=csv.DictWriter(handle,fieldnames=fields);writer.writeheader();writer.writerows(rows)

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--task');args=parser.parse_args()
 candidates=list(csv.DictReader((BASE.parent.parent/'benchmark/results/network-task-candidates.csv').open()))
 for candidate in candidates:
  task=candidate['task']
  if candidate['decision']!='propose' or args.task and args.task!=task:continue
  directory=RAW/'inventory'/task;directory.mkdir(parents=True,exist_ok=True)
  if (directory/'receipt.json').exists():print('INVENTORY_RETAINED',task,flush=True);continue
  image=candidate['official_image']
  # A manifest lookup downloads no layers and records the exact public descriptor.
  receipt(task,'before_manifest')
  manifest=docker(['manifest','inspect','--verbose',image],capture_output=True,text=True).stdout
  (directory/'manifest.json').write_text(manifest)
  try:
   pull(task,image)
   info=json.loads(docker(['image','inspect',image],capture_output=True,text=True).stdout)[0]
   receipt(task,'before_readonly_inventory')
   result=docker(['run','--rm','--read-only','--network','none','--entrypoint','python3','--volume',str(HERE/'inventory_image.py')+':/inventory/inventory_image.py:ro',image,'-B','/inventory/inventory_image.py'],capture_output=True,text=True)
   files=json.loads(result.stdout)
   (directory/'files.json').write_text(json.dumps(files,indent=2)+'\n')
   row=dict(task=task,image=image,image_id=info['Id'],repo_digests=';'.join(info.get('RepoDigests',[])),image_size_bytes=info['Size'],architecture=info['Architecture'],os=info['Os'],dataset_commit=candidate['dataset_commit'],instruction_sha256=candidate['instruction_sha256'],inventory_mode='readonly image; network none; no services or agent',utc=time.strftime('%FT%TZ',time.gmtime()))
   (directory/'receipt.json').write_text(json.dumps(row,indent=2)+'\n');export()
   print('INVENTORIED',json.dumps(row),flush=True)
  finally:
   # This private daemon has no active benchmark; Docker protects active images.
   docker(['image','prune','-af']);docker(['builder','prune','-af'])
 export()

if __name__=='__main__':main()
