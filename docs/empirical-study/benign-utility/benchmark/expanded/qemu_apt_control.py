"""Dependency transport control between official cells; never an agent retry."""
import csv,fcntl,json,os,subprocess,time
from pathlib import Path
ROOT=Path('/workspaces/exp/benign-utility');RAW=ROOT/'raw/benchmark/expanded-recovery'
os.environ.setdefault('BU_EXPANDED_WORKER','worker1')
from benchmark.expanded.dependencies import verifier_env
from benchmark.expanded.apt_transport import verifier_env as apt_env

lock=Path('/run/benign-utility-native-cell.lock').open('a+')
print('WAITING_FOR_NATIVE_CELL_BOUNDARY',time.strftime('%FT%TZ',time.gmtime()),flush=True)
fcntl.flock(lock,fcntl.LOCK_EX)
available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
assert available>=1024**3,'Defer dependency control if actual guest memory has no headroom'
for process in Path('/proc').glob('[0-9]*'):
 try:
  command=(process/'cmdline').read_bytes().split(b'\0')[0].decode()
  assert command!='/workspaces/exp/benign-utility/raw/benchmark/engine/process','Earlier enforcer remains active'
 except (OSError,UnicodeDecodeError):pass
folder=RAW/'apt-transport/control';folder.mkdir(parents=True,exist_ok=True)
env=verifier_env();env.update(apt_env())
task=next(r for r in csv.DictReader((ROOT/'benchmark/expanded/results/tasks.csv').open()) if r['task']=='qemu-alpine-ssh')
image=json.loads((ROOT/'benchmark/expanded/results/per-task/qemu-alpine-ssh.json').read_text())['image']
reference=image['repo_digests'].split(';')[0]
subprocess.run(['docker','pull',reference],check=True)
actual=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',reference],text=True).strip()
assert actual==image['image_id'],'Dependency control must use the exact pre-outcome official image'
command=r'''apt-get update
printf '%s\n' "$?" >/control/apt-update.rc
apt-get install -y curl sshpass
status=$?; printf '%s\n' "$status" >/control/apt-install.rc
if [ "$status" -ne 0 ]; then exit "$status"; fi
curl -LsSf https://astral.sh/uv/0.9.5/install.sh | sh
source "$HOME/.local/bin/env"
uv --version
uvx -p 3.13 -w pytest==8.4.1 -w pytest-json-ctrf==0.3.5 pytest --version
version_status=$?
uvx -p 3.13 -w pytest==8.4.1 -w pytest-json-ctrf==0.3.5 pytest --help >/control/pytest-help.txt
help_status=$?
dpkg-query -W -f='${Package} ${Version}\n' curl libcurl4 libnghttp2-14 sshpass >/control/dpkg-versions.txt
if [ "$version_status" -ne 0 ] || [ "$help_status" -ne 0 ]; then exit 1; fi
grep -q -- --ctrf /control/pytest-help.txt
'''
args=['docker','run','--rm','--name','bu-qemu-verifier-dependency-control','--volume',str(folder)+':/control']
for key,value in env.items():args.extend(['--env',key+'='+value])
args.extend([reference,'bash','-lc',command])
started=time.time()
timed_out=False
with (folder/'stdout.txt').open('w') as stream:
 try:returncode=subprocess.run(args,stdout=stream,stderr=subprocess.STDOUT,timeout=900).returncode
 except subprocess.TimeoutExpired:returncode=124;timed_out=True
 finally:subprocess.run(['docker','rm','--force','bu-qemu-verifier-dependency-control'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
receipt=dict(purpose='dependency-only transport control; no benchmark model, task action or oracle',started_at=time.strftime('%FT%TZ',time.gmtime(started)),elapsed_s=time.time()-started,returncode=returncode,timed_out=timed_out,guest_available_memory_before_bytes=available,official_image=task['official_image'],official_image_digest=reference,actual_image_id=actual,native_cell_lock_held=True,dependency_env=env,stdout=str(folder/'stdout.txt'),dpkg_versions=(folder/'dpkg-versions.txt').read_text() if (folder/'dpkg-versions.txt').exists() else '')
(folder/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2),flush=True)
assert returncode==0,'Dependency control failed; do not wire a model retry'
