"""Persist final guest capability facts; no benchmark/model operation occurs here."""
import csv
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/workspaces/exp/benign-utility')
OUT = Path(os.environ.get('BU_VM_RECEIPTS', str(ROOT / 'raw/benchmark/expanded/vm')))
parser=argparse.ArgumentParser()
parser.add_argument('--worker',type=int,choices=(1,2,3))
args=parser.parse_args()
remote = r'''
import hashlib,json,os,subprocess
from pathlib import Path
def output(args):return subprocess.check_output(args,text=True).strip()
root=Path('/workspaces/exp/benign-utility')
lsm=Path('/sys/kernel/security/lsm').read_text().strip()
assert 'bpf' in lsm.split(','), 'Guest BPF LSM absent'
assert Path('/var/lib/benign-utility-bootstrap-complete').exists()
lane=json.loads(output(['findmnt','--json','-T',str(root)]))['filesystems'][0]
assert lane['target']==str(root) and lane['fstype']=='9p', lane
translation=json.loads(output(['findmnt','--json','-T','/workspaces/lanes/translation-models']))['filesystems'][0]
assert translation['target']=='/workspaces/lanes/translation-models' and 'ro' in translation['options'].split(',')
paths={'engine':root/'raw/benchmark/engine/process','compiler':Path('/workspaces/lanes/translation-models/target/release/actplane')}
hashes={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in paths.items()}
kernel=output(['uname','-r'])
config=Path('/boot/config-'+kernel).read_text().splitlines()
print(json.dumps(dict(environment_id='workspace_kvm_guest_20261029',kernel=kernel,
    boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    kernel_cmdline=Path('/proc/cmdline').read_text().strip(),lsm=lsm,
    kernel_capability_config=[x for x in config if x.startswith(('CONFIG_BPF_LSM=','CONFIG_DEBUG_INFO_BTF=','CONFIG_NET_9P=','CONFIG_9P_FS='))],
    vcpus=os.cpu_count(),memory_kib=int(Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]),
    lane_mount=lane,translation_mount=translation,tool_sha256=hashes,
    bpftrace=output(['bpftrace','--version']),strace=output(['strace','--version']).splitlines()[0],
    docker_version=output(['docker','--version']),
    package_versions=output(['dpkg-query','-W','linux-image-amd64','docker.io','bpftrace','strace','python3-venv']))))
'''
command = ['ssh','-i','/tmp/benign-utility-vm/id_ed25519','-p',str(2246+args.worker if args.worker else 2247),
    '-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null',
    '-o','ConnectTimeout=5','root@127.0.0.1','python3','-']
result = subprocess.run(command, input=remote, text=True, check=True, capture_output=True)
data = json.loads(result.stdout)
data['environment_id'] = os.environ.get('BU_VM_ENVIRONMENT_ID', data['environment_id'])
for name, path in [('engine',ROOT/'raw/benchmark/engine/process'),
                   ('compiler',Path('/workspaces/lanes/translation-models/target/release/actplane'))]:
    assert hashlib.sha256(path.read_bytes()).hexdigest()==data['tool_sha256'][name]
data['captured_utc']=time.strftime('%FT%TZ',time.gmtime())
data['host_kernel']=subprocess.check_output(['uname','-r'],text=True).strip()
host_lsm=Path('/sys/kernel/security/lsm')
data['host_lsm']=host_lsm.read_text().strip() if host_lsm.exists() else 'unavailable: host securityfs not mounted in restarted container'
data['capture_stage']='isolated_primary_worker' if args.worker else 'preparation_before_worker_cloning'
if args.worker:
    data['worker']=args.worker
name=f'worker{args.worker}-environment' if args.worker else 'guest-environment'
target=OUT/(name+'.json')
if target.exists():
    previous=json.loads(target.read_text())
    assert {key:value for key,value in previous.items() if key!='captured_utc'} == {key:value for key,value in data.items() if key!='captured_utc'}, 'Recorded environment differs; preserve its historical receipt and review a new boot separately'
    print(json.dumps(previous,indent=2))
    raise SystemExit
target.write_text(json.dumps(data,indent=2)+'\n')
with (OUT/(name+'.csv')).open('w',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=list(data))
    writer.writeheader()
    writer.writerow({key:json.dumps(value,sort_keys=True) if isinstance(value,(list,dict)) else value for key,value in data.items()})
print(json.dumps(data,indent=2))
