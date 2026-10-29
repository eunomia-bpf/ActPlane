"""Freeze a clean durable recovery template, then boot one bounded worker."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

runtime = Path('/tmp/benign-utility-vm')
receipts = Path('/workspaces/exp/benign-utility/raw/benchmark/expanded/vm/recovery-20261029T2005')
ssh = ['ssh','-i',str(runtime/'id_ed25519'),'-p','2247','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','root@127.0.0.1']
remote = r'''
from pathlib import Path
import subprocess
for proc in Path('/proc').glob('[0-9]*'):
    try: args=(proc/'cmdline').read_bytes().split(b'\0')
    except (FileNotFoundError,PermissionError): continue
    assert b'benchmark.expanded.run' not in args
    assert not any(arg.endswith(b'/enforcement_control.py') for arg in args)
assert not subprocess.check_output(['docker','ps','-aq'],text=True).strip()
assert 'bpf' in Path('/sys/kernel/security/lsm').read_text().split(',')
Path('/etc/cloud/cloud-init.disabled').touch()
subprocess.run(['systemctl','stop','docker.service','docker.socket'],check=True)
subprocess.run(['sync'],check=True)
subprocess.run(['systemctl','poweroff'],check=True)
'''
pid = int((runtime/'qemu.pid').read_text())
assert b'benign-utility-expanded' in Path(f'/proc/{pid}/cmdline').read_bytes()
result = subprocess.run(ssh+['python3','-'],input=remote,text=True,capture_output=True)
(receipts/'template-poweroff.txt').write_text(result.stdout+result.stderr+f'\nreturncode={result.returncode}\n')
assert result.returncode in (0,255)
for _ in range(600):
    if not (runtime/'qemu.pid').exists(): break
    time.sleep(.1)
assert not (runtime/'qemu.pid').exists()
golden = receipts/'golden-standalone.qcow2'
assert not golden.exists()
usage = shutil.disk_usage(receipts)
source_info = json.loads(subprocess.check_output(['qemu-img','info','--output=json',str(runtime/'guest.qcow2')]))
assert usage.used/usage.total < .75, 'Keep durable PVC headroom for golden snapshot'
subprocess.run(['qemu-img','convert','-O','qcow2','-c',str(runtime/'guest.qcow2'),str(golden)],check=True)
assert shutil.disk_usage(receipts).used/shutil.disk_usage(receipts).total < .85
golden.chmod(0o444)
private = receipts/'private-runtime'
private.mkdir(mode=0o700)
shutil.copy2(runtime/'id_ed25519',private/'id_ed25519')
(private/'id_ed25519').chmod(0o600)
with golden.open('rb') as stream: digest = hashlib.file_digest(stream,'sha256').hexdigest()
info = json.loads(subprocess.check_output(['qemu-img','info','--output=json',str(golden)]))
assert 'backing-filename' not in info, 'Durable golden must be independently restorable'
(receipts/'template.json').write_text(json.dumps(dict(path=str(golden),sha256=digest,bytes=golden.stat().st_size,
    frozen_utc=time.strftime('%FT%TZ',time.gmtime()),image_info=info,
    reason='Clean setup-only standalone durable golden after group OOM; zero valid primary outcomes before recovery'),indent=2)+'\n')
disk = runtime/'worker1.qcow2'
subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(golden),str(disk)],check=True)
pidfile = runtime/'worker1.pid'
args = ['qemu-system-x86_64','-name','benign-utility-worker1-recovery','-enable-kvm','-cpu','host',
    '-smp','8','-m','8192','-drive',f'file={disk},if=virtio,format=qcow2',
    '-netdev','user,id=n1,hostfwd=tcp:127.0.0.1:2247-:22','-device','virtio-net-pci,netdev=n1,mac=52:54:00:12:34:56',
    '-virtfs','local,path=/workspaces/exp/benign-utility,mount_tag=lane,security_model=none,multidevs=remap,id=lane',
    '-virtfs','local,path=/workspaces/lanes/translation-models,mount_tag=translation,security_model=none,readonly=on,multidevs=remap,id=translation',
    '-display','none','-serial',f'file:{receipts}/worker1-serial.log','-daemonize','-pidfile',str(pidfile),
    '-monitor',f'unix:{runtime}/worker1-monitor.sock,server,nowait']
available_kib = int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))
assert available_kib > 14*1024*1024
subprocess.run(args,check=True)
row = dict(worker=1,port=2247,pid=int(pidfile.read_text()),vcpus=8,memory_mib=8192,command=args,
    template_sha256=digest,started_utc=time.strftime('%FT%TZ',time.gmtime()),environment_id='workspace_kvm_recovery_20261029T2005')
(receipts/'workers-launch.json').write_text(json.dumps([row],indent=2)+'\n')
print(json.dumps(row,indent=2))
