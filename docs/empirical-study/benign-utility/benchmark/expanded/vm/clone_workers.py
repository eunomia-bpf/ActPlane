"""Freeze the setup-only guest, then boot three separate enforcing kernels."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

runtime=Path('/tmp/benign-utility-vm')
receipts=Path('/workspaces/exp/benign-utility/raw/benchmark/expanded/vm')
key=runtime/'id_ed25519'
ssh=['ssh','-i',str(key),'-p','2247','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','root@127.0.0.1']
for file in runtime.glob('worker*.pid'):
    assert not Path('/proc/'+file.read_text().strip()).exists(), 'Existing worker; do not clone a competing runtime'
remote=r'''
from pathlib import Path
import subprocess
for proc in Path('/proc').glob('[0-9]*'):
    try:args=(proc/'cmdline').read_bytes().split(b'\0')
    except (FileNotFoundError,PermissionError):continue
    assert b'benchmark.expanded.run' not in args, 'A benchmark is active; refuse shutdown'
    assert not any(arg.endswith(b'/enforcement_control.py') for arg in args), 'A control is active'
assert not subprocess.check_output(['docker','ps','-aq'],text=True).strip(), 'Guest containers exist'
Path('/etc/cloud/cloud-init.disabled').touch()
subprocess.run(['systemctl','stop','docker.service','docker.socket'],check=True)
subprocess.run(['sync'],check=True)
subprocess.run(['systemctl','poweroff'],check=True)
'''
pid=int((runtime/'qemu.pid').read_text())
assert b'benign-utility-expanded' in Path(f'/proc/{pid}/cmdline').read_bytes()
result=subprocess.run(ssh+['python3','-'],input=remote,text=True,capture_output=True)
(receipts/'template-poweroff.txt').write_text(result.stdout+result.stderr+f'\nreturncode={result.returncode}\n')
assert result.returncode in (0,255), result.stderr
for _ in range(600):
    if not (runtime/'qemu.pid').exists():break
    time.sleep(.1)
assert not (runtime/'qemu.pid').exists(), 'Preparation guest did not shut down'
template=runtime/'template.qcow2'
(runtime/'guest.qcow2').rename(template)
template.chmod(0o444)
with template.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
template_info=dict(path=str(template),sha256=digest,bytes=template.stat().st_size,
    frozen_utc=time.strftime('%FT%TZ',time.gmtime()),reason='Setup-only template; no benchmark model ran. Cloud-init disabled after provisioning. One enforcing loader per independent worker kernel.')
(receipts/'template.json').write_text(json.dumps(template_info,indent=2)+'\n')
launches=[]
for worker in (1,2,3):
    disk=runtime/f'worker{worker}.qcow2'
    subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(template),str(disk)],check=True)
    port=2246+worker
    pidfile=runtime/f'worker{worker}.pid'
    args=['qemu-system-x86_64','-name',f'benign-utility-worker{worker}','-enable-kvm','-cpu','host',
        '-smp','8','-m','24576','-drive',f'file={disk},if=virtio,format=qcow2',
        '-netdev',f'user,id=n1,hostfwd=tcp:127.0.0.1:{port}-:22','-device','virtio-net-pci,netdev=n1,mac=52:54:00:12:34:56',
        '-virtfs','local,path=/workspaces/exp/benign-utility,mount_tag=lane,security_model=none,multidevs=remap,id=lane',
        '-virtfs','local,path=/workspaces/lanes/translation-models,mount_tag=translation,security_model=none,readonly=on,multidevs=remap,id=translation',
        '-display','none','-serial',f'file:{receipts}/worker{worker}-serial.log','-daemonize','-pidfile',str(pidfile),
        '-monitor',f'unix:{runtime}/worker{worker}-monitor.sock,server,nowait']
    subprocess.run(args,check=True)
    row=dict(worker=worker,port=port,pid=int(pidfile.read_text()),vcpus=8,memory_mib=24576,
        command=args,template_sha256=digest,started_utc=time.strftime('%FT%TZ',time.gmtime()))
    launches.append(row)
    print(json.dumps({key:value for key,value in row.items() if key!='command'}),flush=True)
(receipts/'workers-launch.json').write_text(json.dumps(launches,indent=2)+'\n')
