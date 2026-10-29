"""Reboot only setup-only worker VMs with their template's persistent NIC MAC."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import time

runtime=Path('/tmp/benign-utility-vm')
receipts=Path('/workspaces/exp/benign-utility/raw/benchmark/expanded/vm')
rows=json.loads((receipts/'workers-launch.json').read_text())
archive=receipts/'failed-worker-network-v1'
archive.mkdir(exist_ok=False)
shutil.copy2(receipts/'workers-launch.json',archive/'workers-launch.json')
for row in rows:
    worker=row['worker'];pid=row['pid']
    command=Path(f'/proc/{pid}/cmdline').read_bytes()
    assert f'benign-utility-worker{worker}'.encode() in command
    assert str(runtime/f'worker{worker}.qcow2').encode() in command
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as monitor:
        monitor.connect(str(runtime/f'worker{worker}-monitor.sock'))
        monitor.recv(8192)
        monitor.sendall(b'system_powerdown\n')
for row in rows:
    worker=row['worker'];pidfile=runtime/f'worker{worker}.pid'
    for _ in range(600):
        if not pidfile.exists():break
        time.sleep(.1)
    assert not pidfile.exists(), 'Worker did not power off; do not force-stop it'
    shutil.copy2(receipts/f'worker{worker}-serial.log',archive/f'worker{worker}-serial.log')
    row['command']=[('virtio-net-pci,netdev=n1,mac=52:54:00:12:34:56' if arg.startswith('virtio-net-pci,netdev=n1,mac=') else arg) for arg in row['command']]
    subprocess.run(row['command'],check=True)
    row.update(pid=int(pidfile.read_text()),started_utc=time.strftime('%FT%TZ',time.gmtime()),network_repair='Same template MAC on separate isolated user-net backends; persistent guest network config unchanged')
    print(json.dumps({key:value for key,value in row.items() if key!='command'}),flush=True)
(receipts/'workers-launch.json').write_text(json.dumps(rows,indent=2)+'\n')
