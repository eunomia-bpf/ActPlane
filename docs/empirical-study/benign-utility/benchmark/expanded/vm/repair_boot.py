"""Preserve the setup-only failed guest and rebuild its cloud-init seed safely."""
import json
import os
from pathlib import Path
import shutil
import signal
import time

runtime = Path('/tmp/benign-utility-vm')
receipts = Path('/workspaces/exp/benign-utility/raw/benchmark/expanded/vm')
launch = json.loads((receipts / 'launch.json').read_text())
pid = int((runtime / 'qemu.pid').read_text())
assert launch['pid'] == pid
command = Path(f'/proc/{pid}/cmdline').read_bytes()
assert b'qemu-system-x86_64' in command and str(runtime / 'guest.qcow2').encode() in command
archive = receipts / 'failed-boot-v1'
archive.mkdir(exist_ok=False)
for name in ('serial.log', 'launch.json', 'user-data', 'meta-data'):
    shutil.copy2(receipts / name, archive / name)
(archive / 'reason.txt').write_text('Setup only: cloud kernel lacks usable 9p mount and critical fstab mount caused emergency mode; no model/control trial ran. Rebuild with official full kernel and nofail shared mounts.\n')
os.kill(pid, signal.SIGTERM)
for _ in range(100):
    if not (runtime / 'qemu.pid').exists():
        break
    time.sleep(.1)
assert not (runtime / 'qemu.pid').exists(), 'Own QEMU did not exit; preserve original disk'
(runtime / 'guest.qcow2').rename(runtime / 'failed-boot-v1.qcow2')
