"""Boot an official Debian cloud guest inside the Workspace; never alter host boot."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.request

RUNTIME = Path('/tmp/benign-utility-vm')
RECEIPTS = Path('/workspaces/exp/benign-utility/raw/benchmark/expanded/vm')
RUNTIME.mkdir(exist_ok=True)
RECEIPTS.mkdir(parents=True, exist_ok=True)
pidfile = RUNTIME / 'qemu.pid'
if pidfile.exists() and Path('/proc/' + pidfile.read_text().strip()).exists():
    raise RuntimeError('Existing guest process; do not modify an active VM seed or launch a competitor')
if any(Path('/proc/' + file.read_text().strip()).exists() for file in RUNTIME.glob('worker*.pid')):
    raise RuntimeError('Existing benchmark workers; do not modify their runtime')
BASE = 'https://cloud.debian.org/images/cloud/trixie/20261026-2643/'
NAME = 'debian-13-genericcloud-amd64-20261026-2643.qcow2'
EXPECTED_SHA512 = '3ace18e33bdd036edb49d1f79342bd01d2ab980e35194edb0b410435cd543538d286a0bd13bbb0835f7862306e3d385ce2f6a70d8ecf0bd961111166adbc1b8e'


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def download(url, path):
    temporary = path.with_suffix(path.suffix + '.partial')
    with urllib.request.urlopen(url, timeout=60) as source, temporary.open('wb') as target:
        while data := source.read(4 * 1024 * 1024):
            target.write(data)
    temporary.replace(path)


checksum = RECEIPTS / 'SHA512SUMS'
download(BASE + 'SHA512SUMS', checksum)
match = next(line for line in checksum.read_text().splitlines() if line.split()[-1].lstrip('*') == NAME)
expected = match.split()[0]
assert expected == EXPECTED_SHA512, 'Pinned official cloud build changed'
image = RUNTIME / NAME
if not image.exists():
    print('Downloading official Debian cloud image', flush=True)
    download(BASE + NAME, image)
with image.open('rb') as stream:
    actual = hashlib.file_digest(stream, 'sha512').hexdigest()
assert actual == expected, 'Official cloud image checksum mismatch'
info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(image)]))
(RECEIPTS / 'image.json').write_text(json.dumps(dict(url=BASE + NAME, sha512=actual,
    size_bytes=image.stat().st_size, image_info=info, checksum_url=BASE+'SHA512SUMS'), indent=2))

key = RUNTIME / 'id_ed25519'
if not key.exists():
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
public = key.with_suffix('.pub').read_text().strip()
userdata = f'''#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys:
      - {public}
package_update: true
packages:
  - linux-image-amd64
  - docker.io
  - bpftrace
  - strace
  - python3-venv
  - python3-pip
  - curl
  - ca-certificates
  - rsync
  - git
  - jq
write_files:
  - path: /etc/default/grub.d/90-benign-utility-lsm.cfg
    permissions: '0644'
    content: |
      GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
  - path: /etc/modules-load.d/benign-utility.conf
    content: |
      9p
      9pnet_virtio
  - path: /usr/local/sbin/benign-utility-first-boot
    permissions: '0755'
    content: |
      #!/bin/sh
      set -e
      kernel=$(ls /boot/vmlinuz-* | grep -v cloud | sort -V | tail -1)
      kernel=${{kernel##*/vmlinuz-}}
      test -n "$kernel"
      echo "GRUB_DEFAULT=\\\"Advanced options for Debian GNU/Linux>Debian GNU/Linux, with Linux $kernel\\\"" >> /etc/default/grub.d/90-benign-utility-lsm.cfg
      update-grub
      touch /var/lib/benign-utility-bootstrap-complete
      sync
      reboot
mounts:
  - [lane, /workspaces/exp/benign-utility, 9p, 'trans=virtio,version=9p2000.L,cache=none,nofail', '0', '0']
  - [translation, /workspaces/lanes/translation-models, 9p, 'trans=virtio,version=9p2000.L,ro,cache=none,nofail', '0', '0']
runcmd:
  - [mkdir, -p, /sys/kernel/security]
  - [sh, -c, 'mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security']
  - [/usr/local/sbin/benign-utility-first-boot]
'''
for name, data in [('user-data', userdata), ('meta-data', 'instance-id: benign-utility-20261029\nlocal-hostname: benign-utility-guest\n')]:
    (RUNTIME / name).write_text(data)
    (RECEIPTS / name).write_text(data)
run(['cloud-localds', str(RUNTIME / 'seed.img'), str(RUNTIME / 'user-data'), str(RUNTIME / 'meta-data')])
overlay = RUNTIME / 'guest.qcow2'
if not overlay.exists():
    run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image), str(overlay)])
    run(['qemu-img', 'resize', str(overlay), '500G'])
args = ['qemu-system-x86_64', '-name', 'benign-utility-expanded', '-enable-kvm', '-cpu', 'host',
    '-smp', '16', '-m', '65536', '-drive', f'file={overlay},if=virtio,format=qcow2',
    '-drive', f'file={RUNTIME}/seed.img,if=virtio,format=raw,readonly=on',
    '-netdev', 'user,id=n1,hostfwd=tcp:127.0.0.1:2247-:22', '-device', 'virtio-net-pci,netdev=n1',
    '-virtfs', 'local,path=/workspaces/exp/benign-utility,mount_tag=lane,security_model=none,multidevs=remap,id=lane',
    '-virtfs', 'local,path=/workspaces/lanes/translation-models,mount_tag=translation,security_model=none,readonly=on,multidevs=remap,id=translation',
    '-display', 'none', '-serial', f'file:{RECEIPTS}/serial.log', '-daemonize', '-pidfile', str(pidfile),
    '-monitor', f'unix:{RUNTIME}/monitor.sock,server,nowait']
run(args)
(RECEIPTS / 'launch.json').write_text(json.dumps(dict(command=args, pid=int(pidfile.read_text()),
    started_utc=time.strftime('%FT%TZ', time.gmtime()), host_kernel=subprocess.check_output(['uname','-r'], text=True).strip(),
    guest_vcpus=16, guest_memory_mib=65536, root_backing='ephemeral_qcow2_on_workspace_root_overlay',
    durable_lane_share='/workspaces/exp/benign-utility'), indent=2))
print('Guest launched; SSH root@127.0.0.1:2247 key='+str(key), flush=True)
