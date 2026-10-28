#!/usr/bin/env python3
"""Run an experiment command in the recorded Linux 6.8 KVM guest."""
import argparse
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import urllib.request

from prepare import DEFAULT_RAW, HERE, ROOT, sha, csv_write


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    ap.add_argument('--log', required=True, help='Log basename under raw/guest-logs')
    ap.add_argument('command', nargs=argparse.REMAINDER)
    args = ap.parse_args()
    raw = args.raw.resolve()
    kernel = raw / 'vm-root/boot/vmlinuz-6.8.0-138-generic'
    modules = raw / 'vm-root/lib/modules/6.8.0-138-generic'
    if not kernel.exists():
        kernel.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile('/workspaces/.agent-state/kernels/vmlinuz-6.8.0-138-generic', kernel)
    package = raw / 'downloads/linux-modules-6.8.0-138-generic.deb'
    url = 'https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-6.8.0-138-generic_6.8.0-138.138_amd64.deb'
    if not package.exists():
        package.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, package)
    if not modules.exists():
        subprocess.run(['dpkg-deb', '-x', str(package), str(raw / 'vm-root')], check=True)
    csv_write(HERE / 'guest-environment.csv', [dict(kernel=kernel.name, kernel_sha256=sha(kernel.read_bytes()),
              modules_url=url, modules_sha256=sha(package.read_bytes()), acceleration='kvm', memory='3G', cpus=2)])
    command = args.command
    if command and command[0] == '--':
        command = command[1:]
    if not command:
        raise SystemExit('Supply a guest command after --')
    script = shlex.join(command) + '; tm_status=$?; echo TM_GUEST_EXIT=$tm_status; exit "$tm_status"'
    argv = ['virtme-run', '--kimg', str(kernel), '--mods', 'auto', '--memory', '3G', '--cpus', '2',
            '--force-9p', '--show-boot-console', '--rwdir', str(raw), '--rwdir', str(HERE),
            '--cwd', str(ROOT), '--script-sh', script]
    dest = raw / 'guest-logs'
    dest.mkdir(exist_ok=True)
    (dest / (args.log + '.command.json')).write_text(json.dumps(argv, indent=2) + '\n')
    log = dest / (args.log + '.log')
    with log.open('w') as f:
        p = subprocess.run(argv, stdout=f, stderr=subprocess.STDOUT)
    text = log.read_text(errors='replace').replace('\r', '')
    marker = re.search(r'^TM_GUEST_EXIT=(\d+)$', text, re.M)
    # This distro's minimal modules package lacks virtio_console. virtme's
    # console fallback executes successfully but its host status is 255. Trust
    # the explicit guest exit marker, never the fallback host status alone.
    status = int(marker[1]) if marker else 125
    (dest / (args.log + '.status.json')).write_text(json.dumps(dict(host_status=p.returncode, guest_status=status,
                                                                  log_sha256=sha(log.read_bytes())), indent=2) + '\n')
    print(f'guest status {status}; log {log}')
    raise SystemExit(status)


if __name__ == '__main__':
    main()
