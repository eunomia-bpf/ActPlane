#!/usr/bin/env bash
set -euo pipefail
ssh -i /tmp/benign-utility-vm/id_ed25519 -p 2247 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/benign-utility-vm/known_hosts \
  -o ConnectTimeout=5 root@127.0.0.1 \
  'set -e; uname -a; cat /proc/sys/kernel/random/boot_id; cat /proc/cmdline; cat /sys/kernel/security/lsm; test -e /var/lib/benign-utility-bootstrap-complete; findmnt -T /workspaces/exp/benign-utility; command -v bpftrace; command -v docker; df -h / /workspaces'
