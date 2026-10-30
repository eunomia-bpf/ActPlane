#!/usr/bin/env bash
# Prepare public package bytes on the host, then wait for a guest cell boundary.
set -euo pipefail
cd /workspaces/exp/benign-utility/src
RAW=/workspaces/exp/benign-utility/raw/benchmark/expanded-recovery/apt-transport
mkdir -p "$RAW"
python3 -B benchmark/expanded/apt_transport.py > "$RAW/prepare-receipt.json"
exec ssh -i /tmp/benign-utility-vm/id_ed25519 -p 2247 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 \
  'cd /workspaces/exp/benign-utility/src && exec python3 -B -m benchmark.expanded.qemu_apt_control'
