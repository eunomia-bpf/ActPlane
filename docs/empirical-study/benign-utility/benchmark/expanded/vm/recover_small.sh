#!/bin/sh
# Rebuild only this lane's dead ephemeral runtime after documented group OOM.
set -eu
export BU_VM_RECEIPTS=/workspaces/exp/benign-utility/raw/benchmark/expanded/vm/recovery-20261029T2005
export BU_VM_MEMORY_MIB=8192 BU_VM_VCPUS=8
test ! -e /tmp/benign-utility-vm
mkdir -p "$BU_VM_RECEIPTS"
df -h /workspaces /tmp > "$BU_VM_RECEIPTS/filesystems-before.txt"
DEBIAN_FRONTEND=noninteractive apt-get install -y qemu-utils cloud-image-utils > "$BU_VM_RECEIPTS/host-build-dependencies.log" 2>&1
python3 benchmark/expanded/vm/bootstrap.py
