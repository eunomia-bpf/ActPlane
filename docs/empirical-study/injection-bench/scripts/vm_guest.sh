#!/usr/bin/env bash
# Trusted guest init. Only the lane and benchmark temporary files are writable.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t securityfs securityfs /sys/kernel/security
mount -t bpf bpf /sys/fs/bpf
mount -t tracefs tracefs /sys/kernel/tracing
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts
mkdir -p /dev/shm
mount -t tmpfs tmpfs /dev/shm
/bin/busybox ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
/bin/busybox route add default gw 10.0.2.2
printf 'GUEST_KERNEL '; uname -a
printf 'GUEST_LSM '; cat /sys/kernel/security/lsm
export ACTPLANE_IN_GUEST=1
export WS_RAW=/workspaces/exp/injection-bench/raw
export ACTPLANE_VM_INSTANCE=default
for option in $(cat /proc/cmdline); do
  case "$option" in
    actplane_vm_instance=*) export ACTPLANE_VM_INSTANCE="${option#actplane_vm_instance=}" ;;
  esac
done
vm="$WS_RAW/vm"
test "$ACTPLANE_VM_INSTANCE" = default || vm="$WS_RAW/vm-$ACTPLANE_VM_INSTANCE"
export ACTPLANE_VM_QUEUE="$vm/queue"
cd /workspaces/exp/injection-bench/src
exec python3 scripts/actplane_adapter.py serve "$ACTPLANE_VM_QUEUE"
