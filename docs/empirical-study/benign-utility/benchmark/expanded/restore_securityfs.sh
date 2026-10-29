#!/usr/bin/env bash
set -euo pipefail
RAW=/workspaces/exp/benign-utility/raw/benchmark/expanded
# Keep the metadata repair from resuming admission before native denial is verified.
if [ -r /proc/49334/cmdline ] && tr '\0' ' ' </proc/49334/cmdline | grep -F -- '-m benchmark.expanded.repair_inventory 20095'; then
  cat /proc/49334/stat > "$RAW/securityfs-repair-helper-identity.txt"
  kill -STOP 49334
fi
if [ -r /proc/20095/cmdline ] && tr '\0' ' ' </proc/20095/cmdline | grep -F -- '-m benchmark.expanded.matrix'; then
  kill -STOP 20095
fi
date -u > "$RAW/securityfs-restoration.txt"
mountpoint /sys/kernel/security >> "$RAW/securityfs-restoration.txt" || true
if ! mountpoint -q /sys/kernel/security; then
  mount -t securityfs securityfs /sys/kernel/security
fi
cat /sys/kernel/security/lsm | tee "$RAW/kernel-lsm.txt"
grep -Eq '(^|,)bpf(,|$)' "$RAW/kernel-lsm.txt"
cat /proc/mounts | grep securityfs >> "$RAW/securityfs-restoration.txt"
