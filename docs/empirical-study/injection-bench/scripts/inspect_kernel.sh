#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$WS_RAW"
exec > >(tee "$WS_RAW/kernel-inspection.txt") 2>&1
printf 'UTC '; date -u +%FT%TZ
uname -a
df -h /workspaces
for d in /workspaces/lanes/translation-models /workspaces/lanes/trajectory-indirect /workspaces/repository; do
  printf '\nDIRECTORY %s\n' "$d"
  test -d "$d" || continue
  find "$d" -maxdepth 3 -type f \( -name actplane -o -name '*kernel*' -o -name '*replay*' -o -name '*report*' -o -name '*summary*' \) -printf '%p\n' | head -60
done
printf '\nREPOSITORY\n'
git -C /workspaces/repository branch --show-current
git -C /workspaces/repository rev-parse HEAD
printf '\nKERNEL CONTROL SURFACE\n'
for p in /sys/kernel/security/lsm /proc/sys/kernel/unprivileged_bpf_disabled; do
  if test -r "$p"; then printf '%s: ' "$p"; cat "$p"; fi
done
printf '\nBINARIES\n'
find /workspaces/lanes/translation-models -maxdepth 5 -type f \( -name actplane -o -name process \) -printf '%p\n' | head -30
printf '\nBUILT CLI HELP\n'
cli=$(find /workspaces/lanes/translation-models -maxdepth 5 -type f -name actplane -print -quit)
if test -n "$cli"; then
  "$cli" --version
  "$cli" --help
  "$cli" run --help
fi
printf '\nREMOTE ENGINE SOURCE IDENTITY\n'
git -C /workspaces/lanes/translation-models rev-parse HEAD
git -C /workspaces/lanes/translation-models status --short
printf '\nEXISTING LANE RESULTS\n'
find /workspaces/lanes/translation-models /workspaces/lanes/trajectory-indirect -maxdepth 3 -type f \( -name '*.json' -o -name '*.csv' -o -name '*summary*.md' \) -not -path '*/.git/*' -not -path '*/target/*' -not -path '*/libbpf/*' -not -path '*/bpftool/*' -printf '%p\n' | head -60
printf '\nCAPABILITIES\n'
id
grep -E 'CapEff|CapBnd' /proc/self/status
printf '\nROOT/CHILD DOMAIN SOURCES\n'
grep -nE 'precheck_append_authority|CAP_STAT_REJECT|cap_req|AUTH_DECLASSIFY' /workspaces/lanes/translation-models/bpf/src/lib.rs /workspaces/lanes/translation-models/bpf/capability.bpf.h | head -65
printf '\nREMOTE RUN LIFECYCLE\n'
grep -nE 'pub async fn run_command|pinned singleton|clear_runtime_state|try_lock_runtime|AUTH_BIND_RULE|TARGET_SELF' /workspaces/lanes/translation-models/crates/actplane-runtime/src/runtime.rs | head -50
printf '\nEXISTING PINNED STATE\n'
if test -d /sys/fs/bpf; then find /sys/fs/bpf -maxdepth 3 -type f -printf '%p\n' | head -45; fi
printf '\nPROCESSES\n'
ps -eo pid,ppid,comm | grep -E 'actplane|process|qemu-system' | head -30 || true
printf '\nVM IMAGES (TARGETED)\n'
for d in /workspaces/.agent-state/actplane-research /workspaces/exp /workspaces/lanes/trajectory-indirect /workspaces/lanes/translation-models/docs/empirical-study /workspaces/repository/docs/empirical-study /home/oai/share /tmp; do
  test -d "$d" || continue
  find "$d" -maxdepth 5 -type f \( -name '*.qcow2' -o -name '*.img' -o -name '*vmlinuz*' -o -name '*bzImage*' -o -name '*initramfs*' -o -name '*kernel*.gz' -o -name '*.iso' \) -printf '%s %p\n' | head -45
done
printf '\nKVM/QEMU\n'
ls -l /dev/kvm 2>/dev/null || true
command -v qemu-system-x86_64 || true
