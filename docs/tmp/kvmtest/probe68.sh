#!/bin/bash
# Lean load-only probe: boot a KVM guest on a given kernel and confirm the
# ActPlane engine loads ("ActPlane: ready") or fails (E2BIG / verifier reject).
# Uses a write-sink OAS policy config so the full-matcher open/write path is
# autoloaded and the verifier exercises trace_openat_exit on old kernels.
# Rootfs mirrors run_oas_firing_audit_vm.sh (creates /proc /sys /dev mount
# points so sysfs mounts and /sys/kernel/btf/vmlinux is exposed for BTF).
set -eu
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
ACT="$ROOT/target/release/actplane"
PROC="$ROOT/bpf/process"
OAS="${OAS_POLICY_DIR:-/workspaces/.agent-state/actplane-research/raw/openagentsafety-policy-compile-20260910T1438Z-verify20260911/tree/docs/OpenAgentSafety/policies/actplane}"
POLICY="${1:-safety-applications}"
KERNEL="${ACTPLANE_VM_KERNEL:-/boot/vmlinuz-6.8.0-138-generic}"
WORK="$(mktemp -d /tmp/actplane-probe68.XXXXXX)"
trap 'cp "$WORK/console.log" /tmp/probe68-console.log 2>/dev/null || true; cp "$WORK/loader.log" /tmp/probe68-loader.log 2>/dev/null || true; rm -rf "$WORK"' EXIT

[ -x "$ACT" ] || { echo "missing $ACT" >&2; exit 2; }
[ -x "$PROC" ] || { echo "missing $PROC" >&2; exit 2; }
[ -f "$KERNEL" ] || { echo "missing kernel $KERNEL" >&2; exit 2; }

"$ACT" compile --policy "$OAS/$POLICY.yaml" -f -o "$WORK/blob.bin" >/dev/null

# minimal rootfs: loader + its libs + busybox + the blob, with mount points.
mkdir -p "$WORK/root"/{bin,dev,proc,sys,tmp,sink,workspace}
cp "$PROC" "$WORK/root/process"
cp /bin/busybox "$WORK/root/bin/busybox"
for applet in sh mount poweroff sleep kill cat mkdir true ln awk; do
  ln -sf busybox "$WORK/root/bin/$applet"
done
{ ldd "$PROC"; } | awk '{for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i}' | sort -u |
  while read -r library; do [ -n "$library" ] && cp --parents "$library" "$WORK/root/"; done
cp "$WORK/blob.bin" "$WORK/root/blob.bin"

cat > "$WORK/root/init" <<'EOF'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
dmesg -n 1 2>/dev/null || true
echo "GUEST_KERNEL $(uname -r)"
echo "BTF_SIZE: $(wc -c < /sys/kernel/btf/vmlinux 2>/dev/null || echo absent)"
echo "PROBE_BEGIN $(date +%s)"
/process --config /blob.bin > /tmp/loader.log 2>&1 &
loader=$!
sleep 3
tries=0
while [ "$tries" -lt 250 ]; do
  grep -q 'ActPlane: ready' /tmp/loader.log 2>/dev/null && break
  grep -q 'too large\|E2BIG\|failed to load\|BPF program load failed' /tmp/loader.log 2>/dev/null && break
  kill -0 "$loader" 2>/dev/null || break
  tries=$((tries+1)); sleep 0.1
done
if grep -q 'ActPlane: ready' /tmp/loader.log; then
  echo "PROBE_RESULT LOADED"
elif grep -q 'too large\|E2BIG\|processed [0-9]' /tmp/loader.log; then
  echo "PROBE_RESULT E2BIG"
elif grep -q 'load failed\|failed to load\|ESRCH' /tmp/loader.log; then
  echo "PROBE_RESULT LOAD_FAIL"
else
  echo "PROBE_RESULT UNDETERMINED"
fi
echo "---loader.log---"
cat /tmp/loader.log 2>/dev/null
echo "---end---"
echo "PROBE_DONE"
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 > "$WORK/initramfs.gz") 2>/dev/null

echo "=== probe: kernel=$(basename "$KERNEL") policy=$POLICY ==="
timeout 180 qemu-system-x86_64 -accel kvm -m 1024 -smp 2 -nographic -no-reboot \
  -kernel "$KERNEL" -initrd "$WORK/initramfs.gz" \
  -append 'console=ttyS0 rdinit=/init panic=-1' > "$WORK/console.log" 2>/dev/null || true
tr -d '\r' < "$WORK/console.log" > "$WORK/console.clean.log" 2>/dev/null || true
grep -a 'PROBE_RESULT\|PROBE_BEGIN\|PROBE_DONE\|GUEST_KERNEL\|BTF_SIZE\|processed [0-9]\|max_states\|too large\|ready\|updates,\|libbpf:\|load failed\|E2BIG\|ESRCH\|failed to load' "$WORK/console.clean.log" 2>/dev/null || echo "PROBE: no markers captured"
