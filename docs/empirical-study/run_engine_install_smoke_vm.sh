#!/bin/bash
# Smoke: the pinned-engine path must install on Linux 6.8 for a policy that does
# not mention `recv`.
#
# Context. From Linux 6.8 the verifier sums the maximum stack depth along a call
# chain and rejects a program over 512 bytes. `HookReserve::full_profile()` sets
# `PINNED_POLICY_FEATURES` = `ALL_HOOK_FEATURES`, which includes recv
# unconditionally and does no autoload gating, so `actplane run`, `watch`, and MCP
# load `trace_recvfrom_exit` regardless of the policy. When a helper on that
# chain carries a large stack frame the whole engine fails to install, for any
# policy:
#
#   open ActPlane singleton: trace_recvfrom_exit.load: the BPF_PROG_LOAD syscall
#   returned Permission denied (os error 13). Verifier output: combined stack size
#   of 6 calls is 608. Too large ...
#
# This is a release blocker rather than a policy-semantics problem, and CI cannot
# see it: the privileged job runs on a kernel that does not perform the combined
# walk, and its smokes use no recv or file-flow config. The host is no help
# either, since this container denies `bpf()`. A guest boot of the kernel you mean
# to support is the only authority, which is what this runner does.
#
# The runner asserts the success side: the engine installs and the command reports
# `ActPlane: running`. A rejection prints the verifier text and fails closed.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ACT="${ACTPLANE_BIN:-$ROOT/target/release/actplane}"
# Restrict the default to a 6.8 guest: the claim is a 6.8 measurement, and the
# limit is enforced per kernel version, so a newer generic kernel would record
# evidence for a kernel this smoke is not about.
KERNEL="${ACTPLANE_VM_KERNEL:-$(ls -1 /boot/vmlinuz-6.8.*-generic 2>/dev/null | tail -1)}"
OUT="${1:-$ROOT/docs/empirical-study/results/engine-install-smoke-vm}"
VM_TIMEOUT="${ACTPLANE_VM_TIMEOUT:-900}"
WORK="$(mktemp -d /tmp/actplane-engine-smoke.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

[ -n "$KERNEL" ] || { echo "set ACTPLANE_VM_KERNEL to a 6.8 guest vmlinuz (no /boot/vmlinuz-6.8.*-generic found)" >&2; exit 2; }
for f in "$ACT" "$KERNEL" /bin/busybox; do
  [ -e "$f" ] || { echo "missing $f" >&2; exit 2; }
done
for c in qemu-system-x86_64 cpio gcc; do
  command -v "$c" >/dev/null || { echo "missing $c" >&2; exit 2; }
done

mkdir -p "$OUT" "$WORK/root"/{bin,dev,proc,sys,tmp}

# A policy that names no recv at all: the pinned path loads recv anyway, which is
# what makes the failure fail-any-policy rather than recv-policy-specific.
cat > "$WORK/root/smoke.yaml" <<'EOF'
version: 1
policy: |
  source COMMAND = exec "**"
  rule smoke-noop:
    notify exec "__actplane_never__" if COMMAND
    because "smoke: the engine must install for a policy with no recv"
EOF

cp /bin/busybox "$WORK/root/bin/busybox"
for applet in sh sleep rm true mkdir cat grep awk mount dmesg poweroff; do
  ln -s busybox "$WORK/root/bin/$applet"
done
cp --parents "$ACT" "$WORK/root"
{ ldd "$ACT"; } |
  awk '{for (i=1; i<=NF; i++) if ($i ~ /^\//) print $i}' | sort -u |
while read -r library; do cp --parents "$library" "$WORK/root"; done

cat > "$WORK/root/init" <<EOF
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
dmesg -n 1 2>/dev/null || true
mkdir -p /tmp

echo SMOKE_BEGIN
"$ACT" --policy /smoke.yaml run -- /bin/true > /tmp/run.log 2>&1
run_rc=\$?
cat /tmp/run.log
echo SMOKE_RC \$run_rc
if grep -q 'ActPlane: running' /tmp/run.log && [ "\$run_rc" -eq 0 ]; then
  echo SMOKE_ENGINE_INSTALLED
else
  echo SMOKE_ENGINE_REJECTED
fi
echo EXPERIMENT_DONE
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 >"$WORK/initramfs.gz") \
  2>"$OUT/initramfs.stderr"

run_qemu() {
  timeout "$VM_TIMEOUT" qemu-system-x86_64 -accel "$1" -m 1024 -smp 2 -nographic -no-reboot \
    -kernel "$KERNEL" -initrd "$WORK/initramfs.gz" \
    -append 'console=ttyS0 rdinit=/init panic=-1' >"$OUT/console.log" 2>"$OUT/qemu.stderr"
}
set +e
acceleration=kvm
run_qemu "$acceleration"; qemu_status=$?
if [ "$qemu_status" -ne 0 ] && ! grep -q '^EXPERIMENT_DONE' "$OUT/console.log"; then
  acceleration=tcg
  run_qemu "$acceleration"; qemu_status=$?
fi
set -e
tr -d '\r' <"$OUT/console.log" >"$OUT/console.clean.log"
cp "$OUT/console.clean.log" "$OUT/guest-console.txt"

{
  printf 'timestamp_utc\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'git_commit\t%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
  printf 'host_kernel\t%s\n' "$(uname -r)"
  printf 'guest_kernel\t%s\n' "$(basename "$KERNEL" | sed 's/^vmlinuz-//')"
  printf 'acceleration\t%s\n' "$acceleration"
  printf 'qemu_status\t%s\n' "$qemu_status"
  printf 'qemu_timeout_s\t%s\n' "$VM_TIMEOUT"
  printf 'actplane_bin_sha256\t%s\n' "$(sha256sum "$ACT" | cut -d' ' -f1)"
} >"$OUT/metadata.tsv"

grep -q '^EXPERIMENT_DONE' "$OUT/console.clean.log" || {
  echo "guest experiment did not complete; evidence retained in $OUT" >&2; exit 1;
}
if grep -q '^SMOKE_ENGINE_REJECTED' "$OUT/console.clean.log"; then
  echo "the pinned engine failed to install on the guest kernel; evidence retained in $OUT" >&2
  grep -E 'combined stack size|Permission denied|load failed' "$OUT/console.clean.log" >&2 || true
  exit 1
fi
grep -q '^SMOKE_ENGINE_INSTALLED' "$OUT/console.clean.log" || {
  echo "guest did not report a successful engine install; evidence retained in $OUT" >&2; exit 1;
}
echo "wrote successful engine-install smoke to $OUT"
