#!/bin/bash
# Smoke: the `block` effect must actually deny an operation, which takes a BPF-LSM
# hook. Tracepoint mode only reports; `bpf/README.md` says `block` is unsupported
# without BPF-LSM, and the privileged CI job never has it.
#
# Context. `process.bpf.c` implements `block` at the BPF-LSM hooks
# (`lsm/file_open`, `lsm/path_write`, `lsm/task_kill`): the hook returns `-EPERM`
# before the kernel commits the operation. The engine can attach those programs
# only when the running kernel initialized the `bpf` LSM, which appears in
# `/sys/kernel/security/lsm`. The seven `*_smoke` tests in
# `crates/ebpf-ifc-engine/tests` that assert LSM-path behavior all begin with
# `if !bpf_lsm_active() { return; }`, so on a host without BPF-LSM they early-return
# and cargo records `... ok`. The privileged job's runner is
# `6.17.0-1022-azure` with no `bpf` in its LSM list, so a green job does not show
# that `block` was ever enforced. This runner boots a guest with `bpf` in the LSM
# list and asserts the denial rather than trusting the early-return.
#
# The runner asserts three success conditions: the guest initialized the `bpf`
# LSM, the policy installed (`ActPlane: running`), and the write the policy blocks
# failed with `EPERM` while a `BLOCKED` violation was reported. A host without
# BPF-LSM, or a `block` that only reports, fails closed with the observed reason.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ACT="${ACTPLANE_BIN:-$ROOT/target/release/actplane}"
# The claim is about the `block` path on a kernel that can carry BPF-LSM, so pin a
# 6.8 guest by default. `ACTPLANE_VM_KERNEL` overrides for another kernel line.
KERNEL="${ACTPLANE_VM_KERNEL:-$(ls -1 /boot/vmlinuz-6.8.*-generic 2>/dev/null | tail -1)}"
OUT="${1:-$ROOT/docs/empirical-study/results/lsm-block-smoke-vm}"
VM_TIMEOUT="${ACTPLANE_VM_TIMEOUT:-900}"
WORK="$(mktemp -d /tmp/actplane-lsm-block.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

[ -n "$KERNEL" ] || { echo "set ACTPLANE_VM_KERNEL to a guest vmlinuz (no /boot/vmlinuz-6.8.*-generic found)" >&2; exit 2; }
for f in "$ACT" "$KERNEL" /bin/busybox; do
  [ -e "$f" ] || { echo "missing $f" >&2; exit 2; }
done
for c in qemu-system-x86_64 cpio; do
  command -v "$c" >/dev/null || { echo "missing $c" >&2; exit 2; }
done

mkdir -p "$OUT" "$WORK/root"/{bin,dev,proc,sys,tmp}

# `block write file "/tmp/protected.txt"` lowers to a write-event rule with
# `EFFECT_BLOCK`; the LSM hook denies the open-for-write with `-EPERM`. The source
# is `exec "**"` so the guest's own `sh` carries the label and the write matches.
cat > "$WORK/root/smoke.yaml" <<'EOF'
version: 1
policy: |
  source AGENT = exec "**"
  rule deny-protected:
    block write file "/tmp/protected.txt" if AGENT
    because "smoke: block must deny the write with EPERM"
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
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
dmesg -n 1 2>/dev/null || true
mkdir -p /tmp

echo SMOKE_BEGIN
lsm="\$(cat /sys/kernel/security/lsm 2>/dev/null || echo none)"
echo "SMOKE_LSM \$lsm"
case "\$lsm" in
  *bpf*) echo SMOKE_LSM_ACTIVE ;;
  *) echo SMOKE_LSM_INACTIVE ;;
esac
"$ACT" --policy /smoke.yaml run -- /bin/sh -c 'echo hi > /tmp/protected.txt; echo "write_rc=\$?"' > /tmp/run.log 2>&1
run_rc=\$?
cat /tmp/run.log
echo SMOKE_RC \$run_rc
if grep -q 'ActPlane: running' /tmp/run.log && [ "\$run_rc" -eq 0 ]; then
  echo SMOKE_ENGINE_INSTALLED
else
  echo SMOKE_ENGINE_REJECTED
fi
if grep -q 'BLOCKED' /tmp/run.log && grep -q 'write_rc=1' /tmp/run.log; then
  echo SMOKE_BLOCK_ENFORCED
elif grep -q 'BLOCKED' /tmp/run.log; then
  echo SMOKE_BLOCK_REPORTED_ONLY
else
  echo SMOKE_BLOCK_SILENT
fi
echo EXPERIMENT_DONE
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 >"$WORK/initramfs.gz") \
  2>"$OUT/initramfs.stderr"

# `lsm=` is appended so the guest initializes the `bpf` LSM; the default LSM list
# omits it, which is what leaves `block` unreported.
run_qemu() {
  timeout "$VM_TIMEOUT" qemu-system-x86_64 -accel "$1" -m 1024 -smp 2 -nographic -no-reboot \
    -kernel "$KERNEL" -initrd "$WORK/initramfs.gz" \
    -append 'console=ttyS0 rdinit=/init panic=-1 lsm=lockdown,capability,landlock,yama,apparmor,bpf' \
    >"$OUT/console.log" 2>"$OUT/qemu.stderr"
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
  printf 'guest_lsm\t%s\n' "$(grep -m1 '^SMOKE_LSM ' "$OUT/console.clean.log" | sed 's/^SMOKE_LSM //')"
  printf 'acceleration\t%s\n' "$acceleration"
  printf 'qemu_status\t%s\n' "$qemu_status"
  printf 'qemu_timeout_s\t%s\n' "$VM_TIMEOUT"
  printf 'actplane_bin_sha256\t%s\n' "$(sha256sum "$ACT" | cut -d' ' -f1)"
} >"$OUT/metadata.tsv"

grep -q '^EXPERIMENT_DONE' "$OUT/console.clean.log" || {
  echo "guest experiment did not complete; evidence retained in $OUT" >&2; exit 1;
}
grep -q '^SMOKE_LSM_ACTIVE' "$OUT/console.clean.log" || {
  echo "guest did not initialize the bpf LSM, so block was never exercised; evidence retained in $OUT" >&2; exit 1;
}
grep -q '^SMOKE_ENGINE_INSTALLED' "$OUT/console.clean.log" || {
  echo "guest did not report a successful engine install; evidence retained in $OUT" >&2; exit 1;
}
grep -q '^SMOKE_BLOCK_ENFORCED' "$OUT/console.clean.log" || {
  echo "block did not deny the write with EPERM; evidence retained in $OUT" >&2; exit 1;
}
echo "wrote successful LSM block smoke to $OUT"
