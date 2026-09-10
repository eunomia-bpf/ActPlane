#!/bin/bash
# Run the policy-authority boundary matrix in a minimal privileged guest.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KERNEL="${ACTPLANE_VM_KERNEL:-$(ls -1 /boot/vmlinuz-*-generic | tail -1)}"
OUT="${1:-$ROOT/docs/empirical-study/results/policy-authority-boundary-vm}"
WORK="$(mktemp -d /tmp/actplane-authority-vm.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

for file in "$KERNEL" /bin/busybox; do
  [ -e "$file" ] || { echo "missing $file" >&2; exit 2; }
done
for command in cargo cpio qemu-system-x86_64; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }
done
mkdir -p "$OUT" "$WORK/root"/{bin,dev,proc,sys,tmp,workspaces/repository/target/debug/deps}

set +e
cargo test --locked -p actplane --test mcp_protocol \
  mcp_policy_authority_boundary_matrix_privileged --no-run \
  >"$OUT/build.stdout" 2>"$OUT/build.stderr"
build_status=$?
set -e
printf '%s\n' "$build_status" >"$OUT/build.status"
[ "$build_status" -eq 0 ] || { echo "test build failed; evidence retained in $OUT" >&2; exit 1; }

test_bin="$(find "$ROOT/target/debug/deps" -maxdepth 1 -type f \
  -name 'mcp_protocol-*' -perm -111 -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
actplane_bin="$ROOT/target/debug/actplane"
[ -x "$test_bin" ] || { echo "missing compiled mcp_protocol test" >&2; exit 2; }
[ -x "$actplane_bin" ] || { echo "missing $actplane_bin" >&2; exit 2; }

cp /bin/busybox "$WORK/root/bin/busybox"
for applet in sh sleep rm true mkdir cat grep awk mount dmesg poweroff; do
  ln -s busybox "$WORK/root/bin/$applet"
done
cp --parents "$test_bin" "$actplane_bin" "$WORK/root"
{ ldd "$test_bin"; ldd "$actplane_bin"; } |
  awk '{for (i=1; i<=NF; i++) if ($i ~ /^\//) print $i}' | sort -u |
while read -r library; do cp --parents "$library" "$WORK/root"; done

cat >"$WORK/root/init" <<EOF
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
dmesg -n 1 2>/dev/null || true
cd /workspaces/repository
"$test_bin" mcp_policy_authority_boundary_matrix_privileged \
  --ignored --exact --nocapture --test-threads=1
test_status=\$?
echo AUTHORITY_TEST_STATUS \$test_status
echo EXPERIMENT_DONE
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 >"$WORK/initramfs.gz") \
  2>"$OUT/initramfs.stderr"

run_qemu() {
  timeout 420 qemu-system-x86_64 -accel "$1" -m 1536 -smp 2 -nographic -no-reboot \
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

printf '%s\t%s\t%s\n' case expected observed >"$OUT/counts.tsv"
awk '
  /^AUTHORITY_CASE / {
    name=$2; expected=""; observed="";
    for (i=3; i<=NF; i++) {
      if ($i ~ /^expected=/) { expected=$i; sub(/^expected=/, "", expected) }
      if ($i ~ /^observed=/) { observed=$i; sub(/^observed=/, "", observed) }
    }
    print name "\t" expected "\t" observed
  }
' "$OUT/console.clean.log" >>"$OUT/counts.tsv"
{
  printf 'timestamp_utc\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'git_commit\t%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
  printf 'host_kernel\t%s\n' "$(uname -r)"
  printf 'guest_kernel\t%s\n' "$(basename "$KERNEL" | sed 's/^vmlinuz-//')"
  printf 'acceleration\t%s\n' "$acceleration"
  printf 'qemu_status\t%s\n' "$qemu_status"
  printf 'test_source_sha256\t%s\n' "$(sha256sum "$ROOT/crates/actplane-cli/tests/mcp_protocol.rs" | cut -d' ' -f1)"
  printf 'test_binary_sha256\t%s\n' "$(sha256sum "$test_bin" | cut -d' ' -f1)"
  printf 'actplane_binary_sha256\t%s\n' "$(sha256sum "$actplane_bin" | cut -d' ' -f1)"
} >"$OUT/metadata.tsv"

grep -q '^EXPERIMENT_DONE' "$OUT/console.clean.log" || {
  echo "guest experiment did not complete; evidence retained in $OUT" >&2; exit 1;
}
grep -q '^AUTHORITY_TEST_STATUS 0' "$OUT/console.clean.log" || {
  echo "authority test failed; evidence retained in $OUT" >&2; exit 1;
}
[ "$(wc -l <"$OUT/counts.tsv")" -eq 8 ] || {
  echo "authority matrix did not emit seven cases; evidence retained in $OUT" >&2; exit 1;
}
awk -F '\t' 'NR > 1 && $2 != $3 { bad=1 } END { exit bad }' "$OUT/counts.tsv" || {
  echo "authority outcomes differ from predictions; evidence retained in $OUT" >&2; exit 1;
}
echo "wrote successful authority-boundary VM run to $OUT"
