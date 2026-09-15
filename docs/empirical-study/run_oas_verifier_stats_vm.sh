#!/bin/bash
# Capture per-program verifier statistics for the ActPlane engine on a guest
# kernel that enforces the summed-subprogram-stack limit (Linux 6.8).
#
# The production workload claims that every BPF program in the engine skeleton
# loads on a 6.8 kernel. The host container cannot load BPF (seccomp denies
# bpf()), and the host kernel (7.x) does not perform the combined-stack walk
# that 6.8 does, so the only authoritative measurement is a guest boot.
#
# This runner boots a minimal guest with the diagnostic `vvload` loader (the
# same process skeleton as the production `process` binary, but loading one
# program per process_bpf__load with a level-1 verifier log). It records, per
# program, the verified instruction total and the absence of any rejection
# ("Too large", "invalid mem access"). The result is supporting evidence for
# the firing audit (run_oas_firing_audit_vm.sh), not a correctness claim of its
# own.
#
# Required input: OAS_POLICY_DIR must point at the frozen OpenAgentSafety
# `policies/actplane` directory (there is no portable default; the inventory
# lives outside this repository). Optional knobs: ACTPLANE_VVLOAD_BIN,
# ACTPLANE_BIN, ACTPLANE_VM_KERNEL, ACTPLANE_POLICY, ACTPLANE_VM_TIMEOUT.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VV="${ACTPLANE_VVLOAD_BIN:-$ROOT/bpf/vvload}"
ACT="${ACTPLANE_BIN:-$ROOT/target/release/actplane}"
KERNEL="${ACTPLANE_VM_KERNEL:-$(ls -1 /boot/vmlinuz-*-generic 2>/dev/null | tail -1)}"
OAS="${OAS_POLICY_DIR:-}"
OUT="${1:-$ROOT/docs/empirical-study/results/oas-verifier-stats-vm}"
POLICY="${ACTPLANE_POLICY:-safety-applications}"
# A level-1 verifier log for the deepest programs is large and TCG is slow, so
# the wall-clock bound is a knob.
VM_TIMEOUT="${ACTPLANE_VM_TIMEOUT:-300}"
WORK="$(mktemp -d /tmp/actplane-oas-verifier-vm.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

[ -n "$KERNEL" ] || { echo "set ACTPLANE_VM_KERNEL to a guest vmlinuz (no /boot/vmlinuz-*-generic found)" >&2; exit 2; }
for file in "$VV" "$ACT" "$KERNEL" /bin/busybox; do
  [ -e "$file" ] || { echo "missing $file" >&2; exit 2; }
done
[ -n "$OAS" ] || { echo "set OAS_POLICY_DIR to the OpenAgentSafety policies/actplane directory" >&2; exit 2; }
[ -f "$OAS/$POLICY.yaml" ] || { echo "missing policy $OAS/$POLICY.yaml" >&2; exit 2; }
for command in qemu-system-x86_64 cpio; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }
done

mkdir -p "$OUT" "$WORK/root"/{bin,dev,proc,sys,tmp,workspace}

# Host-side: compile the policy exactly as the firing audit does.
"$ACT" --policy "$OAS/$POLICY.yaml" compile --out "$WORK/root/cfg.bin" --force >/dev/null

cp "$WORK/root/cfg.bin" "$OUT/blob_$POLICY.bin"

# Loader + busybox applets + its shared libraries into the guest.
cp "$VV" "$WORK/root/vvload"
cp /bin/busybox "$WORK/root/bin/busybox"
for applet in sh mount sleep cat poweroff true ln; do
  ln -sf busybox "$WORK/root/bin/$applet"
done
{ ldd "$VV"; } | awk '{for (i=1; i<=NF; i++) if ($i ~ /^\//) print $i}' | sort -u |
while read -r library; do [ -n "$library" ] && cp --parents "$library" "$WORK/root"; done

cat > "$WORK/root/init" <<'EOF'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
dmesg -n 1 2>/dev/null || true
echo "=====VLOAD_START====="
/vvload --config /cfg.bin --seed-pid 1 2>&1
echo "=====VLOAD_END====="
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 > "$WORK/initramfs.gz") 2>"$OUT/initramfs.stderr"

run_qemu() {
  timeout "$VM_TIMEOUT" qemu-system-x86_64 -accel "$1" -m 2048 -smp 2 -nographic -no-reboot \
    -kernel "$KERNEL" -initrd "$WORK/initramfs.gz" \
    -append 'console=ttyS0 rdinit=/init panic=-1' >"$OUT/console.log" 2>"$OUT/qemu.stderr"
}

set +e
acceleration=kvm
run_qemu "$acceleration"; qemu_status=$?
if [ "$qemu_status" -ne 0 ] && ! grep -q '^=====VLOAD_END=====' "$OUT/console.log"; then
  echo "kvm attempt failed; retrying with tcg" >&2
  acceleration=tcg
  run_qemu "$acceleration"; qemu_status=$?
fi
set -e
tr -d '\r' < "$OUT/console.log" > "$OUT/console.clean.log"

# Per-program verified instruction totals.
{
  printf 'program\tprocessed_insns\tmax_states_per_insn\ttotal_states\tpeak_states\tmark_read\n'
  grep -oE "VSTAT [^ ]+ processed [0-9]+ insns \(limit 1000000\) max_states_per_insn [0-9]+ total_states [0-9]+ peak_states [0-9]+ mark_read [0-9]+" \
    "$OUT/console.clean.log" \
  | sed -E 's/VSTAT ([^ ]+) processed ([0-9]+) insns \(limit 1000000\) max_states_per_insn ([0-9]+) total_states ([0-9]+) peak_states ([0-9]+) mark_read ([0-9]+)/\1\t\2\t\3\t\4\t\5\t\6/'
} > "$OUT/verifier-stats.tsv"

grep -E 'VSTAT|VLOAD_DONE|Too large|invalid mem access' "$OUT/console.clean.log" > "$OUT/verifier-console.txt" || true

grep -q '^=====VLOAD_END=====' "$OUT/console.clean.log" || { echo "verifier run did not complete (no VLOAD_END marker)" >&2; exit 1; }

# Exactly one summary line, and it must report zero failed programs with a
# non-empty program set. A missing or ambiguous summary, or any nonzero fail
# count, means a program was rejected and the measurement does not stand.
done_lines="$(grep -c '^VLOAD_DONE ' "$OUT/console.clean.log" || true)"
[ "$done_lines" -eq 1 ] || { echo "expected exactly one VLOAD_DONE line, found $done_lines" >&2; exit 1; }
summary="$(grep '^VLOAD_DONE ' "$OUT/console.clean.log")"
# shellcheck disable=SC2086
set -- ${summary#VLOAD_DONE }
ok=0 fail=- total=0
for field in "$@"; do
  case "$field" in
    ok=*) ok=${field#ok=} ;;
    fail=*) fail=${field#fail=} ;;
    total=*) total=${field#total=} ;;
  esac
done
case "$ok$fail$total" in
  *[!0-9]*|'') echo "unparseable VLOAD_DONE summary: $summary" >&2; exit 1 ;;
esac
[ "$total" -gt 0 ] || { echo "VLOAD_DONE reports zero programs: $summary" >&2; exit 1; }
[ "$fail" -eq 0 ] || { echo "VLOAD_DONE reports $fail failed program(s): $summary" >&2; exit 1; }
[ "$ok" -eq "$total" ] || { echo "VLOAD_DONE ok/total mismatch: $summary" >&2; exit 1; }

{
  printf '%s\n' "timestamp_utc $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s\n' "host_git_commit $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  printf '%s\n' "guest_kernel $(basename "$KERNEL")"
  printf '%s\n' "acceleration $acceleration"
  printf '%s\n' "policy $POLICY.yaml"
  printf '%s\n' "policy_sha256 $(sha256sum "$OAS/$POLICY.yaml" | cut -d' ' -f1)"
  printf '%s\n' "actplane_bin_sha256 $(sha256sum "$ACT" | cut -d' ' -f1)"
  printf '%s\n' "vvload_bin_sha256 $(sha256sum "$VV" | cut -d' ' -f1)"
  # The loader binary is the identity of the build under test; note whether its
  # source carried changes on top of host_git_commit.
  if [ -n "$(git -C "$ROOT" status --porcelain -- bpf/vvload.c bpf/policy_features.h 2>/dev/null)" ]; then
    printf '%s\n' "loader_source_dirty yes"
  else
    printf '%s\n' "loader_source_dirty no"
  fi
  printf '%s\n' "vload_done $summary"
} > "$OUT/metadata.tsv"

if grep -qE 'Too large|invalid mem access' "$OUT/console.clean.log"; then
  echo "verifier rejected one or more programs:" >&2
  grep -E 'Too large|invalid mem access' "$OUT/console.clean.log" >&2
  exit 1
fi
if grep -q '^VLOAD_FAIL ' "$OUT/console.clean.log"; then
  echo "vvload reported a load failure:" >&2
  grep '^VLOAD_FAIL ' "$OUT/console.clean.log" >&2
  exit 1
fi

# Every program must have contributed a stats row: a program that loaded but
# emitted no VSTAT line would silently drop out of the instruction table.
stat_rows="$(awk -F '\t' 'NR > 1' "$OUT/verifier-stats.tsv" | wc -l)"
[ "$stat_rows" -eq "$total" ] || { echo "verifier-stats.tsv has $stat_rows rows, expected $total" >&2; exit 1; }
echo "wrote verifier statistics to $OUT ($ok/$total programs, 0 failures)"
