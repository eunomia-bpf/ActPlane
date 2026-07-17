#!/usr/bin/env bash
# Build (when needed) and boot a Linux 5.10 tree, then run the host-built
# ActPlane binary against a static compatibility policy inside the KVM guest.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL_DIR="${1:-${ACTPLANE_LINUX_510:-}}"

if [ -z "$KERNEL_DIR" ]; then
  echo "usage: $0 /path/to/linux-5.10-source" >&2
  echo "or set ACTPLANE_LINUX_510" >&2
  exit 2
fi
KERNEL_DIR="$(cd "$KERNEL_DIR" && pwd)"
IMAGE="$KERNEL_DIR/arch/x86/boot/bzImage"

for command in cargo grep make timeout vng; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 2
  }
done

release="$(make -s -C "$KERNEL_DIR" kernelrelease)"
case "$release" in
  5.10.*) ;;
  *)
    echo "expected a Linux 5.10 source tree, got kernelrelease $release" >&2
    exit 2
    ;;
esac

if [ ! -f "$IMAGE" ] || [ "${ACTPLANE_REBUILD_KERNEL:-0}" = 1 ]; then
  echo "== building Linux $release with ActPlane KVM prerequisites =="
  (
    cd "$KERNEL_DIR"
    vng --build --skip-modules \
      --configitem CONFIG_BPF=y \
      --configitem CONFIG_BPF_SYSCALL=y \
      --configitem CONFIG_BPF_JIT=y \
      --configitem CONFIG_BPF_EVENTS=y \
      --configitem CONFIG_CGROUP_BPF=y \
      --configitem CONFIG_PERF_EVENTS=y \
      --configitem CONFIG_KPROBES=y \
      --configitem CONFIG_UPROBES=y \
      --configitem CONFIG_FTRACE_SYSCALLS=y \
      --configitem CONFIG_SECURITY=y \
      --configitem CONFIG_SECURITYFS=y \
      --configitem CONFIG_BPF_LSM=y \
      --configitem CONFIG_DEBUG_INFO=y \
      --configitem CONFIG_DEBUG_INFO_DWARF4=y \
      --configitem CONFIG_DEBUG_INFO_BTF=y
  )
fi

for config in CONFIG_BPF=y CONFIG_BPF_SYSCALL=y CONFIG_DEBUG_INFO_BTF=y; do
  grep -qx "$config" "$KERNEL_DIR/.config" || {
    echo "kernel config is missing $config" >&2
    exit 2
  }
done

echo "== building ActPlane on the host =="
cargo build --locked --release -p actplane --manifest-path "$ROOT/Cargo.toml"

mkdir -p "$ROOT/target"
policy="$(mktemp "$ROOT/target/actplane-5.10-policy.XXXXXX")"
report="$(mktemp "$ROOT/target/actplane-5.10-report.XXXXXX")"
host_log="$(mktemp "${TMPDIR:-/tmp}/actplane-5.10-vng.XXXXXX")"
cleanup() {
  rm -f "$policy" "$report" "$host_log"
}
trap cleanup EXIT

cat >"$policy" <<'EOF'
source COMMAND = exec "**"
rule linux-5-10-smoke:
  notify exec "true" if COMMAND
  because "Linux 5.10 compatibility smoke matched"
EOF
chmod 644 "$policy"
chmod 666 "$report"

guest_command="set -eu; { \
echo kernel=\$(uname -r); \
echo memlock_before=\$(ulimit -l); \
test -r /sys/kernel/btf/vmlinux; \
echo btf=present; \
timeout 45 '$ROOT/target/release/actplane' --rule \"\$(cat '$policy')\" run /usr/bin/true; \
} >'$report' 2>&1"

echo "== booting $release and running compatibility smoke =="
if ! vng --run "$IMAGE" \
  --user root \
  --cpus "${ACTPLANE_KVM_CPUS:-2}" \
  --memory "${ACTPLANE_KVM_MEMORY:-4G}" \
  --cwd "$ROOT" \
  --rwdir "$ROOT/target" \
  --exec "$guest_command" >"$host_log" 2>&1; then
  cat "$report" >&2
  tail -n 40 "$host_log" >&2
  exit 1
fi

cat "$report"
assert_report() {
  local pattern="$1"
  if ! grep -q "$pattern" "$report"; then
    echo "guest report is missing pattern: $pattern" >&2
    tail -n 40 "$host_log" >&2
    exit 1
  fi
}
assert_report '^kernel=5\.10\.'
assert_report '^btf=present$'
assert_report 'effect: notify'
assert_report 'reason: Linux 5.10 compatibility smoke matched'
assert_report 'static startup policy'

echo "== Linux 5.10 KVM smoke passed =="
