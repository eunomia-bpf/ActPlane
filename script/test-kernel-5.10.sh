#!/usr/bin/env bash
# Build and smoke-test the host binary in a Linux 5.10 KVM guest.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL_DIR="${1:-${ACTPLANE_LINUX_510:-}}"
[ -n "$KERNEL_DIR" ] || { echo "usage: $0 /path/to/linux-5.10-source" >&2; exit 2; }
KERNEL_DIR="$(cd "$KERNEL_DIR" && pwd)"
IMAGE="$KERNEL_DIR/arch/x86/boot/bzImage"

release="$(make -s -C "$KERNEL_DIR" kernelrelease)"
[[ "$release" == 5.10.* ]] || { echo "expected Linux 5.10, got $release" >&2; exit 2; }

if [ ! -f "$IMAGE" ] || [ "${ACTPLANE_REBUILD_KERNEL:-0}" = 1 ]; then
  pushd "$KERNEL_DIR" >/dev/null
  vng --build --skip-modules \
    --configitem CONFIG_BPF=y --configitem CONFIG_BPF_SYSCALL=y \
    --configitem CONFIG_BPF_JIT=y --configitem CONFIG_BPF_EVENTS=y \
    --configitem CONFIG_CGROUP_BPF=y --configitem CONFIG_PERF_EVENTS=y \
    --configitem CONFIG_KPROBES=y --configitem CONFIG_UPROBES=y \
    --configitem CONFIG_FTRACE_SYSCALLS=y --configitem CONFIG_SECURITY=y \
    --configitem CONFIG_SECURITYFS=y --configitem CONFIG_BPF_LSM=y \
    --configitem CONFIG_DEBUG_INFO=y --configitem CONFIG_DEBUG_INFO_DWARF4=y \
    --configitem CONFIG_DEBUG_INFO_BTF=y
  popd >/dev/null
fi

cargo build --locked --release -p actplane --manifest-path "$ROOT/Cargo.toml"

mkdir -p "$ROOT/target"
policy="$(mktemp "$ROOT/target/actplane-5.10-policy.XXXXXX")"
report="$(mktemp "$ROOT/target/actplane-5.10-report.XXXXXX")"
trap 'rm -f "$policy" "$report"' EXIT

cat >"$policy" <<'EOF'
source COMMAND = exec "**"
rule linux-5-10-smoke:
  notify exec "true" if COMMAND
  because "Linux 5.10 compatibility smoke matched"
EOF
chmod 644 "$policy"
chmod 666 "$report"

guest="set -eu; { echo kernel=\$(uname -r); test -r /sys/kernel/btf/vmlinux; \
  timeout 45 '$ROOT/target/release/actplane' --rule \"\$(cat '$policy')\" run /usr/bin/true; \
  } >'$report' 2>&1"

vng --run "$IMAGE" \
  --user root \
  --cpus "${ACTPLANE_KVM_CPUS:-2}" \
  --memory "${ACTPLANE_KVM_MEMORY:-4G}" \
  --cwd "$ROOT" \
  --rwdir "$ROOT/target" \
  --exec "$guest"

cat "$report"
grep -q '^kernel=5\.10\.' "$report"
for text in 'effect: notify' 'reason: Linux 5.10 compatibility smoke matched' 'static exec-only policy'; do
  grep -q "$text" "$report"
done

echo "== Linux 5.10 KVM smoke passed =="
