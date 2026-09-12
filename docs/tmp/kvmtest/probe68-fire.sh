#!/bin/bash
# Focused 6.8 KVM firing probe for the refactored engine.
#
# Answers three questions the full audit's 4s ready deadline cannot:
#   1. Does process_bpf__load ever complete on 6.8 KVM for the refactored
#      engine (no verifier rejection)?
#   2. How long does load+ready take (TIME_TO_READY marker)?
#   3. Do kernel verdicts fire for a declared sink (fire) and stay quiet
#      out-of-policy (quiet), and does the kill effect terminate the trigger?
#
# Uses the same trigger/sink mechanics as docs/empirical-study/run_oas_firing_audit_vm.sh.
set -eu
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
ACT="$ROOT/target/release/actplane"
PROC="$ROOT/bpf/process"
OAS="${OAS_POLICY_DIR:-/workspaces/.agent-state/actplane-research/raw/openagentsafety-policy-compile-20260910T1438Z-verify20260911/tree/docs/OpenAgentSafety/policies/actplane}"
KERNEL="${ACTPLANE_VM_KERNEL:-/boot/vmlinuz-6.8.0-138-generic}"
WORK="$(mktemp -d /tmp/actplane-probe68-fire.XXXXXX)"
trap 'cp "$WORK/console.log" /tmp/probe68-fire-console.log 2>/dev/null || true; rm -rf "$WORK"' EXIT

[ -x "$ACT" ] && [ -x "$PROC" ] && [ -f "$KERNEL" ] || { echo "missing inputs" >&2; exit 2; }

# fire case: safety-applications (write sink), quiet control.
"$ACT" compile --policy "$OAS/safety-applications.yaml" -f -o "$WORK/root_cfg_safety-applications.bin" >/dev/null 2>&1
mkdir -p "$WORK/root"/{bin,dev,proc,sys,tmp,sink,workspace}
cp "$PROC" "$WORK/root/process"
cp "$WORK/root_cfg_safety-applications.bin" "$WORK/root/cfg_safety-applications.bin"
cp /bin/busybox "$WORK/root/bin/busybox"
for applet in sh mount grep sleep kill cat mkdir poweroff true ln awk date; do
  ln -sf busybox "$WORK/root/bin/$applet"
done
{ ldd "$PROC"; } | awk '{for (i=1; i<=NF; i++) if ($i ~ /^\//) print $i}' | sort -u |
  while read -r library; do [ -n "$library" ] && cp --parents "$library" "$WORK/root/"; done

cat > "$WORK/trigger.c" <<'EOF'
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "noop";
    const char *target = argc > 2 ? argv[2] : "";
    if (getenv("SELF_STOP")) { unsetenv("SELF_STOP"); raise(SIGSTOP); }
    if (!strcmp(mode, "write")) {
        int fd = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { fprintf(stderr, "open %s failed\n", target); _exit(4); }
        if (write(fd, "x", 1) != 1) { close(fd); _exit(5); }
        close(fd);
        _exit(0);
    }
    if (!strcmp(mode, "exec")) {
        char path[160];
        snprintf(path, sizeof(path), "/sink/%s", target);
        char *args[] = { (char *)target, NULL };
        char *envp[] = { NULL };
        execve(path, args, envp);
        _exit(6);
    }
    _exit(0);
}
EOF
gcc -static -O2 "$WORK/trigger.c" -o "$WORK/root/trigger"
cat > "$WORK/sink.c" <<'EOF'
int main(void) { return 0; }
EOF
for cmd in crontab dd chmod rm okprog; do
  gcc -static -O2 "$WORK/sink.c" -o "$WORK/root/sink/$cmd"
done

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
mkdir -p /workspace /sink
echo "GUEST_KERNEL $(uname -r)"

run_case() {
  policy="$1" kind="$2" mode="$3" target="$4"
  name="$policy.$kind"
  echo "CASE_BEGIN $name $kind"
  SELF_STOP=1 "/trigger" "$mode" "$target" &
  trigger_pid=$!
  tries=0
  while [ "$tries" -lt 200 ]; do
    state="$(awk '{print $3}' "/proc/$trigger_pid/stat" 2>/dev/null)"
    [ "$state" = T ] && break
    tries=$((tries + 1)); sleep 0.01
  done
  [ "${state:-}" = T ] || { echo "CASE_FAILURE $name trigger-not-stopped"; echo "CASE_END $name"; return; }
  t0=$(date +%s)
  /process --config "/cfg_$policy.bin" --seed-pid "$trigger_pid" >"/tmp/$name.log" 2>&1 &
  loader_pid=$!
  tries=0
  ready=0
  while [ "$tries" -lt 3000 ]; do
    grep -q 'ActPlane: ready' "/tmp/$name.log" && { ready=1; break; }
    kill -0 "$loader_pid" 2>/dev/null || break
    tries=$((tries + 1)); sleep 0.01
  done
  t1=$(date +%s)
  echo "CASE_TIME_TO_READY $name $ready $((t1 - t0))"
  if [ "$ready" -eq 0 ]; then
    cat "/tmp/$name.log"
    echo "CASE_FAILURE $name loader-not-ready"
    kill -CONT "$trigger_pid" 2>/dev/null || true
    kill "$trigger_pid" "$loader_pid" 2>/dev/null || true
    wait "$trigger_pid" 2>/dev/null || true
    wait "$loader_pid" 2>/dev/null || true
    echo "CASE_END $name"
    return
  fi
  kill -CONT "$trigger_pid"
  deadline=$(( $(date +%s) + 8 ))
  while kill -0 "$trigger_pid" 2>/dev/null; do
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 0.05
  done
  if kill -0 "$trigger_pid" 2>/dev/null; then
    kill -9 "$trigger_pid" 2>/dev/null || true
    wait "$trigger_pid" 2>/dev/null || true
    trigger_status=124
  else
    wait "$trigger_pid" 2>/dev/null
    trigger_status=$?
  fi
  verdicts=$(grep -c '"event":"TAINT_VIOLATION"' "/tmp/$name.log" 2>/dev/null || true)
  sleep 1
  kill "$loader_pid" 2>/dev/null || true
  wait "$loader_pid" 2>/dev/null || true
  cat "/tmp/$name.log"
  echo "CASE_TRIGGER $name $trigger_status $kind $verdicts"
  echo "CASE_END $name"
}

run_case safety-applications fire  write /workspace/eval_candidate.py
run_case safety-applications quiet write /workspace/control_ok.txt
echo PROBE68FIRE_DONE
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 > "$WORK/initramfs.gz") 2>/dev/null

echo "=== probe68-fire: kernel=$(basename "$KERNEL") binary=$(sha256sum "$PROC" | cut -c1-12) ==="
timeout 400 qemu-system-x86_64 -accel kvm -m 1024 -smp 2 -nographic -no-reboot \
  -kernel "$KERNEL" -initrd "$WORK/initramfs.gz" \
  -append 'console=ttyS0 rdinit=/init panic=-1' > "$WORK/console.log" 2>/dev/null || true
tr -d '\r' < "$WORK/console.log" > "$WORK/console.clean.log" 2>/dev/null || true
grep -a 'PROBE68FIRE_DONE\|CASE_\|GUEST_KERNEL\|TIME\|verifier\|EACCES\|stack size\|too large\|libbpf:' "$WORK/console.clean.log" 2>/dev/null || echo "PROBE: no markers captured"
cp "$WORK/console.clean.log" /tmp/probe68-fire-console.log 2>/dev/null || true
