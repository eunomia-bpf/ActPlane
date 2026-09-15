#!/bin/bash
# Probe: does a repo-relative directory-anchored `unless target` exception
# actually exclude writes in tracepoint mode?
#
# Context. The RQ2 false-positive audit (`rq2-fp-attribution.md`) attributes the
# NemoClaw `s02_no_new_javascript_sources` FP to over-broad path matching. In
# tracepoint mode the kernel matches the file path read from the userspace path
# argument (`TE_REF_USER_PATH`), which is relative when a tool passes a relative
# path. The compiler lowers the repo-relative `**/dist/**` exception to
# `contains("/dist/")`, which requires a slash before `dist` and so cannot match
# a relative `dist/...` path.
#
# This probe runs the frozen policy shape against three writes by an
# AGENT-labelled (`exec python3`) trigger, in a KVM/TCG guest with BPF:
#
#   dist_relative   write dist/agent-health/x.js    -> predicted verdicts: 1
#   abs_dist        write /w/dist/agent-health/y.js -> predicted verdicts: 0
#   src_relative    write src/x.js                  -> predicted verdicts: 1
#
# All expectations are pre-registered below before the guest boots.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ACT="${ACTPLANE_BIN:-$ROOT/target/release/actplane}"
PROC="${ACTPLANE_PROCESS_BIN:-$ROOT/bpf/process}"
KERNEL="${ACTPLANE_VM_KERNEL:-$(ls -1 /boot/vmlinuz-*-generic 2>/dev/null | tail -1)}"
OUT="${1:-$ROOT/docs/empirical-study/results/rq2-except-probe-vm}"
VM_TIMEOUT="${ACTPLANE_VM_TIMEOUT:-900}"
WORK="$(mktemp -d /tmp/actplane-except-probe.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

[ -n "$KERNEL" ] || { echo "set ACTPLANE_VM_KERNEL to a guest vmlinuz" >&2; exit 2; }
for f in "$ACT" "$PROC" "$KERNEL" /bin/busybox; do
  [ -e "$f" ] || { echo "missing $f" >&2; exit 2; }
done
for c in qemu-system-x86_64 cpio gcc; do
  command -v "$c" >/dev/null || { echo "missing $c" >&2; exit 2; }
done

mkdir -p "$OUT" "$WORK/root"/{bin,dev,proc,sys,tmp,sink} \
         "$WORK/root/work/dist/agent-health" "$WORK/root/work/src" \
         "$WORK/root/w/dist/agent-health"

policy='source AGENT = exec "python3"
rule probe:
  notify write file "**/*.js" if AGENT unless target "**/dist/**"
  because "probe: repo-relative **/dist/** exception in tracepoint mode"'
"$ACT" --rule "$policy" compile --out "$WORK/root/cfg.bin" --force >"$OUT/compile.stdout" 2>"$OUT/compile.stderr"
printf '%s\n' "$policy" > "$OUT/policy.dsl"
cp "$WORK/root/cfg.bin" "$OUT/blob.bin"

cp "$PROC" "$WORK/root/process"
cp /bin/busybox "$WORK/root/bin/busybox"
for a in sh mount grep sleep kill cat mkdir poweroff true ln awk; do ln -sf busybox "$WORK/root/bin/$a"; done
{ ldd "$PROC"; } | awk '{for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i}' | sort -u |
while read -r lib; do [ -n "$lib" ] && cp --parents "$lib" "$WORK/root"; done

# The trigger stops itself so the loader can attach, then execs /sink/python3
# (labelled AGENT by the exec source) which writes the requested relative path.
cat > "$WORK/trigger.c" <<'EOF'
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "";
    if (getenv("SELF_STOP")) { unsetenv("SELF_STOP"); raise(SIGSTOP); }
    char *args[] = { "python3", (char *)path, NULL };
    char *envp[] = { NULL };
    execve("/sink/python3", args, envp);
    _exit(6);
}
EOF
gcc -static -O2 "$WORK/trigger.c" -o "$WORK/root/trigger"

cat > "$WORK/sink.c" <<'EOF'
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); _exit(4); }
    if (write(fd, "x", 1) != 1) { close(fd); _exit(5); }
    close(fd);
    _exit(0);
}
EOF
gcc -static -O2 "$WORK/sink.c" -o "$WORK/root/sink/python3"

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
mkdir -p /tmp

run_case() {
  name="$1" cwd="$2" path="$3"
  echo "CASE_BEGIN $name"
  ( cd "$cwd" && SELF_STOP=1 /trigger "$path" ) &
  trigger_pid=$!
  tries=0
  while [ "$tries" -lt 200 ]; do
    state="$(awk '{print $3}' "/proc/$trigger_pid/stat" 2>/dev/null)"
    [ "$state" = T ] && break
    tries=$((tries + 1)); sleep 0.05
  done
  if [ "${state:-}" != T ]; then
    echo "CASE_FAILURE $name trigger-not-stopped"
    echo "CASE_END $name"
    return
  fi
  /process --config /cfg.bin --seed-pid "$trigger_pid" >"/tmp/$name.log" 2>&1 &
  loader_pid=$!
  tries=0
  while [ "$tries" -lt 4000 ]; do
    grep -q 'ActPlane: ready' "/tmp/$name.log" && break
    kill -0 "$loader_pid" 2>/dev/null || break
    tries=$((tries + 1)); sleep 0.01
  done
  if ! grep -q 'ActPlane: ready' "/tmp/$name.log"; then
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
  sleep 1
  kill "$loader_pid" 2>/dev/null || true
  wait "$loader_pid" 2>/dev/null || true
  cat "/tmp/$name.log"
  echo "CASE_TRIGGER $name $trigger_status"
  echo "CASE_END $name"
}

run_case dist_relative /work dist/agent-health/x.js
run_case abs_dist      /      /w/dist/agent-health/y.js
run_case src_relative  /work src/x.js
echo EXPERIMENT_DONE
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 > "$WORK/initramfs.gz") 2>"$OUT/initramfs.stderr"

# Pre-registered expectations, written before the guest runs.
printf '%s\t%s\n' case expected_verdicts > "$OUT/expectations.tsv"
printf '%s\t%s\n' dist_relative 1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' abs_dist 0 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' src_relative 1 >> "$OUT/expectations.tsv"

run_qemu() {
  timeout "$VM_TIMEOUT" qemu-system-x86_64 -accel "$1" -m 1024 -smp 2 -nographic -no-reboot \
    -kernel "$KERNEL" -initrd "$WORK/initramfs.gz" \
    -append 'console=ttyS0 rdinit=/init panic=-1' >"$OUT/console.log" 2>"$OUT/qemu.stderr"
}
set +e
accel=kvm
run_qemu "$accel"; qs=$?
if [ "$qs" -ne 0 ] && ! grep -q '^EXPERIMENT_DONE' "$OUT/console.log"; then
  echo "kvm attempt failed; retrying with tcg" >&2
  accel=tcg
  run_qemu "$accel"; qs=$?
fi
set -e
tr -d '\r' < "$OUT/console.log" > "$OUT/console.clean.log"
cp "$OUT/console.clean.log" "$OUT/guest-console.txt"

printf '%s\t%s\n' case observed_verdicts > "$OUT/counts.tsv"
awk '
  /^CASE_BEGIN / { name=$2; observed=0; next }
  /"event":"TAINT_VIOLATION"/ { observed++ }
  /^CASE_END / { print name "\t" observed }
' "$OUT/console.clean.log" >> "$OUT/counts.tsv"

# Combined view: pre-registered expectation next to the observation.
{
  printf '%s\t%s\t%s\n' case expected_verdicts observed_verdicts
  join -t$'\t' -j1 <(tail -n +2 "$OUT/expectations.tsv" | sort) <(tail -n +2 "$OUT/counts.tsv" | sort)
} > "$OUT/summary.tsv"

{
  printf '%s\n' "timestamp_utc $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s\n' "host_git_commit $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo no-git)"
  printf '%s\n' "guest_kernel $(basename "$KERNEL")"
  printf '%s\n' "acceleration $accel"
  printf '%s\n' "process_bin_sha256 $(sha256sum "$PROC" | cut -d' ' -f1)"
  printf '%s\n' "policy_sha256 $(sha256sum "$OUT/policy.dsl" | cut -d' ' -f1)"
} > "$OUT/metadata.tsv"

grep -q '^EXPERIMENT_DONE' "$OUT/console.clean.log" || { echo "guest experiment did not complete" >&2; exit 1; }
if grep -q '^CASE_FAILURE ' "$OUT/console.clean.log"; then
  echo "case harness failure detected:" >&2
  grep '^CASE_FAILURE ' "$OUT/console.clean.log" >&2 || true
  exit 1
fi

# Fail closed: observed verdicts must equal the pre-registered expectations.
fail=0
awk -F '\t' 'NR>1 && $2 != $3 { bad=1 } END { exit bad }' "$OUT/summary.tsv" || fail=1
[ "$fail" -eq 0 ] || { echo "observed verdicts differ from pre-registered expectations" >&2; exit 1; }
echo "wrote exception-probe results to $OUT"
