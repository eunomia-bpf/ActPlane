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
         "$WORK/root/work/dist/agent-health" "$WORK/root/work/src/lib" \
         "$WORK/root/w/dist/agent-health"

policy='source AGENT = exec "python3"
rule probe_except:
  notify write file "**/*.js" if AGENT unless target "**/dist/**"
  because "probe: repo-relative **/dist/** exception in tracepoint mode"'
sink_policy='source AGENT = exec "python3"
rule probe_sink:
  notify write file "**/dist/**" if AGENT
  because "probe: repo-relative **/dist/** sink in tracepoint mode"'
# A repo-relative directory-anchored *file source*. Reading a matching file
# should label the process, after which the connect sink fires; if the source
# fails to match a relative read, the label never appears and enforcement is
# silently lost (the completeness mirror of the exception/sink rows).
source_policy='source CLI = file "**/src/lib/**"
rule probe_source:
  notify connect endpoint "*" if CLI
  because "probe: repo-relative **/src/lib/** file source in tracepoint mode"'
"$ACT" --rule "$policy" compile --out "$WORK/root/cfg_except.bin" --force >"$OUT/compile.stdout" 2>"$OUT/compile.stderr"
"$ACT" --rule "$sink_policy" compile --out "$WORK/root/cfg_sink.bin" --force >>"$OUT/compile.stdout" 2>>"$OUT/compile.stderr"
"$ACT" --rule "$source_policy" compile --out "$WORK/root/cfg_source.bin" --force >>"$OUT/compile.stdout" 2>>"$OUT/compile.stderr"
printf '%s\n' "$policy" > "$OUT/policy.dsl"
printf '%s\n' "$sink_policy" > "$OUT/sink-policy.dsl"
printf '%s\n' "$source_policy" > "$OUT/source-policy.dsl"
cp "$WORK/root/cfg_except.bin" "$OUT/blob_except.bin"
cp "$WORK/root/cfg_sink.bin" "$OUT/blob_sink.bin"
cp "$WORK/root/cfg_source.bin" "$OUT/blob_source.bin"

cp "$PROC" "$WORK/root/process"
cp /bin/busybox "$WORK/root/bin/busybox"
for a in sh mount grep sleep kill cat mkdir poweroff true ln awk; do ln -sf busybox "$WORK/root/bin/$a"; done
{ ldd "$PROC"; } | awk '{for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i}' | sort -u |
while read -r lib; do [ -n "$lib" ] && cp --parents "$lib" "$WORK/root"; done

# Fixture read by the file-source cases (relative and absolute refer to it).
printf 'fn main() {}\n' > "$WORK/root/work/src/lib/cli.rs"

# The trigger stops itself so the loader can attach, then execs /sink/python3
# (labelled AGENT by the exec source) with a mode and a path. Modes:
#   write <path>         open+write path
#   read_connect <path>  open+read path, then connect to a closed loopback port
cat > "$WORK/trigger.c" <<'EOF'
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "write";
    const char *path = argc > 2 ? argv[2] : "";
    if (getenv("SELF_STOP")) { unsetenv("SELF_STOP"); raise(SIGSTOP); }
    char *args[] = { "python3", (char *)mode, (char *)path, NULL };
    char *envp[] = { NULL };
    execve("/sink/python3", args, envp);
    _exit(6);
}
EOF
gcc -static -O2 "$WORK/trigger.c" -o "$WORK/root/trigger"

cat > "$WORK/sink.c" <<'EOF'
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int do_connect(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(31999) };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    (void)connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return 0;
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "write";
    const char *path = argc > 2 ? argv[2] : "";
    if (!strcmp(mode, "read_connect")) {
        char buf[64];
        int fd = open(path, O_RDONLY);
        if (fd < 0) { perror("open"); _exit(4); }
        if (read(fd, buf, sizeof(buf)) < 0) { close(fd); _exit(5); }
        close(fd);
        do_connect();
        _exit(0);
    }
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
  name="$1" cfg="$2" cwd="$3" mode="$4" path="$5"
  echo "CASE_BEGIN $name"
  ( cd "$cwd" && SELF_STOP=1 /trigger "$mode" "$path" ) &
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
  /process --config "/$cfg" --seed-pid "$trigger_pid" >"/tmp/$name.log" 2>&1 &
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

# Exception policy: repo-relative **/dist/** should exclude the write but cannot.
run_case except_dist_relative cfg_except.bin /work write dist/agent-health/x.js
run_case except_abs_dist      cfg_except.bin /      write /w/dist/agent-health/y.js
run_case except_src_relative  cfg_except.bin /work write src/x.js
# Sink policy: a repo-relative **/dist/** sink should catch the write but cannot
# for a relative path, i.e. the mirror image loses enforcement.
run_case sink_dist_relative   cfg_sink.bin   /work write dist/agent-health/x.js
run_case sink_abs_dist        cfg_sink.bin   /      write /w/dist/agent-health/y.js
# File-source policy: reading a repo-relative **/src/lib/** file should label the
# process so the later connect fires; if the source misses, enforcement is lost.
run_case source_rel_read      cfg_source.bin /work read_connect src/lib/cli.rs
run_case source_abs_read      cfg_source.bin /      read_connect /work/src/lib/cli.rs
echo EXPERIMENT_DONE
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 > "$WORK/initramfs.gz") 2>"$OUT/initramfs.stderr"

# Pre-registered predictions, written before the guest runs. These are the
# verdict counts the mechanism predicts (including the mis-match under test), not
# the desired policy outcome: relative paths are predicted to diverge from their
# absolute twin in both directions. The comparison therefore checks the mechanism
# reproduces as diagnosed, and the note interprets which rows are the bug.
printf '%s\t%s\n' case predicted_verdicts > "$OUT/expectations.tsv"
printf '%s\t%s\n' except_dist_relative 1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' except_abs_dist      0 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' except_src_relative  1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' sink_dist_relative   0 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' sink_abs_dist        1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' source_rel_read      0 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' source_abs_read      1 >> "$OUT/expectations.tsv"

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

# Combined view: pre-registered prediction next to the observation.
{
  printf '%s\t%s\t%s\n' case predicted_verdicts observed_verdicts
  join -t$'\t' -j1 <(tail -n +2 "$OUT/expectations.tsv" | sort) <(tail -n +2 "$OUT/counts.tsv" | sort)
} > "$OUT/summary.tsv"

{
  printf '%s\n' "timestamp_utc $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s\n' "host_git_commit $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo no-git)"
  printf '%s\n' "guest_kernel $(basename "$KERNEL")"
  printf '%s\n' "acceleration $accel"
  printf '%s\n' "process_bin_sha256 $(sha256sum "$PROC" | cut -d' ' -f1)"
  printf '%s\n' "except_policy_sha256 $(sha256sum "$OUT/policy.dsl" | cut -d' ' -f1)"
  printf '%s\n' "sink_policy_sha256 $(sha256sum "$OUT/sink-policy.dsl" | cut -d' ' -f1)"
  printf '%s\n' "source_policy_sha256 $(sha256sum "$OUT/source-policy.dsl" | cut -d' ' -f1)"
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
