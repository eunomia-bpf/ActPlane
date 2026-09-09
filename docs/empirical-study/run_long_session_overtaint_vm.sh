#!/bin/bash
# Run the long-session experiment in a minimal KVM/TCG guest with BPF privilege.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ACT="${ACTPLANE_BIN:-$ROOT/target/release/actplane}"
PROC="${ACTPLANE_PROCESS_BIN:-$ROOT/bpf/process}"
KERNEL="${ACTPLANE_VM_KERNEL:-$(ls -1 /boot/vmlinuz-*-generic | tail -1)}"
OUT="${1:-$ROOT/docs/empirical-study/results/long-session-overtaint-vm}"
WORK="$(mktemp -d /tmp/actplane-long-session-vm.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

for file in "$ACT" "$PROC" "$KERNEL" /bin/busybox; do
  [ -e "$file" ] || { echo "missing $file" >&2; exit 2; }
done
for command in qemu-system-x86_64 cpio gcc; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }
done
mkdir -p "$OUT" "$WORK/root"/{bin,dev,proc,sys,tmp}

policy='source SECRET = exec "reader"
rule long-session-no-egress:
  notify connect endpoint "*" if SECRET
  because "A process lineage that has read a secret remains in sensitive context"'
"$ACT" --rule "$policy" compile --out "$WORK/root/config.bin" --force >"$OUT/compile.stdout" 2>"$OUT/compile.stderr"
printf '%s\n' "$policy" > "$OUT/policy.dsl"
cp "$PROC" "$WORK/root/process"
cp "$ACT" "$WORK/root/actplane"
cp /bin/busybox "$WORK/root/bin/busybox"
for applet in sh mount grep sleep kill cat mkdir seq awk poweroff; do ln -s busybox "$WORK/root/bin/$applet"; done

# Copy the loader's dynamic linker and shared libraries into the guest.
{ ldd "$PROC"; ldd "$ACT"; } | awk '{for (i=1; i<=NF; i++) if ($i ~ /^\//) print $i}' | sort -u |
while read -r library; do cp --parents "$library" "$WORK/root"; done
{
  echo 'version: 1'
  echo 'policy: |'
  printf '%s\n' "$policy" | sed 's/^/  /'
} > "$WORK/root/policy.yaml"

cat > "$WORK/trigger.c" <<'EOF'
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void connect_n(int n) {
    for (int i = 0; i < n; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = { .sin_family = AF_INET,
            .sin_port = htons((unsigned short)(31000 + i)) };
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        (void)connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        close(fd);
    }
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "clean";
    int n = argc > 2 ? atoi(argv[2]) : 1;
    if (getenv("SELF_STOP")) { unsetenv("SELF_STOP"); raise(SIGSTOP); }
    if (!strcmp(mode, "clean")) connect_n(n);
    else if (!strcmp(mode, "same")) connect_n(n);
    else if (!strcmp(mode, "sibling")) {
        pid_t child = fork();
        if (child == 0) { execl("/reader", "reader", "read-only", "0", NULL); _exit(3); }
        waitpid(child, 0, 0); connect_n(n);
    } else if (!strcmp(mode, "descendant")) {
        pid_t child = fork();
        if (child == 0) { connect_n(n); _exit(0); }
        waitpid(child, 0, 0);
    } else return 2;
    return 0;
}
EOF
gcc -static -O2 "$WORK/trigger.c" -o "$WORK/root/trigger"
cp "$WORK/root/trigger" "$WORK/root/reader"
cp "$WORK/root/trigger" "$WORK/root/control"

cat > "$WORK/root/init" <<'EOF'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

run_case() {
  name="$1" executable="$2" mode="$3" count="$4" expected="$5" seed_label="$6"
  echo "CASE_BEGIN $name $expected"
  SELF_STOP=1 "/$executable" "$mode" "$count" &
  trigger_pid=$!
  tries=0
  while [ "$tries" -lt 200 ]; do
    state="$(awk '{print $3}' "/proc/$trigger_pid/stat" 2>/dev/null)"
    [ "$state" = T ] && break
    tries=$((tries + 1)); sleep 0.01
  done
  if [ "$state" != T ]; then
    echo "CASE_FAILURE $name trigger-not-stopped"
    echo "CASE_END $name"
    return
  fi
  if [ "$seed_label" = none ]; then
    /process --config /config.bin --seed-pid "$trigger_pid" >"/tmp/$name.log" 2>&1 &
  else
    /process --config /config.bin --seed-pid "$trigger_pid" --seed-label "$seed_label" >"/tmp/$name.log" 2>&1 &
  fi
  loader_pid=$!
  tries=0
  while [ "$tries" -lt 400 ]; do
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
  wait "$trigger_pid" 2>/dev/null || true
  sleep 1
  kill "$loader_pid" 2>/dev/null || true
  wait "$loader_pid" 2>/dev/null || true
  cat "/tmp/$name.log"
  echo "CASE_END $name"
}

run_case clean_pre_label control clean 5 0 none
run_case same_lineage_1 reader same 1 1 1
run_case same_lineage_5 reader same 5 5 1
run_case same_lineage_20 reader same 20 20 1
run_case sibling_after_labeled_exit control sibling 5 0 none
run_case descendant_after_label_5 reader descendant 5 5 1
echo EXPERIMENT_DONE
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 > "$WORK/initramfs.gz") 2>"$OUT/initramfs.stderr"

run_qemu() {
  timeout 300 qemu-system-x86_64 -accel "$1" -m 1024 -smp 2 -nographic -no-reboot \
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
tr -d '\r' < "$OUT/console.log" > "$OUT/console.clean.log"

printf '%s\t%s\t%s\n' case expected_interventions observed_interventions > "$OUT/counts.tsv"
awk '
  /^CASE_BEGIN / { name=$2; expected=$3; observed=0; next }
  /"event":"TAINT_VIOLATION"/ { observed++ }
  /^CASE_END / { print name "\t" expected "\t" observed }
' "$OUT/console.clean.log" >> "$OUT/counts.tsv"
{
  printf 'timestamp_utc\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'git_commit\t%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
  printf 'host_kernel\t%s\n' "$(uname -r)"
  printf 'guest_kernel\t%s\n' "$(basename "$KERNEL" | sed 's/^vmlinuz-//')"
  printf 'acceleration\t%s\n' "$acceleration"
  printf 'qemu_status\t%s\n' "$qemu_status"
  printf 'policy_sha256\t%s\n' "$(printf '%s' "$policy" | sha256sum | cut -d' ' -f1)"
} > "$OUT/metadata.tsv"

grep -q '^EXPERIMENT_DONE' "$OUT/console.clean.log" || { echo "guest experiment did not complete" >&2; exit 1; }
if grep -q '^CASE_FAILURE ' "$OUT/console.clean.log"; then
  echo "one or more ActPlane cases failed before producing valid observations" >&2
  exit 1
fi
awk -F '\t' 'NR > 1 && $2 != $3 { bad=1 } END { exit bad }' "$OUT/counts.tsv" || {
  echo "observed counts differ from preregistered predictions" >&2; exit 1;
}
echo "wrote successful VM run to $OUT"
