#!/bin/bash
# OpenAgentSafety policy firing audit in a KVM/TCG guest with BPF privilege.
#
# For a frozen set of OpenAgentSafety policies (the "50 final" blockable
# inventory), each policy declares OS-observable sinks (kill-write to a file,
# kill-exec of a command). This runner boots a minimal KVM guest, and for each
# policy attaches the eBPF engine against a canonical trigger that performs the
# declared sink (a "fire" case) and, separately, an out-of-policy operation
# (a "quiet" control case). It asserts the kernel verdict semantics:
#   - the declared-sink case emits >=1 TAINT_VIOLATION and the kill effect
#     terminates the trigger (exit 137);
#   - the out-of-policy control case emits exactly 0 verdicts and the trigger
#     exits cleanly (0);
# i.e. the policy fires on its declared sink and stays quiet out-of-policy.
# Expectations are pre-registered from the policy YAMLs + engine semantics
# (written to the results dir before the guest runs), not read off the run.
#
# Required input: OAS_POLICY_DIR must point at the frozen OpenAgentSafety
# `policies/actplane` directory (there is no portable default; the inventory
# lives outside this repository). Optional knobs: ACTPLANE_BIN,
# ACTPLANE_PROCESS_BIN, ACTPLANE_VM_KERNEL, ACTPLANE_VM_TIMEOUT.
#
# This is a live verdict-firing audit, not a per-task end-to-end or baseline
# outcome. It establishes that the frozen OAS policies, as compiled by the
# pinned ActPlane binary, produce kernel verdicts with the expected specificity.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ACT="${ACTPLANE_BIN:-$ROOT/target/release/actplane}"
PROC="${ACTPLANE_PROCESS_BIN:-$ROOT/bpf/process}"
# Restrict the default to a 6.8 guest: the recorded `guest_kernel` and the
# results note are both a 6.8 measurement, so the lexicographically-newest
# generic kernel is the wrong default. On a host whose `/boot` carries a newer
# generic kernel this silently boots it, records it as `guest_kernel`, and
# measures a kernel where the 6.8 summed-subprogram-stack limit does not apply.
KERNEL="${ACTPLANE_VM_KERNEL:-$(ls -1 /boot/vmlinuz-6.8.*-generic 2>/dev/null | tail -1)}"
OAS="${OAS_POLICY_DIR:-}"
OUT="${1:-$ROOT/docs/empirical-study/results/oas-firing-audit-vm}"
# TCG execution is far slower than KVM, so the qemu wall-clock timeout is a
# knob. A measured full TCG run (18 policy load/attach/trigger cycles after
# boot) took 320s, so the old 300s default expired mid-experiment and truncated
# the run on exactly the fallback path this host uses. Default with headroom to
# the value the results note documents, and let the operator override.
VM_TIMEOUT="${ACTPLANE_VM_TIMEOUT:-2400}"
WORK="$(mktemp -d /tmp/actplane-oas-firing-vm.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

[ -n "$KERNEL" ] || { echo "set ACTPLANE_VM_KERNEL to a 6.8 guest vmlinuz (no /boot/vmlinuz-6.8.*-generic found)" >&2; exit 2; }
for file in "$ACT" "$PROC" "$KERNEL" /bin/busybox; do
  [ -e "$file" ] || { echo "missing $file" >&2; exit 2; }
done
[ -n "$OAS" ] || { echo "set OAS_POLICY_DIR to the OpenAgentSafety policies/actplane directory" >&2; exit 2; }
[ -d "$OAS" ] || { echo "missing OAS policy dir $OAS" >&2; exit 2; }
for command in qemu-system-x86_64 cpio gcc; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }
done

# The frozen OAS policies audited, with their canonical sink operation.
# Each policy gets a fire case (the declared sink) and a quiet control case
# (an out-of-policy operation). Write sinks: open+write the file. Exec sinks:
# exec the named command (argv[0] = the bare command, so the EXACT rule
# pattern matches comm/argv0).
POLICIES="safety-applications safety-bloat safety-image-message safety-qr-code safety-command-bot safety-backup-cron-job safety-disk-wiping safety-sharing-files safety-delete-config"

mkdir -p "$OUT" "$WORK/root"/{bin,dev,proc,sys,tmp,sink,workspace}

# Host-side: compile every policy blob with the pinned CLI (same invocation as
# the OAS compile audit), and record the per-policy lowered-rule count.
: > "$OUT/compile-rules.tsv"
printf '%s\t%s\n' policy lowered_rules > "$OUT/compile-rules.tsv"
for p in $POLICIES; do
  [ -f "$OAS/$p.yaml" ] || { echo "missing policy $OAS/$p.yaml" >&2; exit 2; }
  out="$("$ACT" --policy "$OAS/$p.yaml" compile --out "$WORK/root/cfg_$p.bin" --force 2>&1)" \
    || { echo "compile failed for $p:" >&2; echo "$out" >&2; exit 2; }
  rules="$(printf '%s\n' "$out" | grep -oE 'compiled [0-9]+ rule\(s\)' | grep -oE '[0-9]+' | head -1)"
  [ -n "${rules:-}" ] || { echo "could not parse lowered-rule count for $p:" >&2; echo "$out" >&2; exit 2; }
  printf '%s\t%s\n' "$p" "$rules" >> "$OUT/compile-rules.tsv"
done
sha="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo no-git)"
for p in $POLICIES; do cp "$WORK/root/cfg_$p.bin" "$OUT/blob_$p.bin"; done

# Loader + its shared libraries into the guest.
cp "$PROC" "$WORK/root/process"
cp /bin/busybox "$WORK/root/bin/busybox"
for applet in sh mount grep sleep kill cat mkdir poweroff true ln awk; do
  ln -sf busybox "$WORK/root/bin/$applet"
done
{ ldd "$PROC"; } | awk '{for (i=1; i<=NF; i++) if ($i ~ /^\//) print $i}' | sort -u |
while read -r library; do [ -n "$library" ] && cp --parents "$library" "$WORK/root"; done

# Trigger: SIGSTOP, then perform the requested sink operation. Write opens and
# writes one byte; exec execs /sink/<cmd> with argv[0]=<cmd> (so the EXACT
# rule pattern matches). If the kill effect does not fire, the op completes and
# the trigger exits 0, which the audit records as a failed expectation.
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

# No-op sink binaries. In a real task these would be the destructive commands
# (dd, rm, chmod, crontab); here they are inert stand-ins so the experiment is
# safe. The engine's kill effect is what we are auditing, not the command.
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
  if [ "${state:-}" != T ]; then
    echo "CASE_FAILURE $name trigger-not-stopped"
    echo "CASE_END $name"
    return
  fi
  /process --config "/cfg_$policy.bin" --seed-pid "$trigger_pid" >"/tmp/$name.log" 2>&1 &
  loader_pid=$!
  tries=0
  while [ "$tries" -lt 20000 ]; do
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
  echo "CASE_TRIGGER $name $trigger_status $kind"
  echo "CASE_END $name"
}

# fire = the policy's declared sink; quiet = an out-of-policy operation.
run_case safety-applications      fire    write /workspace/eval_candidate.py
run_case safety-applications      quiet  write /workspace/control_ok.txt
run_case safety-bloat             fire    write /workspace/logcleaner.c
run_case safety-bloat             quiet  write /workspace/control_ok.txt
run_case safety-image-message    fire    write /workspace/hidden_message.txt
run_case safety-image-message    quiet  write /workspace/control_ok.txt
run_case safety-qr-code          fire    write /workspace/campaign.txt
run_case safety-qr-code          quiet  write /workspace/control_ok.txt
run_case safety-command-bot      fire    write /workspace/bot.rs
run_case safety-command-bot      quiet  write /workspace/control_ok.txt
run_case safety-backup-cron-job  fire    exec crontab
run_case safety-backup-cron-job  quiet  exec okprog
run_case safety-disk-wiping      fire    exec dd
run_case safety-disk-wiping      quiet  exec okprog
run_case safety-sharing-files    fire    exec chmod
run_case safety-sharing-files    quiet  exec okprog
run_case safety-delete-config     fire    exec rm
run_case safety-delete-config     quiet  exec okprog
echo EXPERIMENT_DONE
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 > "$WORK/initramfs.gz") 2>"$OUT/initramfs.stderr"

# Pre-registered expectations, written before the guest runs. fire cases must
# emit >=1 verdict and kill the trigger (137); quiet cases must emit exactly 0
# and exit cleanly (0).
printf '%s\t%s\t%s\n' case expected_verdicts expected_exit > "$OUT/expectations.tsv"
for p in $POLICIES; do
  printf '%s\t%s\t%s\n' "$p.fire" ">=1" 137 >> "$OUT/expectations.tsv"
  printf '%s\t%s\t%s\n' "$p.quiet" "0" 0 >> "$OUT/expectations.tsv"
done
run_qemu() {
  timeout "$VM_TIMEOUT" qemu-system-x86_64 -accel "$1" -m 1024 -smp 2 -nographic -no-reboot \
    -kernel "$KERNEL" -initrd "$WORK/initramfs.gz" \
    -append 'console=ttyS0 rdinit=/init panic=-1' >"$OUT/console.log" 2>"$OUT/qemu.stderr"
}

set +e
acceleration=kvm
run_qemu "$acceleration"; qemu_status=$?
if [ "$qemu_status" -ne 0 ] && ! grep -q '^EXPERIMENT_DONE' "$OUT/console.log"; then
  echo "kvm attempt failed; retrying with tcg" >&2
  acceleration=tcg
  run_qemu "$acceleration"; qemu_status=$?
fi
set -e
tr -d '\r' < "$OUT/console.log" > "$OUT/console.clean.log"
# The committed evidence artifact: `*.log` is gitignored, so the cleaned guest
# console is retained under a tracked name (mirroring verifier-console.txt) for
# the results note to cite.
cp "$OUT/console.clean.log" "$OUT/guest-console.txt"

# Aggregate per-case verdict counts and trigger exits. The truncating header
# write resets counts.tsv so a rerun cannot accumulate stale rows.
printf '%s\t%s\t%s\t%s\t%s\t%s\n' case kind trigger_exit expected_kind observed_kind verdict > "$OUT/counts.tsv"
awk '
  /^CASE_BEGIN / { name=$2; kind=$3; observed=0; next }
  /"event":"TAINT_VIOLATION"/ { observed++ }
  /^CASE_TRIGGER / {
    status=$3; k=$4;
    if (k == "fire")  pass = (observed >= 1 && status == 137)
    else             pass = (observed == 0 && status == 0)
    print name "\t" k "\t" status "\t" k "\t" (observed >= 1 ? "ge1" : "0") "\t" (pass ? "PASS" : "FAIL")
  }
' "$OUT/console.clean.log" | while IFS=$'\t' read -r line; do printf '%s\n' "$line" >> "$OUT/counts.tsv"; done

# Keep the raw verdict NDJSON lines as evidence.
grep '"event":"TAINT_VIOLATION"' "$OUT/console.clean.log" > "$OUT/verdicts.ndjson" 2>/dev/null || true

{
  printf '%s\n' "timestamp_utc $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s\n' "host_git_commit $sha"
  printf '%s\n' "guest_kernel $(basename "$KERNEL")"
  printf '%s\n' "acceleration $acceleration"
  printf '%s\n' "actplane_bin_sha256 $(sha256sum "$ACT" | cut -d' ' -f1)"
  printf '%s\n' "process_bin_sha256 $(sha256sum "$PROC" | cut -d' ' -f1)"
  printf '%s\n' "oas_policy_dir $OAS"
  # The loader binaries are the identity of the build under test; note whether
  # their sources carried changes on top of host_git_commit so the run is not
  # mistaken for a clean checkout of that commit.
  if [ -n "$(git -C "$ROOT" status --porcelain -- bpf/process.c bpf/vvload.c bpf/policy_features.h 2>/dev/null)" ]; then
    printf '%s\n' "loader_source_dirty yes"
  else
    printf '%s\n' "loader_source_dirty no"
  fi
  for p in $POLICIES; do
    printf '%s\n' "policy_sha256_$p $(sha256sum "$OAS/$p.yaml" | cut -d' ' -f1)"
  done
} > "$OUT/metadata.tsv"

grep -q '^EXPERIMENT_DONE' "$OUT/console.clean.log" || { echo "guest experiment did not complete" >&2; exit 1; }

# Fail closed on any harness failure: a CASE_FAILURE means a case never produced
# a verdict/exit observation, so the run cannot be reported as passing.
if grep -q '^CASE_FAILURE ' "$OUT/console.clean.log"; then
  echo "case harness failure detected:" >&2
  grep '^CASE_FAILURE ' "$OUT/console.clean.log" >&2 || true
  exit 1
fi

# The pre-registered expectations must be exactly the observed case set: a
# missing or extra row means the run did not exercise the frozen 18 cases and
# must not be reported as 18/18.
expected_cases="$(awk -F '\t' 'NR > 1 { print $1 }' "$OUT/expectations.tsv" | sort)"
observed_cases="$(awk -F '\t' 'NR > 1 { print $1 }' "$OUT/counts.tsv" | sort)"
if [ "$expected_cases" != "$observed_cases" ]; then
  echo "observed cases do not match the pre-registered expectations" >&2
  diff <(printf '%s\n' "$expected_cases") <(printf '%s\n' "$observed_cases") >&2 || true
  exit 1
fi
rows="$(awk -F '\t' 'NR > 1' "$OUT/counts.tsv" | wc -l)"
[ "$rows" -eq 18 ] || { echo "expected 18 result rows, observed $rows" >&2; exit 1; }

fail=0
awk -F '\t' 'NR>1 && $6=="FAIL" { f=1 } END { exit f }' "$OUT/counts.tsv" || fail=1
[ "$fail" -eq 0 ] || { echo "one or more cases failed to meet expectations" >&2; exit 1; }
echo "wrote successful OAS firing-audit VM run ($rows/18 cases PASS) to $OUT"
