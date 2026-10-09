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
# The probe covers the repo-relative `**/dir/**` mis-match (an `unless target`
# exception, a sink, and a file source) and the `**/<name>` bare-root dotfile
# case that the `contains -> suffix` tightening regressed. It runs each policy
# shape against one shared AGENT-labelled (`exec python3` / `claude`) trigger,
# in a KVM/TCG guest with BPF. The `**/dir/**` source and sink rows now match the
# first-segment-relative form via the compiler-only companion entry; the
# `unless target` exception keeps its single `cond_kind`/`cond_pat` pair, so its
# relative row still over-fires (the exception half needs an ABI disjunction).
# The `.env` rows assert the `**/<name>` fix (the bare root-level `.env` matches,
# the `foo.env` suffix does not).
#
# All expectations are pre-registered below before the guest boots; the run
# fails closed on any case-set or verdict-count drift.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ACT="${ACTPLANE_BIN:-$ROOT/target/release/actplane}"
PROC="${ACTPLANE_PROCESS_BIN:-$ROOT/bpf/process}"
# Restrict the default to a 6.8 guest: the probe's claim (and metadata) is a
# 6.8-kernel measurement, so silently selecting a newer generic kernel would
# record evidence for a different kernel than the note states.
KERNEL="${ACTPLANE_VM_KERNEL:-$(ls -1 /boot/vmlinuz-6.8.*-generic 2>/dev/null | tail -1)}"
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
         "$WORK/root/work/sub/dist" "$WORK/root/work/nemoclaw/src/lib" \
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
# The exact frozen policy of RQ2 false-negative row `rohitg00/agentmemory` `6`:
# a `file` source over a repo-relative dir pattern gates an exec sink. If the
# source misses a relative read, the dependent `git commit` rule stays silent,
# which is the recorded false negative.
frozen_policy='source AGENT = exec "claude"
source AUDIT_CHANGE = file "**/src/functions/**"
rule update-types-for-audit-ops:
  notify exec "git" "commit" if AGENT and AUDIT_CHANGE
  because "When adding new audit operations, you must also update src/types.ts"'
# The exact frozen policy of RQ2 TP row `Alishahryar1/free-claude-code` `6`. The
# frozen engine fired it on a bare relative `write .env` under the historical
# `contains(".env")` lowering; the current compiler lowers `**/.env` to
# `suffix("/.env")`, which needs a slash and so cannot match a bare `.env`.
env_policy='source AGENT = exec "claude"
rule read-env-example:
  notify write file "**/.env" if AGENT
  because "Read .env.example before creating or modifying .env files"'
"$ACT" --rule "$policy" compile --out "$WORK/root/cfg_except.bin" --force >"$OUT/compile.stdout" 2>"$OUT/compile.stderr"
"$ACT" --rule "$sink_policy" compile --out "$WORK/root/cfg_sink.bin" --force >>"$OUT/compile.stdout" 2>>"$OUT/compile.stderr"
"$ACT" --rule "$source_policy" compile --out "$WORK/root/cfg_source.bin" --force >>"$OUT/compile.stdout" 2>>"$OUT/compile.stderr"
"$ACT" --rule "$frozen_policy" compile --out "$WORK/root/cfg_frozen.bin" --force >>"$OUT/compile.stdout" 2>>"$OUT/compile.stderr"
"$ACT" --rule "$env_policy" compile --out "$WORK/root/cfg_env.bin" --force >>"$OUT/compile.stdout" 2>>"$OUT/compile.stderr"
printf '%s\n' "$policy"        > "$OUT/policy.dsl"
printf '%s\n' "$sink_policy"   > "$OUT/sink-policy.dsl"
printf '%s\n' "$source_policy" > "$OUT/source-policy.dsl"
printf '%s\n' "$frozen_policy" > "$OUT/frozen-policy.dsl"
printf '%s\n' "$env_policy"    > "$OUT/env-policy.dsl"
cp "$WORK/root/cfg_except.bin" "$OUT/blob_except.bin"
cp "$WORK/root/cfg_sink.bin" "$OUT/blob_sink.bin"
cp "$WORK/root/cfg_source.bin" "$OUT/blob_source.bin"
cp "$WORK/root/cfg_frozen.bin" "$OUT/blob_frozen.bin"
cp "$WORK/root/cfg_env.bin" "$OUT/blob_env.bin"
cp "$PROC" "$WORK/root/process"
cp /bin/busybox "$WORK/root/bin/busybox"
for a in sh mount grep sleep kill cat mkdir poweroff true ln awk date; do ln -sf busybox "$WORK/root/bin/$a"; done
{ ldd "$PROC"; } | awk '{for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i}' | sort -u |
while read -r lib; do [ -n "$lib" ] && cp --parents "$lib" "$WORK/root"; done

# Fixtures read by the file-source cases (relative and absolute refer to them).
printf 'fn main() {}\n' > "$WORK/root/work/src/lib/cli.rs"
printf 'fn main() {}\n' > "$WORK/root/work/nemoclaw/src/lib/cli.rs"
mkdir -p "$WORK/root/work/src/functions" "$WORK/root/work/a/src/functions"
printf 'export const x = 1;\n' > "$WORK/root/work/src/functions/archive.ts"
printf 'export const x = 1;\n' > "$WORK/root/work/a/src/functions/archive.ts"
# The trigger stops itself so the loader can attach, then execs /sink/<agent>
# (whose comm becomes the agent name, so the matching exec source labels it) with
# a mode and a path. Modes:
#   write <path>         open+write path
#   read_connect <path>  open+read path, then connect to a closed loopback port
#   read_commit <path>   open+read path, then exec `git commit`
cat > "$WORK/trigger.c" <<'EOF'
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    const char *agent = argc > 1 ? argv[1] : "python3";
    const char *mode = argc > 2 ? argv[2] : "write";
    const char *path = argc > 3 ? argv[3] : "";
    if (getenv("SELF_STOP")) { unsetenv("SELF_STOP"); raise(SIGSTOP); }
    char bin[64];
    snprintf(bin, sizeof(bin), "/sink/%s", agent);
    char *args[] = { (char *)agent, (char *)mode, (char *)path, NULL };
    char *envp[] = { NULL };
    execve(bin, args, envp);
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
static int read_file(const char *path) {
    char buf[64];
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); _exit(4); }
    if (read(fd, buf, sizeof(buf)) < 0) { close(fd); _exit(5); }
    close(fd);
    return 0;
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "write";
    const char *path = argc > 2 ? argv[2] : "";
    if (!strcmp(mode, "read_connect")) {
        read_file(path);
        do_connect();
        _exit(0);
    }
    if (!strcmp(mode, "read_commit")) {
        /* Mirror the frozen trace: read the guarded file, then `git commit`.
         * The commit is the guarded action; the rule fires only if the read
         * labeled this lineage through the file source. */
        read_file(path);
        char *args[] = { "git", "commit", NULL };
        char *envp[] = { NULL };
        execve("/sink/git", args, envp);
        _exit(7);
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); _exit(4); }
    if (write(fd, "x", 1) != 1) { close(fd); _exit(5); }
    close(fd);
    _exit(0);
}
EOF
# The sink binary is entered under the agent's name so comm matches the exec source.
gcc -static -O2 "$WORK/sink.c" -o "$WORK/root/sink/python3"
cp "$WORK/root/sink/python3" "$WORK/root/sink/claude"
cat > "$WORK/git.c" <<'EOF'
int main(void) { return 0; }
EOF
gcc -static -O2 "$WORK/git.c" -o "$WORK/root/sink/git"

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
  name="$1" cfg="$2" cwd="$3" agent="$4" mode="$5" path="$6"
  echo "CASE_BEGIN $name"
  ( cd "$cwd" && SELF_STOP=1 /trigger "$agent" "$mode" "$path" ) &
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
    # A verifier instruction/state-budget rejection (-E2BIG) means a program is
    # too large for this guest's 1,000,000-instruction limit under this engine
    # build. That is an engine/host precondition, not a policy-semantics
    # observation, so the case is unmeasurable here (recorded as skipped) rather
    # than pass/fail. Any other loader failure stays a hard failure.
    if grep -q 'load failed: -E2BIG' "/tmp/$name.log"; then
      echo "CASE_SKIPPED $name engine-budget"
    else
      echo "CASE_FAILURE $name loader-not-ready"
    fi
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
    # A trigger still alive at the deadline did not stop on the policy verdict,
    # so any verdict count it happened to emit before the kill is not evidence.
    # Record it as a harness failure, which fails the run below.
    echo "CASE_FAILURE $name trigger-timeout"
  else
    wait "$trigger_pid" 2>/dev/null
    trigger_status=$?
  fi
  # The loader must still be alive after the trigger runs. A loader that
  # crashed after reporting ready would emit zero violations, which would
  # spuriously satisfy a row whose expected count is zero (for example
  # `except_abs_dist`); require liveness so a crash is a harness failure, not
  # a passing observation.
  loader_alive=0
  if kill -0 "$loader_pid" 2>/dev/null; then
    loader_alive=1
  fi
  sleep 1
  kill "$loader_pid" 2>/dev/null || true
  wait "$loader_pid" 2>/dev/null || true
  cat "/tmp/$name.log"
  if [ "$loader_alive" -eq 0 ]; then
    echo "CASE_FAILURE $name loader-exited-before-count"
  fi
  echo "CASE_TRIGGER $name $trigger_status"
  echo "CASE_END $name"
}

# Exception policy: repo-relative **/dist/** should exclude the write. The
# exception still has one cond_kind/cond_pat, so the relative row over-fires
# (the exception half is unfixed; only the sink/source/gate roles get the
# companion), while the absolute twin is correctly excluded.
run_case except_dist_relative cfg_except.bin /work python3 write dist/agent-health/x.js
run_case except_abs_dist      cfg_except.bin /      python3 write /w/dist/agent-health/y.js
run_case except_src_relative  cfg_except.bin /work python3 write src/x.js
# Sink policy: a repo-relative **/dist/** sink now catches the first-segment
# relative write via the companion prefix("dist/"), and the absolute twin via
# the primary contains("/dist/").
run_case sink_dist_relative   cfg_sink.bin   /work python3 write dist/agent-health/x.js
run_case sink_abs_dist        cfg_sink.bin   /      python3 write /w/dist/agent-health/y.js
# Delimiting case: the miss needs the relative path to *start* with the pattern's
# first segment; a preceding directory (`sub/dist/...`) supplies the slash, so it
# matches and fires. This bounds the finding to first-segment-relative paths.
run_case sink_subdir_relative cfg_sink.bin   /work python3 write sub/dist/x.js
# Frozen TP policy live (Alishahryar1/free-claude-code 6): the recorded
# bare-relative `.env` write vs a nested control, plus a suffix control. Under
# the historical `contains(".env")` lowering all three fired, but the historical
# contains form also over-matched `foo.env`; the `**/<name>` basename lowering
# fires the bare `.env` and the nested `sub/.env`, and correctly rejects the
# `foo.env` suffix (a component-boundary match, not a substring).
run_case env_bare_relative    cfg_env.bin    /work claude write .env
run_case env_nested_relative  cfg_env.bin    /work claude write sub/.env
run_case env_suffix_control   cfg_env.bin    /work claude write foo.env
# File-source policy: reading a repo-relative **/src/lib/** file now labels the
# process (first-segment relative via the companion, nested/absolute via the
# primary) so the later connect fires.
run_case source_rel_read      cfg_source.bin /work python3 read_connect src/lib/cli.rs
run_case source_nested_read   cfg_source.bin /work python3 read_connect nemoclaw/src/lib/cli.rs
run_case source_abs_read      cfg_source.bin /      python3 read_connect /work/src/lib/cli.rs
# The frozen RQ2 false-negative policy, live. The companion now labels the
# recorded first-segment-relative read, so the `git commit` rule fires; the
# nested relative read remains a control that labels and fires.
run_case frozen_fn_rel_read   cfg_frozen.bin /work claude read_commit src/functions/archive.ts
run_case frozen_fn_abs_read   cfg_frozen.bin /work claude read_commit a/src/functions/archive.ts
echo EXPERIMENT_DONE
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc | gzip -1 > "$WORK/initramfs.gz") 2>"$OUT/initramfs.stderr"

# Pre-registered predictions, written before the guest runs. These are the
# verdict counts the current mechanism predicts, so the comparison checks that
# the engine matches the lowering under test (and fails closed on any drift).
# The `**/dir/**` source and sink rows now predict a first-segment-relative
# match: the compiler pairs `contains("/dir/")` with a companion
# `prefix("dir/")`. The `unless target` exception still has a single
# `cond_kind`/`cond_pat`, so its relative row keeps over-firing; the `.env` rows
# assert the `**/<name>` fix (the bare root-level `.env` matches, a longer name
# like `foo.env` does not).
printf '%s\t%s\n' case predicted_verdicts > "$OUT/expectations.tsv"
printf '%s\t%s\n' except_dist_relative 1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' except_abs_dist      0 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' except_src_relative  1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' sink_dist_relative   1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' sink_abs_dist        1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' sink_subdir_relative 1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' env_bare_relative    1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' env_nested_relative  1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' env_suffix_control   0 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' source_rel_read      1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' source_nested_read   1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' source_abs_read      1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' frozen_fn_rel_read   1 >> "$OUT/expectations.tsv"
printf '%s\t%s\n' frozen_fn_abs_read   1 >> "$OUT/expectations.tsv"

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
  /^CASE_BEGIN / { name=$2; observed=0; skipped=0; next }
  /"event":"TAINT_VIOLATION"/ { observed++ }
  /^CASE_SKIPPED / { skipped=1 }
  /^CASE_END / { print name "\t" (skipped ? "skip(engine-budget)" : observed) }
' "$OUT/console.clean.log" >> "$OUT/counts.tsv"

# Combined view: pre-registered prediction next to the observation. A skipped
# case is unmeasurable under this engine build and is excluded from the
# pass/fail comparison (but still listed, and still required to be present).
{
  printf '%s\t%s\t%s\n' case predicted_verdicts observed_verdicts
  join -t$'\t' -j1 <(tail -n +2 "$OUT/expectations.tsv" | sort) <(tail -n +2 "$OUT/counts.tsv" | sort)
} > "$OUT/summary.tsv"

{
  printf '%s\n' "timestamp_utc $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s\n' "env_policy_sha256 $(sha256sum "$OUT/env-policy.dsl" | cut -d' ' -f1)"
  printf '%s\n' "host_git_commit $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo no-git)"
  printf '%s\n' "guest_kernel $(basename "$KERNEL")"
  printf '%s\n' "frozen_policy_sha256 $(sha256sum "$OUT/frozen-policy.dsl" | cut -d' ' -f1)"
  printf '%s\n' "acceleration $accel"
  printf '%s\n' "actplane_bin_sha256 $(sha256sum "$ACT" | cut -d' ' -f1)"
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
# Fail closed: the observed case set must equal the pre-registered set (a
# missing or extra case means the guest did not run the frozen case list), and
# every observed verdict count must equal its pre-registered prediction.
# `join` above silently drops an unmatched expected case, so check the two case
# columns explicitly before trusting the per-row comparison. A row the guest
# could not measure (an engine-budget non-load) is reported as
# `skip(engine-budget)` and excluded from the count comparison; it must still be
# present, and CASE_FAILURE above already fails any non-budget loader error.
expected_cases="$(awk -F '\t' 'NR > 1 { print $1 }' "$OUT/expectations.tsv" | sort)"
observed_cases="$(awk -F '\t' 'NR > 1 { print $1 }' "$OUT/counts.tsv" | sort)"
if [ "$expected_cases" != "$observed_cases" ]; then
  echo "observed cases do not match the pre-registered expectations" >&2
  diff <(printf '%s\n' "$expected_cases") <(printf '%s\n' "$observed_cases") >&2 || true
  exit 1
fi
fail=0
awk -F '\t' '
  NR>1 && $3 ~ /^skip\(/ { skipped++; next }
  NR>1 && $2 != $3 { bad=1 }
  END {
    printf "measured %d, skipped %d\n", NR-1-skipped, skipped > "/dev/stderr"
    if (bad) exit 1
  }' "$OUT/summary.tsv" || fail=1
[ "$fail" -eq 0 ] || { echo "observed verdicts differ from pre-registered expectations" >&2; exit 1; }
echo "wrote exception-probe results to $OUT"
