#!/bin/bash
# Probe: does a wildcard-only clause target reach the kernel matcher, or does a
# `*` leak into the matcher literal and make the rule never fire?
#
# Context. `bpf/taint.h` `taint_match` treats `*` as an ordinary byte and its
# `M_ANY` kind returns 1 unconditionally, so a matcher literal that still
# contains a `*` can never match. The parser (`dsl/parse.rs` `P::target`)
# rewrites a slash-free exec pattern to `**/<pattern>`, so `exec "**"` reached the
# lowerer as `**/**` and the whole-pattern ANY guard did not see it. Before the
# fix the compiled rule carried `match=PREFIX, literal="*"`, which matches no
# comm; after the fix it carries `match=ANY, literal=""`, byte-identical to the
# long-working `exec "*"`.
#
# This is a live 6.8 guest A/B of the same policy source compiled by two
# binaries: the pre-fix compiler (a18a0a44) and the current one. The trigger is
# stopped before the loader attaches and continued after it reports ready, so the
# observed verdicts are the trigger's exec, not the loader's own startup execs.
# Pre-registered expectation, enforced below: pre-fix emits ZERO violations for
# the exec and post-fix emits at least one, for the identical policy text. A run
# that does not observe both fails closed.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ACT="${ACTPLANE_BIN:-$ROOT/target/release/actplane}"
PRE="${ACTPLANE_PRE_FIX_BIN:-}"
PROC="${ACTPLANE_PROCESS_BIN:-$ROOT/bpf/process}"
KERNEL="${ACTPLANE_VM_KERNEL:-$(ls -1 /boot/vmlinuz-6.8.*-generic 2>/dev/null | tail -1)}"
OUT="${1:-$ROOT/docs/empirical-study/results/rq2-wildcard-literal-vm}"
VM_TIMEOUT="${ACTPLANE_VM_TIMEOUT:-900}"
WORK="$(mktemp -d /tmp/actplane-wildcard-literal.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

[ -n "$KERNEL" ] || { echo "set ACTPLANE_VM_KERNEL to a guest vmlinuz" >&2; exit 2; }
[ -n "$PRE" ] || { echo "set ACTPLANE_PRE_FIX_BIN to the pre-fix actplane" >&2; exit 2; }
for f in "$ACT" "$PRE" "$PROC" "$KERNEL" /bin/busybox; do
  [ -e "$f" ] || { echo "missing $f" >&2; exit 2; }
done
for c in qemu-system-x86_64 cpio gcc; do
  command -v "$c" >/dev/null || { echo "missing $c" >&2; exit 2; }
done

# The whole-pattern catch-all sink. `**` is the shape whose parser-normalized
# form (`**/**`) defeated the guard; `*` is the long-working control.
policy='rule catch_all:
  notify exec "**"
  because "probe: wildcard-only exec target must match every comm"'

mkdir -p "$OUT" "$WORK/root"/{bin,dev,proc,sys,tmp,flow}
"$PRE" --rule "$policy" compile --out "$WORK/cfg_pre.bin" --force >"$OUT/compile-pre.stdout" 2>"$OUT/compile-pre.stderr"
"$ACT" --rule "$policy" compile --out "$WORK/cfg_post.bin" --force >"$OUT/compile-post.stdout" 2>"$OUT/compile-post.stderr"
printf '%s\n' "$policy" > "$OUT/policy.dsl"
cp "$WORK/cfg_pre.bin"  "$OUT/blob_pre_fix.bin"
cp "$WORK/cfg_post.bin" "$OUT/blob_post_fix.bin"
# The byte-identity claim: post-fix `exec "**"` must be the same blob as `exec "*"`.
star_policy='rule catch_all:
  notify exec "*"
  because "probe: wildcard-only exec target must match every comm"'
"$ACT" --rule "$star_policy" compile --out "$WORK/cfg_star.bin" --force >/dev/null 2>&1
cmp -s "$WORK/cfg_post.bin" "$WORK/cfg_star.bin" \
  && echo "blob_post_equals_star=yes" > "$OUT/blob-identity.txt" \
  || echo "blob_post_equals_star=NO" > "$OUT/blob-identity.txt"

cp "$PROC" "$WORK/root/process"
cp /bin/busybox "$WORK/root/bin/busybox"
for a in sh mount grep sleep kill cat poweroff true ln date; do ln -sf busybox "$WORK/root/bin/$a"; done
ldd "$PROC" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i}' | sort -u |
while read -r lib; do [ -n "$lib" ] && cp --parents "$lib" "$WORK/root"; done

# The trigger stops itself (so the loader can attach and seed its pid), then
# execs a uniquely named binary. `exec "**"` must match that exec's comm.
cat > "$WORK/trigger.c" <<'EOF'
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    raise(SIGSTOP);
    char *args[] = { "zzzprobe", NULL };
    char *envp[] = { NULL };
    execve("/bin/zzzprobe", args, envp);
    return 6;
}
EOF
gcc -static -O2 "$WORK/trigger.c" -o "$WORK/root/trigger"
cp /bin/busybox "$WORK/root/bin/zzzprobe"

# `run_arm <cfg> <arm-name>`: boot, wait ready, continue the trigger, report the
# trigger's verdicts and exit status.
run_arm() {
  cfg="$1"; arm="$2"
  cp "$cfg" "$WORK/root/cfg.bin"
  cat > "$WORK/root/init" <<'EOF'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
cd /flow
/trigger &
tpid=$!
tries=0
while [ "$tries" -lt 200 ]; do
  state="$(awk '{print $3}' "/proc/$tpid/stat" 2>/dev/null)"
  [ "$state" = T ] && break
  tries=$((tries + 1)); sleep 0.05
done
[ "$state" = T ] || { echo "TRIGGER_NOT_STOPPED"; poweroff -f; }
/process --config /cfg.bin --seed-pid "$tpid" >/out.txt 2>/err.txt &
lpid=$!
tries=0
while [ "$tries" -lt 4000 ]; do
  grep -q 'ActPlane: ready' /err.txt 2>/dev/null && break
  kill -0 "$lpid" 2>/dev/null || break
  tries=$((tries + 1)); sleep 0.01
done
grep -q 'ActPlane: ready' /err.txt 2>/dev/null || { echo "LOADER_NOT_READY"; cat /err.txt; poweroff -f; }
sleep 1
kill -CONT "$tpid"
deadline=$(( $(date +%s) + 8 ))
while kill -0 "$tpid" 2>/dev/null; do
  state="$(awk '{print $3}' "/proc/$tpid/stat" 2>/dev/null)"
  { [ -z "$state" ] || [ "$state" = Z ]; } && break
  [ "$(date +%s)" -ge "$deadline" ] && { echo "TRIGGER_TIMEOUT"; break; }
  sleep 0.05
done
wait "$tpid" 2>/dev/null
sleep 1
vc=$(grep -c TAINT_VIOLATION /out.txt 2>/dev/null || true)
echo "VERDICT_COUNT ${vc:-0}"
cat /out.txt 2>/dev/null
sleep 1
kill "$lpid" 2>/dev/null
poweroff -f
EOF
  chmod +x "$WORK/root/init"
  (cd "$WORK/root" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 > "$WORK/i.gz")
  timeout "$VM_TIMEOUT" qemu-system-x86_64 -accel tcg -m 2048 -smp 2 -nographic -no-reboot \
    -kernel "$KERNEL" -initrd "$WORK/i.gz" \
    -append 'console=ttyS0 rdinit=/init panic=-1' > "$OUT/$arm.qemu.stdout" 2>"$OUT/$arm.qemu.stderr"
  echo "qemu_status_$arm=$?" | tee -a "$OUT/qemu-status.txt"
  # Committed as `.txt` because `.gitignore` ignores `*.log`; the clean text (no
  # CR) is the retained evidence, matching the other `guest-console.txt` files.
  tr -d '\r' < "$OUT/$arm.qemu.stdout" > "$OUT/guest-console-$arm.txt"
}

: > "$OUT/qemu-status.txt"
run_arm "$WORK/cfg_pre.bin"  "pre-fix"
run_arm "$WORK/cfg_post.bin" "post-fix"

pre="$(grep -o 'VERDICT_COUNT [0-9]*' "$OUT/guest-console-pre-fix.txt" | awk '{print $2}')"
post="$(grep -o 'VERDICT_COUNT [0-9]*' "$OUT/guest-console-post-fix.txt" | awk '{print $2}')"
echo "pre_fix_violations=$pre"
echo "post_fix_violations=$post"

# Pre-registered expectation, enforced (fail closed).
rc=0
[ "${pre:-x}" = "0" ] || { echo "FAIL: pre-fix expected 0 violations, got ${pre:-none}" >&2; rc=1; }
[ -n "${post:-}" ] && [ "$post" -ge 1 ] || { echo "FAIL: post-fix expected >=1 violation, got ${post:-none}" >&2; rc=1; }

python3 - "$OUT" "$PRE" "$ACT" "$KERNEL" "$pre" "$post" <<'PY'
import hashlib, subprocess, sys, os
out, pre_bin, act_bin, kernel, pre, post = sys.argv[1:7]
def sha(p): return hashlib.sha256(open(p,'rb').read()).hexdigest()
def sh(c): return subprocess.run(c,shell=True,capture_output=True,text=True).stdout.strip()
ident = open(os.path.join(out,"blob-identity.txt")).read().strip()
rows = [
 ("timestamp_utc", sh("date -u +%Y-%m-%dT%H:%M:%SZ")),
 ("git_commit", sh("git -C "+out+"/../.. rev-parse HEAD")),
 ("host_kernel", sh("uname -r")),
 ("guest_kernel", os.path.basename(kernel)),
 ("guest_kernel_sha256", sha(kernel)),
 ("acceleration", "tcg"),
 ("qemu_timeout_s", os.environ.get("ACTPLANE_VM_TIMEOUT","900")),
 ("pre_fix_binary_sha256", sha(pre_bin)),
 ("post_fix_binary_sha256", sha(act_bin)),
 ("pre_fix_blob_sha256", sha(os.path.join(out,"blob_pre_fix.bin"))),
 ("post_fix_blob_sha256", sha(os.path.join(out,"blob_post_fix.bin"))),
 ("post_fix_blob_equals_star_form", ident.split("=",1)[1]),
 ("policy", 'rule catch_all: notify exec "**" because "..." (identical source both arms)'),
 ("pre_fix_violations", pre),
 ("post_fix_violations", post),
]
open(os.path.join(out,"metadata.tsv"),"w").write("\n".join(f"{k}\t{v}" for k,v in rows)+"\n")
PY

sed -n '/TRIGGER_NOT_STOPPED\|LOADER_NOT_READY/,$p' | grep -vE '^\[ *[0-9]' | head
exit $rc
