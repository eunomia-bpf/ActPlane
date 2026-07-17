#!/usr/bin/env bash
# Build a host ActPlane binary and run each compatibility case in a fresh Linux
# 5.10 KVM guest. Keeping one feature per boot makes verifier failures local to
# the policy and hook set named by the case.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL_DIR="${ACTPLANE_LINUX_510:-}"

if [ $# -gt 0 ] && [ -d "$1" ]; then
  KERNEL_DIR="$1"
  shift
fi
if [ -z "$KERNEL_DIR" ]; then
  echo "usage: $0 /path/to/linux-5.10-source [case ...]" >&2
  echo "or set ACTPLANE_LINUX_510" >&2
  exit 2
fi
KERNEL_DIR="$(cd "$KERNEL_DIR" && pwd)"
IMAGE="$KERNEL_DIR/arch/x86/boot/bzImage"

ALL_CASES=(
  exec-basic
  exec-argv
  exec-prefix
  exec-lineage
  exec-after-exit
  exec-declassify
  file-read-source
  file-transitive
  file-open-sink
  file-write-sink
  file-prefix-source
  file-prefix-sink
  file-suffix-source
  file-suffix-sink
  file-contains-source
  file-contains-sink
  file-lineage
  file-after-exit
  file-target-condition
  file-since-write
  file-after-read
  file-target-prefix
  file-truncate-sink
  file-unlink-sink
  file-rename-sink
  file-rename-flow
  file-rename-overwrite
  file-rename-exchange
  file-rename-self
  file-failed-read-no-flow
  file-failed-write-no-gate
  network-connect-source
  network-connect-sink
  network-recv-source
  network-recv-sink
  network-recv-connected
  network-fd-reuse
  network-failed-connect-fd-reuse
  network-connected-dup2-fd-reuse
  network-nonsocket-read
  network-transitive
  network-prefix
  network-lineage
  network-after-exit
  network-target-condition
  provenance-exec
  provenance-file-immediate
  provenance-file-transitive
  provenance-multilabel-fallback
  kill-exec
  kill-file
  kill-connect
  kill-recv
  block-exec
  block-file-rejected
  endpoint-pattern-rejected
  block-connect
  block-recv
)
if [ $# -gt 0 ]; then
  CASES=("$@")
else
  CASES=("${ALL_CASES[@]}")
fi

for command in cargo grep make script timeout vng; do
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

case_data() {
  SETUP=
  POLICY=
  TRIGGER=
  REASON=
  WANT_COUNT=1
  WANT_RC=0
  STARTUP_PATTERN='static startup policy'
  EXPECT_PATTERN=
  case "$1" in
    exec-basic)
      REASON="Linux 5.10 exec basic matched"
      POLICY='source AGENT = exec "**"
rule exec-basic:
  notify exec "true" if AGENT
  because "Linux 5.10 exec basic matched"'
      TRIGGER='/usr/bin/true'
      ;;
    exec-argv)
      REASON="Linux 5.10 exec argv matched"
      POLICY='source AGENT = exec "**"
rule exec-argv:
  notify exec "true" "matchme" if AGENT
  because "Linux 5.10 exec argv matched"'
      TRIGGER='/usr/bin/true missme
python3 - <<'\''PY'\''
import os
os.execv("/usr/bin/true", ["x" * 70, "y" * 30, "matchme"])
PY'
      ;;
    exec-prefix)
      REASON="Linux 5.10 exec prefix matched"
      POLICY='source AGENT = exec "**"
rule exec-prefix:
  notify exec "tru*" if AGENT
  because "Linux 5.10 exec prefix matched"'
      TRIGGER='/usr/bin/false
/usr/bin/true'
      ;;
    exec-lineage)
      REASON="Linux 5.10 exec lineage matched"
      POLICY='source AGENT = exec "**"
rule exec-lineage:
  notify exec "true" if AGENT unless lineage-includes exec "apgate"
  because "Linux 5.10 exec lineage matched"'
      TRIGGER='/usr/bin/true
/tmp/apgate -c "exec /usr/bin/true"'
      ;;
    exec-after-exit)
      REASON="Linux 5.10 exec exit gate matched"
      POLICY='source AGENT = exec "**"
rule exec-after-exit:
  notify exec "true" if AGENT unless after exec "apgate" exits 0
  because "Linux 5.10 exec exit gate matched"'
      TRIGGER='/usr/bin/true
/tmp/apgate -c "exit 0"
/usr/bin/true'
      ;;
    exec-declassify)
      REASON="Linux 5.10 exec declassify matched"
      POLICY='source AGENT = exec "**"
source SECRET = exec "apsecret"
declassify SECRET by exec "apredact"
rule exec-declassify:
  notify exec "true" if SECRET
  because "Linux 5.10 exec declassify matched"'
      TRIGGER='/tmp/apsecret -c "exec /usr/bin/true"
/tmp/apsecret -c "exec /tmp/apredact -c '\''exec /usr/bin/true'\''"'
      ;;
    file-read-source)
      REASON="Linux 5.10 file read source matched"
      POLICY='source AGENT = exec "**"
source SECRET = file "/tmp/ap-secret"
rule file-read-source:
  notify exec "true" if SECRET
  because "Linux 5.10 file read source matched"'
      TRIGGER='printf secret >/tmp/ap-secret
read -r value </tmp/ap-secret
/usr/bin/true'
      ;;
    file-transitive)
      REASON="Linux 5.10 transitive file flow matched"
      POLICY='source AGENT = exec "**"
source SECRET = file "/tmp/ap-secret"
rule file-transitive:
  notify exec "true" if SECRET
  because "Linux 5.10 transitive file flow matched"'
      TRIGGER='rm -f /tmp/ap-derived /tmp/ap-ready
(while [ ! -e /tmp/ap-ready ]; do :; done
 read -r value </tmp/ap-derived
 /usr/bin/true) &
reader=$!
printf secret >/tmp/ap-secret
read -r value </tmp/ap-secret
printf "%s\n" "$value" >/tmp/ap-derived
: >/tmp/ap-ready
      wait "$reader"'
      ;;
    file-open-sink)
      REASON="Linux 5.10 file open sink matched"
      POLICY='source AGENT = exec "**"
rule file-open-sink:
  notify open file "/tmp/ap-open" if AGENT
      because "Linux 5.10 file open sink matched"'
      TRIGGER='printf data >/tmp/ap-open
read -r value </tmp/ap-open
:'
      ;;
    file-write-sink)
      REASON="Linux 5.10 file write sink matched"
      POLICY='source AGENT = exec "**"
rule file-write-sink:
  notify write file "/tmp/ap-write" if AGENT
  because "Linux 5.10 file write sink matched"'
      TRIGGER=': >/tmp/ap-write'
      ;;
    file-prefix-source)
      REASON="Linux 5.10 file prefix source matched"
      POLICY='source AGENT = exec "**"
source SECRET = file "/tmp/ap-prefix/**"
rule file-prefix-source:
  notify exec "true" if SECRET
  because "Linux 5.10 file prefix source matched"'
      TRIGGER='mkdir -p /tmp/ap-prefix
printf secret >/tmp/ap-prefix/secret
read -r value </tmp/ap-prefix/secret
/usr/bin/true'
      ;;
    file-prefix-sink)
      REASON="Linux 5.10 file prefix sink matched"
      POLICY='source AGENT = exec "**"
rule file-prefix-sink:
  notify write file "/tmp/ap-prefix/**" if AGENT
  because "Linux 5.10 file prefix sink matched"'
      TRIGGER='mkdir -p /tmp/ap-prefix
: >/tmp/ap-prefix/output'
      ;;
    file-suffix-source)
      REASON="Linux 5.10 file suffix source matched"
      POLICY='source AGENT = exec "**"
source SECRET = file "**/ap-secret.env"
rule file-suffix-source:
  notify exec "true" if SECRET
  because "Linux 5.10 file suffix source matched"'
      TRIGGER='printf secret >/tmp/ap-secret.env
read -r value </tmp/ap-secret.env
/usr/bin/true'
      ;;
    file-suffix-sink)
      REASON="Linux 5.10 file suffix sink matched"
      POLICY='source AGENT = exec "**"
rule file-suffix-sink:
  notify write file "**/ap-output.log" if AGENT
  because "Linux 5.10 file suffix sink matched"'
      TRIGGER=': >/tmp/ap-output.log'
      ;;
    file-contains-source)
      REASON="Linux 5.10 file contains source matched"
      POLICY='source AGENT = exec "**"
source SECRET = file "**/mid/**"
rule file-contains-source:
  notify exec "true" if SECRET
  because "Linux 5.10 file contains source matched"'
      TRIGGER='mkdir -p /tmp/mid
printf secret >/tmp/mid/secret
read -r value </tmp/mid/secret
/usr/bin/true'
      ;;
    file-contains-sink)
      REASON="Linux 5.10 file contains sink matched"
      POLICY='source AGENT = exec "**"
rule file-contains-sink:
  notify write file "**/mid/**" if AGENT
  because "Linux 5.10 file contains sink matched"'
      TRIGGER='mkdir -p /tmp/mid
: >/tmp/mid/output'
      ;;
    file-lineage)
      REASON="Linux 5.10 file lineage matched"
      POLICY='source AGENT = exec "**"
rule file-lineage:
  notify write file "/tmp/ap-lineage" if AGENT unless lineage-includes exec "apgate"
  because "Linux 5.10 file lineage matched"'
      TRIGGER=': >/tmp/ap-lineage
/tmp/apgate -c ": >/tmp/ap-lineage"'
      ;;
    file-after-exit)
      REASON="Linux 5.10 file after exit matched"
      POLICY='source AGENT = exec "**"
rule file-after-exit:
  notify write file "/tmp/ap-after" if AGENT unless after exec "apgate" exits 0
  because "Linux 5.10 file after exit matched"'
      TRIGGER=': >/tmp/ap-after
/tmp/apgate -c "exit 0"
: >/tmp/ap-after'
      ;;
    file-target-condition)
      REASON="Linux 5.10 file target condition matched"
      POLICY='source AGENT = exec "**"
rule file-target-condition:
  notify write file "/tmp/ap-target/**" if AGENT unless target "/tmp/ap-target/allowed"
  because "Linux 5.10 file target condition matched"'
      TRIGGER='mkdir -p /tmp/ap-target
: >/tmp/ap-target/denied
: >/tmp/ap-target/allowed'
      ;;
    file-since-write)
      REASON="Linux 5.10 file freshness matched"
      WANT_COUNT=2
      POLICY='source AGENT = exec "**"
rule file-since-write:
  notify write file "/tmp/ap-output" if AGENT unless after exec "apgate" exits 0 since write "/tmp/ap-input"
  because "Linux 5.10 file freshness matched"'
      TRIGGER=': >/tmp/ap-output
/tmp/apgate -c "exit 0"
: >/tmp/ap-output
: >/tmp/ap-input
: >/tmp/ap-output'
      ;;
    file-after-read)
      REASON="Linux 5.10 file read gate matched"
      POLICY='source AGENT = exec "**"
rule file-after-read:
  notify write file "/tmp/ap-read-output" if AGENT unless after read "/tmp/ap-read-input"
  because "Linux 5.10 file read gate matched"'
      TRIGGER='printf data >/tmp/ap-read-input
: >/tmp/ap-read-output
read -r value </tmp/ap-read-input
: >/tmp/ap-read-output'
      ;;
    file-target-prefix)
      REASON="Linux 5.10 file target prefix matched"
      POLICY='source AGENT = exec "**"
rule file-target-prefix:
  notify write file "/tmp/ap-cond/**" if AGENT unless target "/tmp/ap-cond/allowed/**"
  because "Linux 5.10 file target prefix matched"'
      TRIGGER='mkdir -p /tmp/ap-cond/allowed
: >/tmp/ap-cond/denied
: >/tmp/ap-cond/allowed/output'
      ;;
    file-truncate-sink)
      REASON="Linux 5.10 truncate sink matched"
      SETUP='printf data >/tmp/ap-truncate'
      POLICY='source AGENT = exec "**"
rule file-truncate-sink:
  notify write file "/tmp/ap-truncate" if AGENT
  because "Linux 5.10 truncate sink matched"'
      TRIGGER='python3 - <<'\''PY'\''
import os
os.truncate("/tmp/ap-truncate", 0)
PY'
      ;;
    file-unlink-sink)
      REASON="Linux 5.10 unlink sink matched"
      SETUP='printf data >/tmp/ap-unlink'
      POLICY='source AGENT = exec "**"
rule file-unlink-sink:
  notify write file "/tmp/ap-unlink" if AGENT
  because "Linux 5.10 unlink sink matched"'
      TRIGGER='rm /tmp/ap-unlink'
      ;;
    file-rename-sink)
      REASON="Linux 5.10 rename sink matched"
      SETUP='printf data >/tmp/ap-rename-old; rm -f /tmp/ap-rename-new'
      POLICY='source AGENT = exec "**"
rule file-rename-sink:
  notify write file "/tmp/ap-rename-new" if AGENT
  because "Linux 5.10 rename sink matched"'
      TRIGGER='mv /tmp/ap-rename-old /tmp/ap-rename-new'
      ;;
    file-rename-flow)
      REASON="Linux 5.10 rename flow matched"
      EXPECT_PATTERN='provenance: pid [0-9][0-9]* read /tmp/ap-rename-secret -> label SECRET'
      SETUP='printf secret >/tmp/ap-rename-secret; rm -f /tmp/ap-rename-moved'
      POLICY='source AGENT = exec "**"
source SECRET = file "/tmp/ap-rename-secret"
rule file-rename-flow:
  notify exec "true" if SECRET
  because "Linux 5.10 rename flow matched"'
      TRIGGER='mv /tmp/ap-rename-secret /tmp/ap-rename-moved
read -r value </tmp/ap-rename-moved
/usr/bin/true'
      ;;
    file-rename-overwrite)
      REASON="Linux 5.10 rename overwrite retained stale label"
      WANT_COUNT=0
      EXPECT_PATTERN='^overwrite_clean$'
      SETUP='printf plain >/tmp/ap-rename-plain; printf secret >/tmp/ap-rename-source-secret; rm -f /tmp/ap-rename-dest'
      POLICY='source AGENT = exec "never"
source SECRET = file "/tmp/ap-rename-source-secret"
rule file-rename-overwrite:
  notify exec "true" if SECRET
  because "Linux 5.10 rename overwrite retained stale label"'
      TRIGGER='/bin/bash -c '\''read -r value </tmp/ap-rename-source-secret'\''
python3 - <<'\''PY'\''
import ctypes
import os

libc = ctypes.CDLL(None, use_errno=True)
for old, new in ((b"/tmp/ap-rename-source-secret", b"/tmp/ap-rename-dest"),
                 (b"/tmp/ap-rename-plain", b"/tmp/ap-rename-dest")):
    if libc.syscall(82, old, new) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
PY
/bin/bash -c '\''read -r value </tmp/ap-rename-dest; exec /usr/bin/true'\''
echo overwrite_clean'
      ;;
    file-rename-exchange)
      REASON="Linux 5.10 rename exchange label moved"
      EXPECT_PATTERN='^exchange_complete$'
      SETUP='printf secret >/tmp/ap-exchange-source; printf plain >/tmp/ap-exchange-b; rm -f /tmp/ap-exchange-a'
      POLICY='source AGENT = exec "never"
source SECRET = file "/tmp/ap-exchange-source"
rule file-rename-exchange:
  notify exec "true" if SECRET
  because "Linux 5.10 rename exchange label moved"'
      TRIGGER='/bin/bash -c '\''read -r value </tmp/ap-exchange-source'\''
python3 - <<'\''PY'\''
import ctypes
import os

libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD = -100
RENAME_EXCHANGE = 2
if libc.syscall(82, b"/tmp/ap-exchange-source", b"/tmp/ap-exchange-a") != 0:
    raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
if libc.syscall(316, AT_FDCWD, b"/tmp/ap-exchange-a", AT_FDCWD,
                b"/tmp/ap-exchange-b", RENAME_EXCHANGE) != 0:
    raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
PY
/bin/bash -c '\''read -r value </tmp/ap-exchange-a; exec /usr/bin/true'\''
/bin/bash -c '\''read -r value </tmp/ap-exchange-b; exec /usr/bin/true'\''
echo exchange_complete'
      ;;
    file-rename-self)
      REASON="Linux 5.10 self rename preserved derived label"
      SETUP='printf secret >/tmp/ap-self-rename-secret; rm -f /tmp/ap-self-rename-derived'
      POLICY='source AGENT = exec "never"
source SECRET = file "/tmp/ap-self-rename-secret"
rule file-rename-self:
  notify exec "true" if SECRET
  because "Linux 5.10 self rename preserved derived label"'
      TRIGGER='/bin/bash -c '\''read -r value </tmp/ap-self-rename-secret; printf derived >/tmp/ap-self-rename-derived'\''
python3 - <<'\''PY'\''
import ctypes
import os

libc = ctypes.CDLL(None, use_errno=True)
path = b"/tmp/ap-self-rename-derived"
if libc.syscall(82, path, path) != 0:
    raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
PY
/bin/bash -c '\''read -r value </tmp/ap-self-rename-derived; exec /usr/bin/true'\'''
      ;;
    file-failed-read-no-flow)
      REASON="Linux 5.10 failed read changed labels"
      WANT_COUNT=0
      EXPECT_PATTERN='^failed_read_clean$'
      POLICY='source AGENT = exec "never"
source SECRET = file "/tmp/ap-missing-secret"
rule failed-read-no-flow:
  notify exec "true" if SECRET
  because "Linux 5.10 failed read changed labels"'
      TRIGGER='rm -f /tmp/ap-missing-secret
python3 - <<'\''PY'\''
try:
    open("/tmp/ap-missing-secret").read()
except FileNotFoundError:
    pass
PY
/usr/bin/true
echo failed_read_clean'
      ;;
    file-failed-write-no-gate)
      REASON="Linux 5.10 failed write satisfied gate"
      EXPECT_PATTERN='^failed_write_gate_open$'
      POLICY='source AGENT = exec "**"
rule failed-write-no-gate:
  notify exec "true" if AGENT unless after write "/tmp/ap-missing-dir/file"
  because "Linux 5.10 failed write satisfied gate"'
      TRIGGER='rm -rf /tmp/ap-missing-dir
if : >/tmp/ap-missing-dir/file; then echo unexpected_write; fi
/usr/bin/true
echo failed_write_gate_open'
      ;;
    network-connect-source)
      REASON="Linux 5.10 endpoint source matched"
      POLICY='source AGENT = exec "**"
source NET = endpoint "127.0.0.1"
rule network-connect-source:
  notify exec "true" if NET
  because "Linux 5.10 endpoint source matched"'
      TRIGGER='python3 - <<'\''PY'\''
import os
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 9))
except OSError:
    pass
os.execl("/usr/bin/true", "true")
PY'
      ;;
    network-connect-sink)
      REASON="Linux 5.10 connect sink matched"
      POLICY='source AGENT = exec "**"
rule network-connect-sink:
  notify connect endpoint "127.0.0.1" if AGENT
  because "Linux 5.10 connect sink matched"'
      TRIGGER='python3 - <<'\''PY'\''
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 9))
except OSError:
    pass
PY'
      ;;
    network-recv-source)
      REASON="Linux 5.10 endpoint recv source matched"
      POLICY='source AGENT = exec "**"
source NET = endpoint "127.0.0.1"
rule network-recv-source:
  notify exec "true" if NET
  because "Linux 5.10 endpoint recv source matched"'
      TRIGGER='python3 - <<'\''PY'\''
import os
import socket
import time
pid = os.fork()
if pid == 0:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 34567))
    s.recvfrom(16)
    os.execl("/usr/bin/true", "true")
time.sleep(0.2)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"data", ("127.0.0.1", 34567))
os.waitpid(pid, 0)
PY'
      ;;
    network-recv-sink)
      REASON="Linux 5.10 recv sink matched"
      POLICY='source AGENT = exec "**"
rule network-recv-sink:
  notify recv endpoint "127.0.0.1" if AGENT
  because "Linux 5.10 recv sink matched"'
      TRIGGER='python3 - <<'\''PY'\''
import os
import socket
import time
pid = os.fork()
if pid == 0:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 34568))
    s.recvfrom(16)
    os._exit(0)
time.sleep(0.2)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"data", ("127.0.0.1", 34568))
os.waitpid(pid, 0)
PY'
      ;;
    network-recv-connected)
      REASON="Linux 5.10 connected recv sink matched"
      POLICY='source AGENT = exec "**"
rule network-recv-connected:
  notify recv endpoint "127.0.0.1" if AGENT
  because "Linux 5.10 connected recv sink matched"'
      TRIGGER='python3 - <<'\''PY'\''
import os
import socket
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 34574))
    s.connect(("127.0.0.1", 34575))
    os.write(w, b"1")
    s.recv(16)
    os._exit(0)
os.close(w)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 34575))
os.read(r, 1)
s.sendto(b"data", ("127.0.0.1", 34574))
os.waitpid(pid, 0)
PY'
      ;;
    network-fd-reuse)
      REASON="Linux 5.10 stale connected fd matched regular read"
      WANT_COUNT=0
      EXPECT_PATTERN='^regular_read$'
      SETUP='printf data >/tmp/ap-regular-read'
      POLICY='source AGENT = exec "**"
source CONNECT_HOOK = endpoint "192.0.2.1"
rule enable-connect-hooks:
  notify connect endpoint "192.0.2.1" if CONNECT_HOOK
  because "Linux 5.10 connect hook reserve"
rule network-fd-reuse:
  notify recv endpoint "127.0.0.1" if AGENT
  because "Linux 5.10 stale connected fd matched regular read"'
      TRIGGER='python3 - <<'\''PY'\''
import os
import socket

server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)
client = socket.socket()
client.connect(server.getsockname())
peer, _ = server.accept()
client_fd = client.fileno()
client.close()
peer.close()
fd = os.open("/tmp/ap-regular-read", os.O_RDONLY)
if fd != client_fd:
    raise RuntimeError(f"expected fd reuse {client_fd}, got {fd}")
os.read(fd, 4)
print("regular_read")
PY'
      ;;
    network-failed-connect-fd-reuse)
      REASON="Linux 5.10 failed connect cached regular fd"
      WANT_COUNT=0
      EXPECT_PATTERN='^failed_connect_regular_read$'
      SETUP='printf data >/tmp/ap-failed-connect-read'
      POLICY='source AGENT = exec "**"
source CONNECT_HOOK = endpoint "192.0.2.1"
rule enable-connect-hooks:
  notify connect endpoint "192.0.2.1" if CONNECT_HOOK
  because "Linux 5.10 connect hook reserve"
rule network-failed-connect-fd-reuse:
  notify recv endpoint "127.0.0.1" if AGENT
  because "Linux 5.10 failed connect cached regular fd"'
      TRIGGER='python3 - <<'\''PY'\''
import os
import socket

probe = socket.socket()
probe.bind(("127.0.0.1", 0))
port = probe.getsockname()[1]
probe.close()

client = socket.socket()
client_fd = client.fileno()
try:
    client.connect(("127.0.0.1", port))
except OSError:
    pass
else:
    raise RuntimeError("expected connect to fail")

regular_fd = os.open("/tmp/ap-failed-connect-read", os.O_RDONLY)
os.dup2(regular_fd, client_fd)
if regular_fd != client_fd:
    os.close(regular_fd)
os.read(client_fd, 4)
print("failed_connect_regular_read")
PY'
      ;;
    network-connected-dup2-fd-reuse)
      REASON="Linux 5.10 connected dup2 cached regular fd"
      WANT_COUNT=0
      EXPECT_PATTERN='^connected_dup2_regular_read$'
      SETUP='printf data >/tmp/ap-connected-dup2-read'
      POLICY='source AGENT = exec "**"
source CONNECT_HOOK = endpoint "192.0.2.1"
rule enable-connect-hooks:
  notify connect endpoint "192.0.2.1" if CONNECT_HOOK
  because "Linux 5.10 connect hook reserve"
rule network-connected-dup2-fd-reuse:
  notify recv endpoint "127.0.0.1" if AGENT
  because "Linux 5.10 connected dup2 cached regular fd"'
      TRIGGER='python3 - <<'\''PY'\''
import os
import socket

server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)
client = socket.socket()
client.connect(server.getsockname())
peer, _ = server.accept()
client_fd = client.fileno()
regular_fd = os.open("/tmp/ap-connected-dup2-read", os.O_RDONLY)
os.dup2(regular_fd, client_fd)
if regular_fd != client_fd:
    os.close(regular_fd)
os.read(client_fd, 4)
peer.close()
server.close()
print("connected_dup2_regular_read")
PY'
      ;;
    network-nonsocket-read)
      REASON="Linux 5.10 nonsocket read matched recv"
      WANT_COUNT=0
      EXPECT_PATTERN='^pipe_read_clean$'
      POLICY='source AGENT = exec "**"
rule network-nonsocket-read:
  notify recv endpoint "*" if AGENT
  because "Linux 5.10 nonsocket read matched recv"'
      TRIGGER='python3 - <<'\''PY'\''
import os
r, w = os.pipe()
os.write(w, b"data")
os.close(w)
os.read(r, 4)
os.close(r)
print("pipe_read_clean")
PY'
      ;;
    network-transitive)
      REASON="Linux 5.10 transitive endpoint flow matched"
      EXPECT_PATTERN='provenance: pid [0-9][0-9]* read /tmp/ap-secret -> label PRIVATE'
      POLICY='source AGENT = exec "**"
source SECRET = file "/tmp/ap-secret"
source PRIVATE = file "/tmp/ap-secret"
rule enable-network-hooks:
  notify connect endpoint "192.0.2.1" if SECRET
  notify recv endpoint "192.0.2.1" if SECRET
  because "network hook reserve"
rule network-transitive:
  notify exec "true" if PRIVATE
  because "Linux 5.10 transitive endpoint flow matched"'
      TRIGGER='printf secret >/tmp/ap-secret
python3 - <<'\''PY'\''
import os
import socket
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 34569))
    os.write(w, b"1")
    s.recvfrom(16)
    os.execl("/usr/bin/true", "true")
os.close(w)
os.read(r, 1)
open("/tmp/ap-secret").read()
probe = socket.socket()
try:
    probe.connect(("127.0.0.1", 9))
except OSError:
    pass
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"data", ("127.0.0.1", 34569))
os.waitpid(pid, 0)
PY'
      ;;
    network-prefix)
      REASON="Linux 5.10 endpoint prefix matched"
      POLICY='source AGENT = exec "**"
rule network-prefix:
  notify connect endpoint "127." if AGENT
  because "Linux 5.10 endpoint prefix matched"'
      TRIGGER='python3 - <<'\''PY'\''
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 9))
except OSError:
    pass
PY'
      ;;
    network-lineage)
      REASON="Linux 5.10 endpoint lineage matched"
      POLICY='source AGENT = exec "**"
rule network-lineage:
  notify connect endpoint "127.0.0.1" if AGENT unless lineage-includes exec "apgate"
  because "Linux 5.10 endpoint lineage matched"'
      TRIGGER='python3 - <<'\''PY'\''
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 9))
except OSError:
    pass
PY
/tmp/apgate -c "python3 - <<'\''PY'\''
import socket
s = socket.socket()
try:
    s.connect((\"127.0.0.1\", 9))
except OSError:
    pass
PY"'
      ;;
    network-after-exit)
      REASON="Linux 5.10 endpoint after exit matched"
      POLICY='source AGENT = exec "**"
rule network-after-exit:
  notify connect endpoint "127.0.0.1" if AGENT unless after exec "apgate" exits 0
  because "Linux 5.10 endpoint after exit matched"'
      TRIGGER='python3 - <<'\''PY'\''
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 9))
except OSError:
    pass
PY
/tmp/apgate -c "exit 0"
python3 - <<'\''PY'\''
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 9))
except OSError:
    pass
PY'
      ;;
    network-target-condition)
      REASON="Linux 5.10 endpoint target condition matched"
      POLICY='source AGENT = exec "**"
rule network-target-condition:
  notify connect endpoint "*" if AGENT unless target "127.0.0.1"
  because "Linux 5.10 endpoint target condition matched"'
      TRIGGER='python3 - <<'\''PY'\''
import socket
for address in ("127.0.0.1", "192.0.2.1"):
    s = socket.socket()
    s.settimeout(0.1)
    try:
        s.connect((address, 9))
    except OSError:
        pass
PY'
      ;;
    provenance-exec)
      REASON="Linux 5.10 exec provenance matched"
      EXPECT_PATTERN='provenance: pid [0-9][0-9]* exec apsecret -> label PRIVATE'
      POLICY='source AGENT = exec "**"
source SECRET = exec "apsecret"
source PRIVATE = exec "apsecret"
rule provenance-exec:
  notify exec "true" if PRIVATE
  because "Linux 5.10 exec provenance matched"'
      TRIGGER='/tmp/apsecret -c "exec /usr/bin/true"'
      ;;
    provenance-file-immediate)
      REASON="Linux 5.10 immediate file provenance matched"
      EXPECT_PATTERN='provenance: pid [0-9][0-9]* read /tmp/ap-immediate -> label SECRET'
      POLICY='source AGENT = exec "**"
source SECRET = file "/tmp/ap-immediate"
rule provenance-file-immediate:
  notify open file "/tmp/ap-immediate" if SECRET
  because "Linux 5.10 immediate file provenance matched"'
      TRIGGER='printf "%s\n" secret >/tmp/ap-immediate
read -r value </tmp/ap-immediate'
      ;;
    provenance-file-transitive)
      REASON="Linux 5.10 transitive file provenance matched"
      EXPECT_PATTERN='provenance: pid [0-9][0-9]* read /tmp/ap-secret -> label PRIVATE'
      POLICY='source AGENT = exec "**"
source SECRET = file "/tmp/ap-secret"
source PRIVATE = file "/tmp/ap-secret"
rule provenance-file-transitive:
  notify exec "true" if PRIVATE
  because "Linux 5.10 transitive file provenance matched"'
      TRIGGER='rm -f /tmp/ap-derived /tmp/ap-ready
(while [ ! -e /tmp/ap-ready ]; do :; done
 read -r value </tmp/ap-derived
 /usr/bin/true) &
reader=$!
printf secret >/tmp/ap-secret
read -r value </tmp/ap-secret
printf "%s\n" "$value" >/tmp/ap-derived
: >/tmp/ap-ready
wait "$reader"'
      ;;
    provenance-multilabel-fallback)
      REASON="Linux 5.10 multi-label provenance matched"
      EXPECT_PATTERN='provenance: pid [0-9][0-9]* read /tmp/ap-multilabel -> label PRIVATE'
      POLICY='source AGENT = exec "never"
source PRIVATE = file "/tmp/ap-multilabel"
rule provenance-multilabel-fallback:
  notify exec "true" if AGENT and PRIVATE
  because "Linux 5.10 multi-label provenance matched"'
      TRIGGER='printf private >/tmp/ap-multilabel
read -r value </tmp/ap-multilabel
/usr/bin/true'
      ;;
    kill-exec)
      REASON="Linux 5.10 exec kill matched"
      EXPECT_PATTERN='^exec_killed$'
      POLICY='source AGENT = exec "**"
rule kill-exec:
  kill exec "true" if AGENT
  because "Linux 5.10 exec kill matched"'
      TRIGGER='if /usr/bin/true; then echo kill_failed; else echo exec_killed; fi'
      ;;
    kill-file)
      REASON="Linux 5.10 file kill matched"
      EXPECT_PATTERN='^file_killed$'
      POLICY='source AGENT = exec "**"
rule kill-file:
  kill write file "/tmp/ap-kill" if AGENT
  because "Linux 5.10 file kill matched"'
      TRIGGER='if /bin/bash -c ": >/tmp/ap-kill"; then echo kill_failed; else echo file_killed; fi'
      ;;
    kill-connect)
      REASON="Linux 5.10 connect kill matched"
      EXPECT_PATTERN='^connect_killed$'
      POLICY='source AGENT = exec "**"
rule kill-connect:
  kill connect endpoint "127.0.0.1" if AGENT
  because "Linux 5.10 connect kill matched"'
      TRIGGER='if python3 - <<'\''PY'\''
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 9))
except OSError:
    pass
PY
then echo kill_failed; else echo connect_killed; fi'
      ;;
    kill-recv)
      REASON="Linux 5.10 recv kill matched"
      EXPECT_PATTERN='^recv_killed$'
      POLICY='source AGENT = exec "**"
rule kill-recv:
  kill recv endpoint "127.0.0.1" if AGENT
  because "Linux 5.10 recv kill matched"'
      TRIGGER='python3 - <<'\''PY'\''
import os
import socket
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 34572))
    s.connect(("127.0.0.1", 34573))
    os.write(w, b"1")
    s.recv(16)
    os._exit(0)
os.close(w)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 34573))
os.read(r, 1)
s.sendto(b"data", ("127.0.0.1", 34572))
_, status = os.waitpid(pid, 0)
print("recv_killed" if os.WIFSIGNALED(status) else "kill_failed")
PY'
      ;;
    block-exec)
      REASON="Linux 5.10 exec block matched"
      EXPECT_PATTERN='^exec_blocked$'
      POLICY='source AGENT = exec "**"
rule block-exec:
  block exec "true" if AGENT
  because "Linux 5.10 exec block matched"'
      TRIGGER='if /usr/bin/true; then echo block_failed; else echo exec_blocked; fi'
      ;;
    block-file-rejected)
      REASON="Linux 5.10 rejected file block"
      WANT_COUNT=0
      WANT_RC=1
      STARTUP_PATTERN='does not support file block rules safely'
      EXPECT_PATTERN='does not support file block rules safely'
      POLICY='source AGENT = exec "**"
rule block-file-rejected:
  block write file "/tmp/ap-block" if AGENT
  because "Linux 5.10 rejected file block"'
      TRIGGER='echo block_file_should_not_run'
      ;;
    endpoint-pattern-rejected)
      REASON="Linux 5.10 rejected endpoint pattern"
      WANT_COUNT=0
      WANT_RC=1
      STARTUP_PATTERN='cannot represent this endpoint policy safely'
      EXPECT_PATTERN='endpoint pattern `\*\.internal` is not numeric IPv4'
      POLICY='source AGENT = exec "**"
rule endpoint-pattern-rejected:
  block connect endpoint "*.internal" if AGENT
  because "Linux 5.10 rejected endpoint pattern"'
      TRIGGER='echo endpoint_pattern_should_not_run'
      ;;
    block-connect)
      REASON="Linux 5.10 connect block matched"
      EXPECT_PATTERN='^connect_blocked$'
      POLICY='source AGENT = exec "**"
rule block-connect:
  block connect endpoint "127.0.0.1" if AGENT
  because "Linux 5.10 connect block matched"'
      TRIGGER='python3 - <<'\''PY'\''
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 9))
except PermissionError:
    print("connect_blocked")
except OSError:
    print("block_failed")
PY'
      ;;
    block-recv)
      REASON="Linux 5.10 recv block matched"
      EXPECT_PATTERN='^recv_blocked$'
      POLICY='source AGENT = exec "**"
rule block-recv:
  block recv endpoint "127.0.0.1" if AGENT
  because "Linux 5.10 recv block matched"'
      TRIGGER='python3 - <<'\''PY'\''
import os
import socket
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 34570))
    s.connect(("127.0.0.1", 34571))
    os.write(w, b"1")
    try:
        s.recv(16)
    except PermissionError:
        print("recv_blocked", flush=True)
    os._exit(0)
os.close(w)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 34571))
os.read(r, 1)
s.sendto(b"data", ("127.0.0.1", 34570))
os.waitpid(pid, 0)
PY'
      ;;
    *)
      echo "unknown Linux 5.10 KVM case: $1" >&2
      echo "known cases: ${ALL_CASES[*]}" >&2
      exit 2
      ;;
  esac
}

assert_report() {
  local report="$1" pattern="$2"
  if ! grep -q "$pattern" "$report"; then
    echo "guest report is missing pattern: $pattern" >&2
    return 1
  fi
}

run_case() {
  local name="$1" setup policy trigger report host_log count vng_command
  case_data "$name"
  setup="$(mktemp "$ROOT/target/actplane-5.10-setup.XXXXXX")"
  policy="$(mktemp "$ROOT/target/actplane-5.10-policy.XXXXXX")"
  trigger="$(mktemp "$ROOT/target/actplane-5.10-trigger.XXXXXX")"
  report="$(mktemp "$ROOT/target/actplane-5.10-report.XXXXXX")"
  host_log="$(mktemp "${TMPDIR:-/tmp}/actplane-5.10-vng.XXXXXX")"
  printf '#!/usr/bin/env bash\nset -eu\n%s\n' "$SETUP" >"$setup"
  printf '%s\n' "$POLICY" >"$policy"
  printf '#!/usr/bin/env bash\nset -u\n%s\n' "$TRIGGER" >"$trigger"
  chmod 644 "$setup" "$policy" "$trigger"
  chmod 666 "$report"

  printf -v binary_q '%q' "$ROOT/target/release/actplane"
  printf -v setup_q '%q' "$setup"
  printf -v policy_q '%q' "$policy"
  printf -v trigger_q '%q' "$trigger"
  printf -v report_q '%q' "$report"
  guest_command="set -u; { \
echo case=$name; \
echo kernel=\$(uname -r); \
echo memlock_before=\$(ulimit -l); \
test -r /sys/kernel/btf/vmlinux && echo btf=present; \
grep -qw bpf /sys/kernel/security/lsm; \
echo active_lsm=\$(cat /sys/kernel/security/lsm); \
cp /bin/bash /tmp/apgate; cp /bin/bash /tmp/apsecret; cp /bin/bash /tmp/apredact; \
/bin/bash $setup_q; \
timeout 60 $binary_q --rule \"\$(cat $policy_q)\" run /bin/bash $trigger_q; \
echo actplane_rc=\$?; \
} >$report_q 2>&1"

  echo "== [$name] booting $release =="
  printf -v vng_command '%q ' \
    timeout "${ACTPLANE_KVM_TIMEOUT:-120}" vng --run "$IMAGE" \
      --user root \
      --cpus "${ACTPLANE_KVM_CPUS:-2}" \
      --memory "${ACTPLANE_KVM_MEMORY:-4G}" \
      --append "lsm=bpf" \
      --cwd "$ROOT" \
      --rwdir "$ROOT/target" \
      --exec "$guest_command"
  # QEMU's virtme chardev requires a terminal; util-linux script preserves one
  # while retaining a host-side log for verifier and boot diagnostics.
  if ! script -qefc "$vng_command" "$host_log" >/dev/null; then
    cat "$report" >&2
    tail -n 80 "$host_log" >&2
    rm -f "$setup" "$policy" "$trigger" "$report" "$host_log"
    return 1
  fi

  cat "$report"
  assert_report "$report" '^kernel=5\.10\.'
  assert_report "$report" '^btf=present$'
  assert_report "$report" '^active_lsm=.*bpf'
  if [ -n "$STARTUP_PATTERN" ]; then
    assert_report "$report" "$STARTUP_PATTERN"
  fi
  assert_report "$report" "^actplane_rc=$WANT_RC$"
  if [ -n "$EXPECT_PATTERN" ]; then
    assert_report "$report" "$EXPECT_PATTERN"
  fi
  count="$(grep -cF "reason: $REASON" "$report" || true)"
  if [ "$count" -ne "$WANT_COUNT" ]; then
    echo "[$name] expected $WANT_COUNT matching violations, got $count" >&2
    tail -n 80 "$host_log" >&2
    rm -f "$setup" "$policy" "$trigger" "$report" "$host_log"
    return 1
  fi
  rm -f "$setup" "$policy" "$trigger" "$report" "$host_log"
  echo "== [$name] passed =="
}

for name in "${CASES[@]}"; do
  run_case "$name"
done

echo "== Linux 5.10 KVM matrix passed (${#CASES[@]} cases) =="
