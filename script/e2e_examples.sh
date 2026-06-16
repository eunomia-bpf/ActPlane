#!/bin/bash
# ActPlane end-to-end example driver. The test cases (E1–E12 from
# docs/taint-dsl.md) live in test/e2e_cases.yaml; this script is only the
# driver: it seeds fixtures, then for each case compiles the case's DSL policy,
# runs the real eBPF enforcer, fires the trigger, and checks the expected
# violation fires (and the allowed/declassified case is suppressed). Run as root:
#   sudo bash script/e2e_examples.sh [path/to/cases.yaml]
#
# Triggers use copies of /bin/bash renamed to the agent/tool names (exec sources
# match comm) and /bin/true renamed to "git" (so @arg cases get a clean argv
# without side effects).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACT="${ACTPLANE_BIN:-$ROOT/target/release/actplane}"
PROC="$ROOT/bpf/process"
CASES="${1:-$ROOT/test/e2e_cases.yaml}"
export D=/tmp/ape
READY_TRIES=600  # 600 * 0.025s = 15s for BPF load+attach on slower kernels
RUN_TRIES=500    # 500 * 0.01s = 5s trigger window after the loader is ready

[ -f "$CASES" ] || { echo "cases file not found: $CASES" >&2; exit 2; }
# Always (re)build fresh binaries so this suite can never run stale ABI mirrors.
# Set ACTPLANE_SKIP_BUILD=1 to skip (e.g. when the caller just built).
if [ "${ACTPLANE_SKIP_BUILD:-0}" != "1" ]; then
  make -C "$ROOT/bpf" process >/dev/null || { echo "make -C bpf process failed" >&2; exit 2; }
  cargo build --locked -p actplane --release >/dev/null || { echo "cargo build -p actplane --release failed" >&2; exit 2; }
fi
[ -x "$ACT" ]   || { echo "build ActPlane first ('cargo build --release -p actplane') or set ACTPLANE_BIN: $ACT missing" >&2; exit 2; }
[ -x "$PROC" ]  || { echo "build bpf first: $PROC missing" >&2; exit 2; }

# --- fixtures --------------------------------------------------------------
rm -rf "$D"; mkdir -p "$D/work" "$D/downloads" "$D/customers" "$D/data" "$D/shared"
for h in codex research-agent task-a task-b human-approve confirm redact migrate pytest; do cp /bin/bash "$D/$h"; done
cp /bin/true "$D/git"; cp /bin/true "$D/deploy"
echo secret > "$D/sec.env"; echo inject > "$D/downloads/inj"
echo pii > "$D/customers/rec"; echo db > "$D/data/prod.db"

# --- explode YAML cases into per-case files (no yq dependency) -------------
CDIR="$D/cases"; rm -rf "$CDIR"; mkdir -p "$CDIR"
N=$(python3 - "$CASES" "$CDIR" <<'PY'
import os, sys, yaml
cases_path, outdir = sys.argv[1], sys.argv[2]
D = os.environ.get("D", "/tmp/ape")
def sub(s): return s.replace("${D}", D) if isinstance(s, str) else s
with open(cases_path) as f:
    doc = yaml.safe_load(f)
cases = doc.get("cases", [])
for i, c in enumerate(cases):
    d = os.path.join(outdir, f"{i:02d}"); os.makedirs(d, exist_ok=True)
    def put(name, val):
        if val is None: return
        with open(os.path.join(d, name), "w") as w: w.write(sub(val))
    put("name", c.get("name", f"case {i}"))
    put("policy", c.get("policy", ""))
    put("trigger", c.get("trigger", ""))
    put("setup", c.get("setup"))
    e = c.get("expect", {}) or {}
    put("want", e.get("want"))
    put("notwant", e.get("notwant"))
    if e.get("count") is not None: put("count", str(e["count"]))
    put("re", e.get("re"))
print(len(cases))
PY
) || { echo "failed to parse $CASES" >&2; exit 2; }

# --- driver ----------------------------------------------------------------
pass=0; fail=0
get() { [ -f "$1" ] && cat "$1"; }

wait_stopped() {
  local pid="$1" stat state
  for _ in $(seq 1 200); do
    if ! stat="$(cat "/proc/$pid/stat" 2>/dev/null)"; then return 1; fi
    stat="${stat##*) }"
    state="${stat%% *}"
    case "$state" in
      T|t) return 0 ;;
      Z) return 1 ;;
    esac
    sleep 0.01
  done
  return 1
}

wait_ready() {
  local pid="$1" file="$2"
  for _ in $(seq 1 "$READY_TRIES"); do
    grep -q "ActPlane: ready" "$file" 2>/dev/null && return 0
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.025
  done
  return 1
}

wait_done_or_timeout() {
  local pid="$1" stat state
  for _ in $(seq 1 "$RUN_TRIES"); do
    if ! stat="$(cat "/proc/$pid/stat" 2>/dev/null)"; then return 0; fi
    stat="${stat##*) }"
    state="${stat%% *}"
    [ "$state" = Z ] && return 0
    sleep 0.01
  done
  return 1
}

run_case() {
  local d="$1" name policy trig setup tfile tpid loader
  name="$(get "$d/name")"; policy="$(get "$d/policy")"; trig="$(get "$d/trigger")"
  { echo "policy: |"; printf '%s\n' "$policy" | sed 's/^/  /'; } > "$D/p.yaml"
  if ! "$ACT" --policy "$D/p.yaml" compile --out "$D/c.bin" >"$D/cc.txt" 2>&1; then
    echo "✗ $name  (compile error)"; sed 's/^/    /' "$D/cc.txt"; fail=$((fail+1)); return
  fi
  [ -f "$d/setup" ] && bash -c "$(get "$d/setup")" >/dev/null 2>&1
  tfile="$D/trigger.sh"
  printf '%s\n' "$trig" > "$tfile"
  : > "$D/o.txt"
  /bin/bash -c 'kill -STOP $$; exec /bin/bash "$1"' actplane-e2e "$tfile" >/dev/null 2>&1 &
  tpid=$!
  if ! wait_stopped "$tpid"; then
    echo "✗ $name  (trigger did not stop before seeding)"; fail=$((fail+1)); return
  fi
  "$PROC" --config "$D/c.bin" --seed-pid "$tpid" >"$D/o.txt" 2>"$D/e.txt" &
  loader=$!
  if ! wait_ready "$loader" "$D/e.txt"; then
    echo "✗ $name  (loader did not become ready)"
    sed 's/^/    /' "$D/e.txt"
    kill -CONT "$tpid" 2>/dev/null || true
    kill "$tpid" "$loader" 2>/dev/null || true
    wait "$tpid" "$loader" 2>/dev/null || true
    fail=$((fail+1))
    return
  fi
  kill -CONT "$tpid" 2>/dev/null || true
  wait_done_or_timeout "$tpid" || kill "$tpid" 2>/dev/null || true
  wait "$tpid" 2>/dev/null || true
  sleep 0.2
  kill "$loader" 2>/dev/null || true
  wait "$loader" 2>/dev/null || true

  if [ -f "$d/count" ]; then        # count mode: exactly N lines match re
    local n re got; n="$(get "$d/count")"; re="$(get "$d/re")"
    got=$(grep -Ec "$re" "$D/o.txt")
    if [ "$got" = "$n" ]; then echo "✓ $name"; pass=$((pass+1));
    else echo "✗ $name  (expected $n /$re/, got $got)"; sed 's/^/    /' "$D/o.txt"; fail=$((fail+1)); fi
  else                              # want/notwant mode
    local want notwant ok=1 why=""
    want="$(get "$d/want")"; notwant="$(get "$d/notwant")"
    if [ -n "$want" ]    && ! grep -Eq "$want"    "$D/o.txt"; then ok=0; why="missing /$want/"; fi
    if [ -n "$notwant" ] &&   grep -Eq "$notwant" "$D/o.txt"; then ok=0; why="$why; leaked /$notwant/"; fi
    if [ "$ok" = 1 ]; then echo "✓ $name"; pass=$((pass+1));
    else echo "✗ $name  ($why)"; sed 's/^/    /' "$D/o.txt"; fail=$((fail+1)); fi
  fi
}

echo "== ActPlane E1–E12 live enforcement ($N cases from $(basename "$CASES")) =="
for d in "$CDIR"/*/; do run_case "${d%/}"; done

echo "== result: $pass passed, $fail failed =="
exit $([ "$fail" = 0 ] && echo 0 || echo 1)
