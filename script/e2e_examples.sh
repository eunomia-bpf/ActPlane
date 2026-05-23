#!/bin/bash
# ActPlane end-to-end example driver. The test cases (E1–E12 from
# docs/taint-dsl.md) live in script/test/e2e_cases.yaml; this script is only the
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
ACT="$ROOT/collector/target/release/actplane"
PROC="$ROOT/bpf/process"
CASES="${1:-$ROOT/script/test/e2e_cases.yaml}"
export D=/tmp/ape
SETTLE=2.8   # let BPF attach before triggers fire
WIN=6        # loader lifetime per case

[ -f "$CASES" ] || { echo "cases file not found: $CASES" >&2; exit 2; }
[ -x "$ACT" ]   || { echo "build the collector first: $ACT missing" >&2; exit 2; }
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

run_case() {
  local d="$1" name policy trig setup
  name="$(get "$d/name")"; policy="$(get "$d/policy")"; trig="$(get "$d/trigger")"
  printf '%s' "$policy" > "$D/p.dsl"
  if ! "$ACT" "$D/p.dsl" --out "$D/c.bin" >"$D/cc.txt" 2>&1; then
    echo "✗ $name  (compile error)"; sed 's/^/    /' "$D/cc.txt"; fail=$((fail+1)); return
  fi
  [ -f "$d/setup" ] && bash -c "$(get "$d/setup")" >/dev/null 2>&1
  : > "$D/o.txt"
  ( sleep "$SETTLE"; timeout 3 bash -c "$trig" ) >/dev/null 2>&1 &
  timeout "$WIN" "$PROC" --config "$D/c.bin" >"$D/o.txt" 2>"$D/e.txt"

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
