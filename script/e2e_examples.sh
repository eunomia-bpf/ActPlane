#!/bin/bash
# ActPlane end-to-end example suite: loads each docs/taint-dsl.md example (E1–E12)
# as its own compiled policy, fires a trigger, and checks the expected violation
# fires AND the allowed/declassified case is suppressed. Run as root:
#   sudo bash test/e2e_examples.sh
#
# Each example is loaded separately on purpose: several are mutually contradictory
# by design (E9 "no git at all" subsumes E5/E11 "git ok if tested/confirmed"), so a
# single merged policy cannot show both E9 and E5's allow-path. Triggers use copies
# of /bin/bash renamed to the agent/tool names (exec sources match comm) and
# /bin/true renamed to "git" (so @arg cases get a clean argv without side effects).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACT="$ROOT/collector/target/release/actplane"
PROC="$ROOT/bpf/process"
D=/tmp/ape
SETTLE=2.8   # let BPF attach before triggers fire
WIN=6        # loader lifetime per case

rm -rf "$D"; mkdir -p "$D/work" "$D/downloads" "$D/customers" "$D/data" "$D/shared"
for h in codex research-agent task-a task-b human-approve confirm redact migrate pytest; do cp /bin/bash "$D/$h"; done
cp /bin/true "$D/git"; cp /bin/true "$D/deploy"
echo secret > "$D/sec.env"; echo inject > "$D/downloads/inj"
echo pii > "$D/customers/rec"; echo db > "$D/data/prod.db"

pass=0; fail=0
# run NAME TRIGGER WANT_REGEX [NOTWANT_REGEX]   (policy already written to $D/p.dsl)
run() {
  local name="$1" trig="$2" want="$3" notwant="${4:-}"
  if ! "$ACT" "$D/p.dsl" --out "$D/c.bin" >"$D/cc.txt" 2>&1; then
    echo "✗ $name  (compile error)"; sed 's/^/    /' "$D/cc.txt"; fail=$((fail+1)); return
  fi
  : > "$D/o.txt"
  ( sleep "$SETTLE"; timeout 3 bash -c "$trig" ) >/dev/null 2>&1 &
  timeout "$WIN" "$PROC" --config "$D/c.bin" >"$D/o.txt" 2>"$D/e.txt"
  local ok=1 why=""
  if [ -n "$want" ]    && ! grep -Eq "$want" "$D/o.txt"; then ok=0; why="missing /$want/"; fi
  if [ -n "$notwant" ] &&   grep -Eq "$notwant" "$D/o.txt"; then ok=0; why="$why; leaked /$notwant/"; fi
  if [ "$ok" = 1 ]; then echo "✓ $name"; pass=$((pass+1));
  else echo "✗ $name  ($why)"; sed 's/^/    /' "$D/o.txt"; fail=$((fail+1)); fi
}
# runN NAME TRIGGER N_EXPECTED REGEX  — exactly N matching violation lines
runN() {
  local name="$1" trig="$2" n="$3" re="$4"
  if ! "$ACT" "$D/p.dsl" --out "$D/c.bin" >"$D/cc.txt" 2>&1; then
    echo "✗ $name  (compile error)"; sed 's/^/    /' "$D/cc.txt"; fail=$((fail+1)); return
  fi
  : > "$D/o.txt"
  ( sleep "$SETTLE"; timeout 3 bash -c "$trig" ) >/dev/null 2>&1 &
  timeout "$WIN" "$PROC" --config "$D/c.bin" >"$D/o.txt" 2>"$D/e.txt"
  local got; got=$(grep -Ec "$re" "$D/o.txt")
  if [ "$got" = "$n" ]; then echo "✓ $name"; pass=$((pass+1));
  else echo "✗ $name  (expected $n /$re/, got $got)"; sed 's/^/    /' "$D/o.txt"; fail=$((fail+1)); fi
}

echo "== ActPlane E1–E12 live enforcement =="

# E1 — secret no-exfil + declassify (also covers E8). fire: secret->connect 1.1.1.1;
# suppress: same flow through redact -> connect 1.1.1.2.
cat > "$D/p.dsl" <<EOF
source SECRET = file "**/sec.env"
rule no-exfil:
  deny connect endpoint "*" if SECRET
  reason "secret data must not leave the host; redact first"
declassify SECRET by exec "**/redact"
EOF
run "E1  secret no-exfil (+E8 declassify)" \
  "read x < $D/sec.env; timeout 1 bash -c 'exec 3<>/dev/tcp/1.1.1.1/80'; $D/redact -c 'timeout 1 bash -c \"exec 4<>/dev/tcp/1.1.1.2/80\"'" \
  '"target":"1.1.1.1"' '"target":"1.1.1.2"'

# E2 — prompt-injection => no privileged action + endorse. fire: untrusted->git push;
# suppress: human-approve endorses REVIEWED before git push.
# NB: doc writes "**/downloads/**"; the kernel matcher has no infix glob (only
# exact/prefix/suffix/any), so we use the concrete prefix form here.
cat > "$D/p.dsl" <<EOF
source UNTRUST = file "$D/downloads/**"
rule no-injected-priv:
  deny exec "**/git" @arg "push" if UNTRUST and not REVIEWED
  reason "action derived from untrusted input; needs human review"
endorse REVIEWED by exec "**/human-approve"
EOF
runN "E2  injected-priv (+endorse suppress)" \
  "$D/codex -c 'read x < $D/downloads/inj; $D/git push'; $D/codex -c 'read x < $D/downloads/inj; $D/human-approve -c \"$D/git push\"'" \
  1 '"comm":"git"'

# E3 — mandatory mediation. fire: codex opens prod.db; suppress: via migrate lineage.
cat > "$D/p.dsl" <<EOF
rule mediate-proddb:
  deny open file "**/prod.db" unless lineage-includes exec "**/migrate"
  reason "prod.db is reachable only through the migration tool"
EOF
runN "E3  mandatory mediation (lineage)" \
  "$D/codex -c 'cat $D/data/prod.db'; $D/migrate -c 'cat $D/data/prod.db'" \
  1 '"target":"[^"]*prod.db"'

# E4 — workspace confinement. fire: unlink outside work/; suppress: inside work/.
echo > "$D/outside.txt"; echo > "$D/work/in.txt"
cat > "$D/p.dsl" <<EOF
source AGENT = exec "**/codex"
rule confine-writes:
  deny unlink file "$D/**" if AGENT unless target "$D/work/**"
  reason "agent may only modify its workspace work/**"
EOF
run "E4  workspace confinement" \
  "$D/codex -c 'rm -f $D/outside.txt'; $D/codex -c 'rm -f $D/work/in.txt'" \
  '"target":"[^"]*outside.txt"' '"target":"[^"]*work/in.txt"'

# E5 — test-before-commit (temporal). fire: commit w/o pytest; suppress: after pytest.
cat > "$D/p.dsl" <<EOF
source AGENT = exec "**/codex"
rule test-before-commit:
  deny exec "**/git" @arg "commit" if AGENT unless after exec "**/pytest"
  reason "run the test suite before committing"
EOF
runN "E5  test-before-commit (after)" \
  "$D/codex -c '$D/git commit'; $D/codex -c '$D/pytest -c true; $D/git commit'" \
  1 '"comm":"git"'

# E6 — read-only sub-agent. fire: research-agent execs git.
cat > "$D/p.dsl" <<EOF
source RESEARCH = exec "**/research-agent"
rule research-readonly:
  deny exec "**/git" if RESEARCH
  reason "research sub-agent is read-only; spawn an executor for changes"
EOF
run "E6  read-only sub-agent scope" \
  "$D/research-agent -c '$D/git status'" \
  '"comm":"git"'

# E7 — transitive secret derivation. A taints out.json; unrelated B reads it & connects.
cat > "$D/p.dsl" <<EOF
source SECRET = file "**/sec.env"
rule no-exfil:
  deny connect endpoint "*" if SECRET
  reason "secret data must not leave the host; redact first"
EOF
run "E7  transitive secret derivation" \
  "$D/codex -c 'read x < $D/sec.env; echo derived > $D/data/out.json'; sleep 0.3; /bin/bash -c 'read y < $D/data/out.json; timeout 1 bash -c \"exec 3<>/dev/tcp/3.3.3.3/80\"'" \
  '"target":"3.3.3.3"'

# E9 — cross-tool / unbypassable. fire: codex->git; suppress: plain bash->git.
cat > "$D/p.dsl" <<EOF
source AGENT = exec "**/codex"
rule no-git:
  deny exec "**/git" if AGENT
  reason "this agent must not invoke git on any path"
EOF
runN "E9  cross-tool unbypassable git" \
  "$D/codex -c '$D/git status'; /bin/bash -c '$D/git status'" \
  1 '"comm":"git"'

# E10 — provenance-scoped egress (hostname *.internal adapted to IP scope 127.x).
# fire: PII proc -> external 8.8.8.8; suppress: -> internal 127.0.0.1.
cat > "$D/p.dsl" <<EOF
source PII = file "$D/customers/**"
rule pii-egress:
  deny connect endpoint "*" if PII unless target "127."
  reason "PII-handling process may only reach internal endpoints"
EOF
run "E10 provenance-scoped egress" \
  "$D/codex -c 'read x < $D/customers/rec; timeout 1 bash -c \"exec 3<>/dev/tcp/8.8.8.8/80\"; timeout 1 bash -c \"exec 4<>/dev/tcp/127.0.0.1/80\"'" \
  '"target":"8.8.8.8"' '"target":"127.0.0.1"'

# E11 — destructive op requires confirmation gate (lineage). fire: --force w/o confirm;
# suppress: --force with confirm in lineage.
cat > "$D/p.dsl" <<EOF
source AGENT = exec "**/codex"
rule confirm-destructive:
  deny exec "**/git" @arg "--force" if AGENT unless lineage-includes exec "**/confirm"
  reason "destructive action needs an explicit confirm step in its lineage"
EOF
runN "E11 destructive needs confirm gate" \
  "$D/codex -c '$D/git --force'; $D/codex -c '$D/confirm -c \"$D/git --force\"'" \
  1 '"comm":"git"'

# E12 — task non-interference (multi-label). fire: proc carrying TASK_A and TASK_B
# commits; suppress: TASK_A alone.
cat > "$D/p.dsl" <<EOF
source TASK_A = exec "**/task-a"
source TASK_B = exec "**/task-b"
rule no-cross-task-commit:
  deny exec "**/git" @arg "commit" if TASK_A and TASK_B
  reason "a commit must not mix data from task A and task B"
EOF
runN "E12 task non-interference (A and B)" \
  "$D/task-a -c '$D/task-b -c \"$D/git commit\"'; $D/task-a -c '$D/git commit'" \
  1 '"comm":"git"'

echo "== result: $pass passed, $fail failed =="
exit $([ "$fail" = 0 ] && echo 0 || echo 1)
