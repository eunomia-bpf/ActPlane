#!/bin/bash
# Exp-C: precision — false positives (legit work must NOT trip) + allow-paths
# (declassify / after / lineage gates must let the gated op through, while the
# un-gated op is still denied). audit mode; AGENT seeded via actplane run. Run as root.
set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
A="$ROOT/collector/target/release/actplane"; OUT="$(cd "$(dirname "$0")" && pwd)"
D=/tmp/expC; SET=2.8
make -C "$ROOT/bpf" >/dev/null 2>&1; cargo build --release --manifest-path "$ROOT/collector/Cargo.toml" >/dev/null 2>&1
rm -rf "$D"; mkdir -p "$D/work" "$D/data"; chmod -R 777 "$D"
cp /bin/true "$D/zgit"; cp /bin/true "$D/pytest"; cp /bin/true "$D/confirm"; cp /bin/true "$D/redact"
echo secret > "$D/sec.env"; echo plain > "$D/work/notes.txt"

# count violations emitted while running <trigger> under <rule> (AGENT-labeled, audit)
nviol(){ # rule trig
  sudo -n -E timeout 7 "$A" --rule "$1" run -- bash -c "sleep $SET; $2" 2>/dev/null | grep -cE 'VIOLATION|KILLED|🚫'
}
P=0; F=0; pass(){ echo "  ✓ $1"; P=$((P+1)); }; fail(){ echo "  ✗ $1 ($2)"; F=$((F+1)); }
chk(){ local name="$1" want="$2" got="$3"; [ "$got" = "$want" ] && pass "$name (viol=$got)" || fail "$name" "want $want got $got"; }

echo "== false positives (legit work must NOT trip) =="
RULE_secret='label AGENT
source SECRET = file "**/sec.env"
rule no-exfil:
  deny connect endpoint "*" if SECRET
  effect audit
  reason "x"
declassify SECRET by exec "**/redact"'
chk "FP1 read non-secret then connect (no taint)" 0 "$(nviol "$RULE_secret" "read x < $D/work/notes.txt; timeout 1 bash -c 'exec 3<>/dev/tcp/1.2.3.4/80' 2>/dev/null; true")"

RULE_commit='label AGENT
rule test-before-commit:
  deny exec "**/zgit" @arg "commit" if AGENT unless after exec "**/pytest"
  effect audit
  reason "x"'
chk "FP2 zgit status (not a commit)" 0 "$(nviol "$RULE_commit" "$D/zgit status")"

RULE_write='label AGENT
rule confine:
  deny write file "/etc/**" if AGENT
  effect audit
  reason "x"'
chk "FP3 write inside workspace (/work)" 0 "$(nviol "$RULE_write" "echo hi > $D/work/out.txt")"

echo "== allow-paths (gate satisfied => allowed; un-gated => denied) =="
# declassify: secret->connect denied; secret->redact->connect allowed
chk "AP1a secret->connect (un-gated)  DENIED"  1 "$(nviol "$RULE_secret" "read x < $D/sec.env; timeout 1 bash -c 'exec 3<>/dev/tcp/1.2.3.4/80' 2>/dev/null; true")"
chk "AP1b secret->redact->connect     ALLOWED" 0 "$(nviol "$RULE_secret" "read x < $D/sec.env; $D/redact -c 'timeout 1 bash -c \"exec 3<>/dev/tcp/5.6.7.8/80\"' 2>/dev/null; true")"
# after: commit without pytest denied; after pytest allowed
chk "AP2a zgit commit (no pytest)      DENIED"  1 "$(nviol "$RULE_commit" "$D/zgit commit")"
chk "AP2b pytest then zgit commit      ALLOWED" 0 "$(nviol "$RULE_commit" "$D/pytest -c true; $D/zgit commit")"
# lineage: force without confirm denied; with confirm allowed
RULE_force='label AGENT
rule confirm-destructive:
  deny exec "**/zgit" @arg "--force" if AGENT unless lineage-includes exec "**/confirm"
  effect audit
  reason "x"'
chk "AP3a zgit --force (no confirm)     DENIED"  1 "$(nviol "$RULE_force" "$D/zgit --force")"
chk "AP3b confirm then zgit --force     ALLOWED" 0 "$(nviol "$RULE_force" "$D/confirm -c \"$D/zgit --force\"")"

echo "== Exp-C: $P passed, $F failed =="
{ echo "# Exp-C 精度:误报 + 放行路径 (audit)"; echo
  echo "$P/$((P+F)) checks passed. 误报组:合法操作 0 触发;放行组:满足 gate 的操作放行(0),未满足仍拦(1)。"; } > "$OUT/results.md"
echo "wrote $OUT/results.md"