#!/bin/bash
# One-click ActPlane Round-1 experiments. Steps needing root are run with sudo.
# Usage: bash docs/experimental/run_all.sh        (run from repo root or anywhere)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
echo "== build =="; make -C "$ROOT/bpf" >/dev/null 2>&1; cargo build --release --manifest-path "$ROOT/collector/Cargo.toml" >/dev/null 2>&1

echo "== Phase 0: rebuild + verify ruleset =="
( cd "$HERE/ruleset" && python3 build_ruleset.py )
python3 - <<PY
import json,subprocess
A="$ROOT/collector/target/release/actplane"
rules=[json.loads(l) for l in open("$HERE/ruleset/ruleset.jsonl")]
q=c=0
for r in rules:
    for ex in r['example_repos'][:1]:
        p=f"$ROOT/docs/corpus/{ex['repo'].replace('/','__')}/{ex['family']}"
        try:
            L=open(p,encoding='utf-8',errors='replace').read().splitlines()
            if ex['quote'].strip()[:25] in (L[ex['line_no']-1] if 0<ex['line_no']<=len(L) else ""): q+=1
        except FileNotFoundError: pass
    if subprocess.run([A,'--rule',r['dsl'],'compile','--out','/tmp/_v.bin'],capture_output=True).returncode==0: c+=1
print(f"ruleset: {len(rules)} rules, quotes-verified={q}, dsl-compiles={c}")
PY

echo "== Exp-A cross-path (sudo) =="; sudo -n bash "$HERE/expA_cross_path/run.sh"      | tail -3
echo "== Exp-B overhead (sudo) =="; EXPB_N=${EXPB_N:-12} bash "$HERE/expB_overhead/run.sh" | tail -4
echo "== Exp-C precision (sudo) =="; sudo -n bash "$HERE/expC_false_positive/run.sh"   | tail -2
echo "== Exp-D agent loop (user; C2 uses sudo internally) =="; EXPD_N=${EXPD_N:-5} bash "$HERE/expD_agent_loop/run_agent.sh" | tail -2
echo "== Exp-E funnel (offline) =="; ( cd "$HERE" && python3 expE_expressiveness/../expE_expressiveness/funnel.py 2>/dev/null || echo "see expE_expressiveness/funnel.md" )
echo "== Exp-G rule-count scalability (sudo) =="; sudo -n bash "$HERE/expG_rule_scale/run.sh" | tail -8
echo "== done. See docs/experimental/README.md and each exp*/ result file. =="