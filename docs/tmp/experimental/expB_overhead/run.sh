#!/bin/bash
# Exp-B: ActPlane STEADY-STATE overhead on REAL workloads (no synthetic microbenchmarks).
# Method: attach ActPlane ONCE via `actplane watch` (audit, ~10-rule policy — taint engine + rule
# loop run on every exec/open/connect system-wide), then time each real workload N times WITH it
# attached vs WITHOUT (bare). Isolates per-syscall overhead from the one-time BPF attach cost.
# Report wall-clock p50/p99 + median overhead ratio. Run as root.
set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
A="$ROOT/collector/target/release/actplane"; OUT="$(cd "$(dirname "$0")" && pwd)"
POL="$OUT/overhead_policy.dsl"; N="${EXPB_N:-12}"; TMP="$(mktemp -d)"
make -C "$ROOT/bpf" >/dev/null 2>&1; cargo build --release --manifest-path "$ROOT/collector/Cargo.toml" >/dev/null 2>&1

WL_NAMES=(cc-compile git-loop find-grep)
declare -A WL
WL[cc-compile]="for i in \$(seq 40); do cc -O1 -o /tmp/ccb_\$i -x c - <<<'int f(int x){return x*x+1;} int main(){int s=0;for(int i=0;i<9;i++)s+=f(i);return s;}' 2>/dev/null; done"
WL[git-loop]="cd $ROOT; for i in \$(seq 120); do git status >/dev/null; git log -1 >/dev/null; git diff --stat HEAD~3 >/dev/null 2>&1; done"
WL[find-grep]="cd $ROOT; for i in \$(seq 30); do grep -rl taint bpf >/dev/null; find bpf -name '*.c' >/dev/null; done"

pctl(){ python3 -c "import sys,math;v=sorted(float(x) for x in sys.stdin.read().split() if x)
def p(q):
  i=min(len(v)-1,max(0,int(math.ceil(q/100*len(v))-1))); return v[i] if v else 0
print(f'{p(50):.3f} {p(99):.3f} {sum(v)/len(v):.3f}')"; }
timeit(){ /usr/bin/time -f '%e' -o "$TMP/t" bash -c "$1" >/dev/null 2>&1; cat "$TMP/t"; }

declare -A WITH BARE
echo "warmup..."; eval "${WL[git-loop]}" >/dev/null 2>&1

# ---- phase 1: ActPlane attached (watch, audit, stays running) ----
echo "attaching actplane watch..."
sudo -n -E "$A" --rule "$(cat "$POL")" watch >"$TMP/watch.log" 2>&1 &
for i in $(seq 40); do grep -qiE 'ready|running|sources' "$TMP/watch.log" && break; sleep 0.3; done
sleep 1
grep -qiE 'ready|running|sources' "$TMP/watch.log" && echo "attached=yes" || { echo "ATTACH FAILED"; tail -5 "$TMP/watch.log"; }
for w in "${WL_NAMES[@]}"; do
  acc=""; for i in $(seq "$N"); do acc+="$(timeit "${WL[$w]}") "; done; WITH[$w]="$acc"
done
sudo -n pkill -f 'actplane.*watch' 2>/dev/null; sudo -n pkill -f 'tmp.*/process' 2>/dev/null; sleep 1

# ---- phase 2: bare (no ActPlane) ----
echo "detached; bare runs..."
for w in "${WL_NAMES[@]}"; do
  acc=""; for i in $(seq "$N"); do acc+="$(timeit "${WL[$w]}") "; done; BARE[$w]="$acc"
done

# ---- report ----
csv="$OUT/overhead.csv"; md="$OUT/overhead.md"
echo "workload,mode,p50_s,p99_s,mean_s,runs" > "$csv"
{ echo "# Exp-B 真实负载稳态开销 (audit, attach-once watch, N=$N)"; echo
  echo "ActPlane 经 \`watch\` 一次性挂载(taint 引擎 + 规则循环在每个 syscall 上运行);对比同一真实负载挂载前后的墙钟。"; echo
  echo "| workload | bare p50/p99 (s) | +ActPlane p50/p99 (s) | median 开销 |"
  echo "|---|---|---|---|"; } > "$md"
for w in "${WL_NAMES[@]}"; do
  read bp50 bp99 bmean <<<"$(echo "${BARE[$w]}" | tr ' ' '\n' | pctl)"
  read ap50 ap99 amean <<<"$(echo "${WITH[$w]}" | tr ' ' '\n' | pctl)"
  ratio=$(python3 -c "print(f'{($ap50-$bp50)/$bp50*100:+.1f}%' if $bp50>0 else 'n/a')")
  echo "$w,bare,$bp50,$bp99,$bmean,$N" >> "$csv"
  echo "$w,actplane,$ap50,$ap99,$amean,$N" >> "$csv"
  echo "| $w | $bp50 / $bp99 | $ap50 / $ap99 | $ratio |" >> "$md"
  printf '   %-10s bare p50=%ss  +ActPlane p50=%ss  (%s)\n' "$w" "$bp50" "$ap50" "$ratio"
done
echo "wrote $md / $csv"; rm -rf "$TMP"