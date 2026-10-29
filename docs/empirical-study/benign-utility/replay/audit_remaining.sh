#!/usr/bin/env bash
# Forensic repeats of actually intervened complete native-block trajectories.
# Existing t05/t20 audits are reused; no forensic result enters primary timing.
set -euo pipefail
if [ "${1:-}" = --after ]; then
  tail --pid="$2" -f /dev/null
  shift 2
fi
[ "$#" = 0 ] || exit 2
python3 replay/analyze.py --effect block
mapfile -t batches < <(python3 - <<'PY'
import csv,os
from pathlib import Path
rows=list(csv.DictReader((Path(os.environ['WS_RAW']).parent/'replay/results/runs.csv').open()))
cores=sorted(os.sched_getaffinity(0))
for shard in range(4):
    ids=[r['dynamic_id'] for r in rows if r['condition']=='broad' and r['coverage']=='complete'
         and int(r['intervention_events'])>0 and int(r['dynamic_id'][1:])//10==shard]
    cpu=','.join(map(str,cores[shard*len(cores)//4:(shard+1)*len(cores)//4]))
    print(cpu+' '+','.join(ids))
PY
)
pids=()
for shard in 0 1 2 3; do
  read -r cpu ids <<< "${batches[$shard]}"
  [ -n "${ids:-}" ] || continue
  taskset -c "$cpu" bash replay/run.sh --condition broad --effect block --open-audit --ids "$ids" \
    > "$WS_RAW/replay/open-audit-shard-$shard.log" 2>&1 &
  pids+=("$!")
  echo "forensic shard=$shard pid=$! ids=$ids"
done
status=0
for pid in "${pids[@]}"; do wait "$pid" || status=1; done
python3 replay/open_audit.py
exit "$status"
