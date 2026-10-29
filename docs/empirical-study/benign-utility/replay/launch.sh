#!/usr/bin/env bash
# Four disjoint model-group shards. Each trajectory retains sequential calls
# and its original two-core execution affinity, with independent process roots.
set -euo pipefail
effect=kill
previous_pids=()
previous_starts=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --after)
      previous=$2
      [[ "$previous" =~ ^[1-9][0-9]*$ ]] && [ "$previous" != "$$" ] || exit 2
      previous_pids+=("$previous")
      previous_starts+=("$(awk '{print $22}' "/proc/$previous/stat" 2>/dev/null || true)")
      shift 2 ;;
    --effect) effect=$2; shift 2 ;;
    *) exit 2 ;;
  esac
done
for index in "${!previous_pids[@]}"; do
  previous=${previous_pids[$index]}
  previous_start=${previous_starts[$index]}
  while [ -n "$previous_start" ] && [ "$(awk '{print $22}' "/proc/$previous/stat" 2>/dev/null || true)" = "$previous_start" ]; do
    [ "$(awk '{print $3}' "/proc/$previous/stat")" != Z ] || break
    sleep 5
  done
done
[[ "$effect" = kill || "$effect" = block ]] || exit 2
python3 replay/prepare.py
raw="$WS_RAW/replay"
mkdir -p "$raw/attempts"
if [ -f "$raw/broad/dynamic/runs/t00/done.json" ] && [ ! -e "$raw/attempts/t00-valid-preflight" ]; then
  mv "$raw/broad/dynamic/runs/t00" "$raw/attempts/t00-valid-preflight"
fi
mapfile -t groups < <(python3 - <<'PY'
import os
cores=sorted(os.sched_getaffinity(0))
for i in range(4): print(','.join(map(str,cores[i*len(cores)//4:(i+1)*len(cores)//4])))
PY
)
pids=()
for shard in 0 1 2 3; do
  ids=$(python3 - "$shard" <<'PY'
import sys
i=int(sys.argv[1]);print(','.join(f't{j:02d}' for j in range(i*10,(i+1)*10)))
PY
)
  (
    conditions=(none broad scoped)
    if [ "$effect" = block ]; then conditions=(broad scoped); fi
    for condition in "${conditions[@]}"; do
      taskset -c "${groups[$shard]}" bash replay/run.sh --condition "$condition" --effect "$effect" --ids "$ids"
    done
  ) > "$raw/$effect-shard-$shard.log" 2>&1 &
  pids+=("$!")
  echo "shard=$shard pid=$! cores=${groups[$shard]} ids=$ids"
done
status=0
for pid in "${pids[@]}"; do wait "$pid" || status=1; done
echo "all shards terminal status=$status"
exit "$status"
