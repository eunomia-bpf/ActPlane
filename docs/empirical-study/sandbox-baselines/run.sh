#!/usr/bin/env bash
set -euo pipefail
tag=${1:-final}
export SANDBOX_RUN_TAG="$tag"
python3 provenance.py
pids=()
for system in control codex srt srt-cwd docker original; do
  python3 study.py --systems "$system" --tag "$tag" > "$WS_RAW/$tag-$system.log" 2>&1 &
  pids+=("$!")
done
failed=0
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
echo "all workers terminal; failed=$failed"
python3 analyze.py
python3 report.py
