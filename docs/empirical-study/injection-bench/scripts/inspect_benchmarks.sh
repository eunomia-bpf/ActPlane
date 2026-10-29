#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$WS_RAW/upstream"
for spec in 'tml-epfl/os-harm OS-Harm' 'DaoyuanLi2816/RepoGuardBench RepoGuardBench'; do
  read -r repo name <<< "$spec"
  if [ ! -d "$WS_RAW/upstream/$name/.git" ]; then
    git clone --depth 1 "https://github.com/$repo.git" "$WS_RAW/upstream/$name"
  fi
  printf '\nSOURCE %s ' "$name"
  git -C "$WS_RAW/upstream/$name" rev-parse HEAD
done
cd "$WS_RAW/upstream/RepoGuardBench"
find repoguard -type f | sort
cat configs/models.yaml configs/experiment.yaml 2>/dev/null || true
sed -n '1,250p' scripts/run_experiments.py
cd "$WS_RAW/upstream/OS-Harm"
printf '\nOS-Harm CLI and providers\n'
grep -nE 'observation_type|provider|model|inject|judge|add_argument' run.py | head -90
cat evaluation_examples/test_injection.json
df -h /workspaces
