#!/usr/bin/env bash
set -euo pipefail
cd "$WS_RAW/upstream/OS-Harm"
sed -n '60,102p' run.py
sed -n '1,180p' desktop_env/providers/docker/manager.py
grep -nE 'https|zip|qcow|download|DISK|image' desktop_env/providers/docker/*.py
grep -nE 'openai|base_url|gpt|a11y|model|raise' mm_agents/agent.py | head -100
cd "$WS_RAW/upstream/RepoGuardBench"
cat repoguard/agents/ollama_backend.py
cat repoguard/agents/agent_loop.py
cat repoguard/defenses/registry.py
cat repoguard/sandbox/workspace.py
cat repoguard/scoring/scorer.py
