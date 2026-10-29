#!/usr/bin/env bash
set -euo pipefail
git -C /workspaces/repository ls-tree -r --name-only origin/artifact-ready docs | grep -Ei 'rq5|generate.*polic|polic.*generat' | head -50
