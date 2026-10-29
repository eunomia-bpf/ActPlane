#!/usr/bin/env bash
set -euo pipefail
/workspaces/.agent-state/actplane-trajectory-indirect/venv/bin/python replay/run.py "$@"
