#!/usr/bin/env bash
# Mechanism preflight only. This is not a benchmark task or a paper result.
set -euo pipefail
if ! test -r /sys/kernel/security/lsm; then
  mount -t securityfs securityfs /sys/kernel/security
fi
printf 'Active LSMs: '; cat /sys/kernel/security/lsm
mkdir -p "$WS_RAW/kernel-preflight"
export KERNEL_PREFLIGHT_ID="${KERNEL_PREFLIGHT_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
if test -z "${ACTPLANE_BIN:-}"; then
  cp /workspaces/lanes/translation-models/target/release/actplane "$WS_RAW/actplane"
  export ACTPLANE_BIN="$WS_RAW/actplane"
fi
python3 - <<'PY'
import json, os, pathlib, sys, tempfile
sys.path.insert(0, 'scripts')
from actplane_adapter import execute
root = pathlib.Path(os.environ['WS_RAW']) / 'kernel-preflight' / os.environ['KERNEL_PREFLIGHT_ID']
for mode in ('parent', 'child'):
    with tempfile.TemporaryDirectory(prefix='injection_kernel_preflight_') as temp:
        cwd = pathlib.Path(temp)
        guarded = cwd / 'guarded.txt'
        guarded.write_text('inert preflight text\n')
        policy = f'rule preflight:\n  block open file "{guarded}"\n  because "inert preflight guard"\n'
        code = ('import pathlib,sys; p=pathlib.Path(sys.argv[1]); '
                'allowed=p.parent/"allowed.txt"; allowed.write_text("permitted"); '
                'assert allowed.read_text()=="permitted"; '
                'print("legitimate read/write succeeded");\ntry:\n '
                'print(p.read_text());sys.exit(3)\nexcept PermissionError:\n '
                'print("kernel denied inert read");sys.exit(0)')
        command = [sys.executable, '-c', code, str(guarded)]
        result = execute(policy, mode, command, cwd, root / mode, timeout=30)
        print(json.dumps({'mode':mode,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}), flush=True)
        if result.returncode != 0:
            raise SystemExit(result.returncode)
PY
