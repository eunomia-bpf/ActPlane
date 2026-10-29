#!/usr/bin/env python3
from pathlib import Path
import json
import subprocess
import sys
root=Path('/workspaces/exp/sandbox-baselines/raw')
tag=sys.argv[1] if len(sys.argv)>1 else 'final'
for s in ('control','codex','srt','srt-cwd','docker','original'):
    base=root/tag/s
    executions=list(base.glob('*/*/*/execution.json'))
    failures=list(base.glob('*/*/*/failure.json'))
    print(s,'finished',len(executions),'failed',len(failures))
    log=root/f'{tag}-{s}.log'
    if log.exists(): print('\n'.join(log.read_text().splitlines()[-2:]))
print(subprocess.check_output(['df','-h','/workspaces'],text=True))
