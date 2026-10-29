#!/usr/bin/env python3
"""Retain instrumentation failures and retry the same fixed trajectories.

Command/setup failures alone never trigger this retry. The original attempted
sequence and tracer output remain available in instrumentation-attempts/.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

from analyze import HERE
from dynamic_effects import parse_observer


def retry(raw,string_bytes):
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try:args=(process/'cmdline').read_bytes().decode().split('\0')
        except (OSError,UnicodeError):continue
        if any(Path(arg).name=='dynamic_run.py' for arg in args if arg):
            raise SystemExit('Finish the active replay coordinator before retrying instrumentation.')
    selected=[]
    for receipt in sorted((raw/'dynamic/runs').glob('*/done.json')):
        run=receipt.parent;done=json.loads(receipt.read_text())
        if not (run/'observer_metadata.json').exists():continue
        counts,bytes_,errors=parse_observer(run/'observer.jsonl')
        if not errors and done['observer_exit']==0:continue
        destination=raw/'dynamic/instrumentation-attempts'/run.name
        attempt=1
        while destination.with_name(destination.name+f'-attempt-{attempt}').exists():attempt+=1
        destination=destination.with_name(destination.name+f'-attempt-{attempt}')
        destination.parent.mkdir(exist_ok=True)
        shutil.move(str(run),str(destination))
        (destination/'retry_reason.json').write_text(json.dumps(dict(
            reason='Observer errors or observer exit failure. Same fixed task, full sequence and private-cache protocol replayed.',
            observer_errors=errors,observer_exit=done['observer_exit'],next_string_bytes=string_bytes,
            archived_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())),indent=2))
        selected.append(run.name)
    if selected:
        subprocess.run([sys.executable,str(HERE/'dynamic_run.py'),'--raw',str(raw),'--ids',','.join(selected),
                        '--observer-string-bytes',str(string_bytes)],check=True)
    print('Instrumentation retries:',','.join(selected) or 'none')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True)
    p.add_argument('--string-bytes',type=int,default=1024)
    args=p.parse_args();retry(args.raw,args.string_bytes)
