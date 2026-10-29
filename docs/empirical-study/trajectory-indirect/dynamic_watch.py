#!/usr/bin/env python3
"""Bounded local resource sampling while a specified replay coordinator exists."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from analyze import HERE,write_csv


def watch(raw,pid,interval):
    target=raw/'dynamic'/'resource_samples.jsonl'
    records=[json.loads(line) for line in target.read_text().splitlines()] if target.exists() else []
    for row in records:row.setdefault('run_phase','main-v1-private-cache')
    phase=json.loads((HERE/'dynamic_config.json').read_text())['run_phase']
    while True:
        try:os.kill(pid,0)
        except ProcessLookupError:break
        usage=shutil.disk_usage(raw)
        measured=subprocess.run(['du','-sb',str(raw)],capture_output=True,text=True)
        try:size=int(measured.stdout.split()[0])
        except (ValueError,IndexError):size=''
        row=dict(utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),raw_bytes=size,
                 workspace_used_bytes=usage.used,workspace_total_bytes=usage.total,
                 workspace_used_pct=100*usage.used/usage.total,du_exit=measured.returncode,run_phase=phase)
        records.append(row)
        with target.open('a') as f:f.write(json.dumps(row)+'\n')
        write_csv(HERE/'dynamic_resource_samples.csv',records)
        time.sleep(interval)
    print('Resource sampler finished')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True)
    p.add_argument('--pid',type=int,required=True);p.add_argument('--interval',type=int,default=30)
    args=p.parse_args();watch(args.raw,args.pid,args.interval)
