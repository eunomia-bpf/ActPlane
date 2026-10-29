#!/usr/bin/env python3
"""Compress only closed audit files owned by this lane; never discard raw data."""
import gzip
from pathlib import Path
import shutil
import sys
from study import RAW
tag=sys.argv[1]
target=(RAW/tag).resolve()
assert target.parent==RAW.resolve()
count=0
for done in target.glob('*/*/*/*/execution.json'):
    for name in ('syscalls.log','before.json','after.json'):
        path=done.parent/name
        if path.exists():
            with path.open('rb') as src,gzip.open(str(path)+'.gz','wb',compresslevel=3) as dst:
                shutil.copyfileobj(src,dst)
            path.unlink()
            count+=1
print('compressed closed raw files',count,flush=True)
