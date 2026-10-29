"""Export only small, nonsecret VM capability facts; keep all full logs remote."""
import csv
import json
from pathlib import Path
import shutil

base=Path('/workspaces/exp/benign-utility')
raw=base/'raw/benchmark/expanded/vm'
out=base/'benchmark/expanded/vm/results'
out.mkdir(parents=True,exist_ok=True)
for name in ['image.json','template.json','workers-launch.json'] + [f'worker{n}-environment.{suffix}' for n in (1,2,3) for suffix in ('json','csv')]:
    shutil.copy2(raw/name,out/name)
rows=[]
for item in json.loads((raw/'workers-launch.json').read_text()):
    row={key:value for key,value in item.items() if key!='command'}
    rows.append(row)
with (out/'workers-launch.csv').open('w',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
print('Published VM launch and per-worker kernel/LSM/hash metadata; no disk images or logs exported.')
