"""Export only small, nonsecret VM capability facts; keep all full logs remote."""
import csv
import json
from pathlib import Path
import shutil
import urllib.request

base=Path('/workspaces/exp/benign-utility')
raw=base/'raw/benchmark/expanded/vm'
out=base/'benchmark/expanded/vm/results'
out.mkdir(parents=True,exist_ok=True)
image=json.loads((raw/'image.json').read_text())
immutable_base='https://cloud.debian.org/images/cloud/trixie/20261026-2643/'
immutable_name='debian-13-genericcloud-amd64-20261026-2643.qcow2'
checksums=urllib.request.urlopen(immutable_base+'SHA512SUMS').read().decode()
expected=next(line.split()[0] for line in checksums.splitlines() if line.split()[-1].lstrip('*')==immutable_name)
assert expected==image['sha512'], 'Archived official image differs from the original downloaded bytes'
image.update(immutable_equivalent_url=immutable_base+immutable_name,official_build_version='20261026-2643',
             immutable_checksum_url=immutable_base+'SHA512SUMS',
             immutable_equivalence='Archived provider SHA512 matches original downloaded image; original URL/hash facts retained')
(raw/'image.json').write_text(json.dumps(image,indent=2)+'\n')
for name in ['image.json','template.json','workers-launch.json'] + [f'worker{n}-environment.{suffix}' for n in (1,2,3) for suffix in ('json','csv')]:
    shutil.copy2(raw/name,out/name)
rows=[]
for item in json.loads((raw/'workers-launch.json').read_text()):
    row={key:value for key,value in item.items() if key!='command'}
    rows.append(row)
with (out/'workers-launch.csv').open('w',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
print('Published VM launch and per-worker kernel/LSM/hash metadata; no disk images or logs exported.')
