"""Derive small resource results; run in the remote Workspace."""
import csv
import json
import os
from pathlib import Path
import shutil

raw=Path(os.environ['WS_RAW'])
out=raw.parent/'results'
out.mkdir(exist_ok=True)
f=json.loads((raw/'feasibility.json').read_text())
z=json.loads((raw/'image_inventory.json').read_text())
rows=[]
for key,value in f['disk'].items():
    rows.append({'measure':f'filesystem_{key}_bytes','value':value,'source':'feasibility.py:shutil.disk_usage'})
rows.extend([
    {'measure':'utilization_ceiling_percent','value':85,'source':'user instruction'},
    {'measure':'osworld_archive_bytes','value':z['zip_bytes'],'source':'image_inventory.py:HTTP Range ZIP directory'},
    {'measure':'osworld_extracted_image_bytes','value':z['entries'][0]['uncompressed'],'source':'image_inventory.py:ZIP64 entry'},
    {'measure':'osworld_default_archive_plus_image_bytes','value':z['zip_bytes']+z['entries'][0]['uncompressed'],'source':'derived sum'},
    {'measure':'osharm_base_tasks','value':len(f['osharm_injection_tasks']),'source':'official test_injection.json'},
    {'measure':'osharm_injection_cases','value':sum(t['cases'] for t in f['osharm_injection_tasks']),'source':'official injection vectors/goals'},
])
with (out/'resources.csv').open('w',newline='') as h:
    w=csv.DictWriter(h,fieldnames=['measure','value','source']);w.writeheader();w.writerows(rows)
for name in ('feasibility.json','image_inventory.json','environment.txt'):
    if (raw/name).exists():shutil.copyfile(raw/name,out/name)
print((out/'resources.csv').read_text())
