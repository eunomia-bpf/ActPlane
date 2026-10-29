"""Export only small recovery facts without overwriting the original guest epoch."""
import csv
import json
from pathlib import Path
import shutil

root=Path('/workspaces/exp/benign-utility')
raw=root/'raw/benchmark/expanded/vm'
out=root/'benchmark/expanded/vm/results/recovery-20261029T2005'
out.mkdir(parents=True,exist_ok=True)
for name in ('image.json','template.json','workers-launch.json','worker1-environment.json','worker1-environment.csv'):
    shutil.copy2(raw/'recovery-20261029T2005'/name,out/name)
shutil.copy2(raw/'reset-20261029T1954/reset-summary.csv',out/'reset-summary.csv')
rows=[{key:value for key,value in row.items() if key!='command'} for row in json.loads((out/'workers-launch.json').read_text())]
with (out/'workers-launch.csv').open('w',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
print('Published separate recovery epoch, preserving all original metadata.')
