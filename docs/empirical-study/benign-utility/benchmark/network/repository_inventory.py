"""Inspect the exact externally referenced project without populating any task."""
import csv,hashlib,json,subprocess,time
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark/network')
OUT=BASE.parents[2]/'benchmark/network/results'
folder=BASE/'repository-inventory';folder.mkdir(parents=True,exist_ok=True)
url='https://github.com/SPOCKnots/pyknotid.git';ref='0.5.3'
attempt=1+len(list(folder.glob('checkout-*')));checkout=folder/f'checkout-{attempt}'
with (folder/f'clone-{attempt}.log').open('w') as log:
 result=subprocess.run(['git','clone','--depth','1','--branch',ref,url,str(checkout)],stdout=log,stderr=subprocess.STDOUT)
if result.returncode:raise RuntimeError('Static referenced-project clone failed; retain log, do not substitute a different task')
head=subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()
files=subprocess.check_output(['git','-C',str(checkout),'ls-files'],text=True).splitlines()
instructions=[dict(path=p,sha256=hashlib.sha256((checkout/p).read_bytes()).hexdigest()) for p in files if Path(p).name in ('AGENTS.md','CLAUDE.md','.cursorrules')]
row=dict(task='build-cython-ext',url=url,declared_ref=ref,resolved_commit=head,instruction_files=len(instructions),instruction_inventory=json.dumps(instructions,sort_keys=True),raw_checkout=str(checkout),attempt=attempt,utc=time.strftime('%FT%TZ',time.gmtime()),purpose='static instruction inventory only; never mounted into benchmark task')
OUT.mkdir(parents=True,exist_ok=True)
with (OUT/'external-repository-inventory.csv').open('w',newline='') as handle:
 writer=csv.DictWriter(handle,fieldnames=list(row));writer.writeheader();writer.writerow(row)
print(json.dumps(row),flush=True)
