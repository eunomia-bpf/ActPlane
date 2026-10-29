"""Predeclare a reproducible outcome-independent expansion from the pinned release."""
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

BASE=Path('/workspaces/exp/benign-utility/raw/benchmark')
ROOT=BASE.parent.parent/'benchmark/expanded'
OUT=ROOT/'results'
SEED='benign-utility-expansion-20261029-v1'
COMMIT='69671fbaac6d67a7ef0dfec016cc38a64ef7a77c'

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def write(name, rows):
    with (OUT/name).open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    assert subprocess.check_output(['git','-C',str(BASE/'terminal-bench-2'),'rev-parse','HEAD'],text=True).strip()==COMMIT
    excluded={r['task'] for folder in ('results','network/results') for r in csv.DictReader((ROOT.parent/folder/'tasks.csv').open())}
    # Exclude every task with an existing model attempt, including preliminary cells.
    for directory in (BASE/'jobs',BASE/'network/jobs',BASE.parent/'benchmark-cli/jobs'):
        for result in directory.glob('*/*/result.json'):
            data=json.loads(result.read_text())
            task=data.get('task_name')
            if task: excluded.add(task)
    catalog=[]
    for config in sorted((BASE/'terminal-bench-2').glob('*/task.toml')):
        task=config.parent.name;t=tomllib.loads(config.read_text());env=t['environment']
        cpus=env.get('cpus',1);memory=env.get('memory_mb',2048);storage=env.get('storage_mb',10240);gpus=env.get('gpus',0)
        reasons=[]
        if task in excluded:reasons.append('previously_executed_or_prespecified_subcohort')
        if not env.get('docker_image'):reasons.append('no_official_prebuilt_image')
        if gpus:reasons.append('requires_gpu')
        if cpus>8:reasons.append('declared_cpu_above_eight')
        if memory>16384:reasons.append('declared_memory_above_16GiB')
        if storage>10240:reasons.append('declared_storage_above_10GiB')
        rank=hashlib.sha256((SEED+'\n'+task).encode()).hexdigest()
        catalog.append(dict(task=task,eligible=int(not reasons),reason=';'.join(reasons) or 'eligible',selection_hash=rank,
            cpus=cpus,memory_mb=memory,storage_mb=storage,gpus=gpus,agent_timeout_s=t['agent']['timeout_sec'],
            verifier_timeout_s=t['verifier']['timeout_sec'],official_image=env.get('docker_image',''),
            instruction_sha256=digest(config.parent/'instruction.md'),task_config_sha256=digest(config),
            test_sha256=digest(config.parent/'tests/test.sh'),dataset_commit=COMMIT))
    chosen=sorted((r for r in catalog if r['eligible']),key=lambda r:r['selection_hash'])[:18]
    assert len(chosen)==18
    tasks=[]
    for i,row in enumerate(chosen):
        order=['a','b','c'];order=order[i%3:]+order[:i%3]
        tasks.append(dict(**row,condition_order=','.join(order),cohort='expanded_20261029'))
    names={r['task'] for r in tasks}
    for row in catalog:row['selected']=int(row['task'] in names)
    write('selection-catalog.csv',catalog)
    write('tasks.csv',tasks)
    protected=[]
    for folder in ('results','network/results'):
        for path in sorted((ROOT.parent/folder).glob('*.csv')):
            protected.append(dict(path=str(path.relative_to(ROOT.parent)),sha256=digest(path)))
    write('protected-results.csv',protected)
    print(json.dumps(dict(seed=SEED,selected=[r['task'] for r in tasks],eligible=sum(r['eligible'] for r in catalog),catalog=len(catalog)),indent=2))

if __name__=='__main__':main()
