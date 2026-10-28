#!/usr/bin/env python3
"""Hash retained replay inputs/evidence and record local tool versions, without credentials."""
import argparse
import csv
import hashlib
from pathlib import Path
import subprocess
import requests

from analyze import HERE,write_csv


def snapshot(raw):
    root=raw/'dynamic';rows=[]
    # Include completed cases only. Partial observer files are actively changing.
    selected=[]
    for done in sorted((root/'runs').glob('*/done.json')):
        run=done.parent
        for name in ('done.json','calls.jsonl','observer.bt','observer.jsonl','observer.stderr','observer_metadata.json',
                     'environment.json','setup.json','clone.log','worker.stderr','replay/replay_worker.py','replay/replay_tools.py'):
            if (run/name).is_file():selected.append(run/name)
        selected.extend(sorted((run/'replay/requests').glob('*.json')))
        selected.extend(sorted((run/'replay/logs').glob('*.log')))
    for name in ('selected_trajectories.jsonl','task_metadata.jsonl','swebench_verified.parquet','launch',
                 'harbor_pinned_version.json','harbor_pinned_tasks.json',
                 'calibration/observer-identity.jsonl','calibration/observer-identity.stderr'):
        if (root/name).is_file():selected.append(root/name)
    selected.extend(sorted((root/'task_archives').glob('*')))
    selected.extend(sorted(root.glob('calibration-repeat-*/*.*')))
    for path in selected:
        if not path.is_file():continue
        digest=hashlib.sha256()
        with path.open('rb') as f:
            while block:=f.read(1024*1024):digest.update(block)
        rows.append(dict(raw_relative_path=str(path.relative_to(raw)),bytes=path.stat().st_size,sha256=digest.hexdigest()))
    plans=list(csv.DictReader((HERE/'dynamic_plan.csv').open()))
    from dynamic_prepare import VERIFIED_REPO,VERIFIED_REV,HARBOR_HASH
    card=root/'swebench_verified_card.md'
    if not card.exists():
        response=requests.get(f'https://huggingface.co/datasets/{VERIFIED_REPO}/raw/{VERIFIED_REV}/README.md',timeout=30)
        response.raise_for_status();card.write_bytes(response.content)
    rows.append(dict(raw_relative_path=str(card.relative_to(raw)),bytes=card.stat().st_size,
                     sha256=hashlib.sha256(card.read_bytes()).hexdigest()))
    write_csv(HERE/'dynamic_evidence_manifest.csv',rows)
    license_lines=[line.strip() for line in card.read_text().splitlines() if line.startswith('license:')]
    verified_file=root/'swebench_verified.parquet'
    metadata=[dict(source=VERIFIED_REPO,version=VERIFIED_REV,sha256=hashlib.sha256(verified_file.read_bytes()).hexdigest(),
                   bytes=verified_file.stat().st_size,sampled_tasks=len({p['instance_id'] for p in plans if p['source']=='mini'}),
                   declared_license='; '.join(license_lines) or 'not specified in pinned dataset card',
                   locator=f'https://huggingface.co/datasets/{VERIFIED_REPO}/tree/{VERIFIED_REV}',
                   use='Repository and base-commit metadata only. Oracle and verifier patches are not applied or redistributed.')]
    for path in sorted((root/'task_archives').glob('*.tar.gz')):
        iid=path.name.removesuffix('.tar.gz')
        related=[p for p in plans if p['instance_id']==iid]
        if not related:continue
        metadata.append(dict(source='Harbor public task archive:'+iid,version=related[0]['metadata_source'],
                             sha256=hashlib.sha256(path.read_bytes()).hexdigest(),bytes=path.stat().st_size,sampled_tasks=1,
                             declared_license='No separate task-data license verified. Third-party project terms remain applicable.',
                             locator='harbor:dataset:'+HARBOR_HASH,
                             use='tests/config.json repository and base-commit metadata only. No task archive is redistributed.'))
    write_csv(HERE/'dynamic_metadata_manifest.csv',metadata)
    tools=[('host_kernel',['uname','-srvmo']),('bpftrace',['bpftrace','--version']),
           ('bubblewrap',['bwrap','--version']),('gcc',['gcc','-dumpfullversion']),('git',['git','--version']),
           ('system_python',['python3','--version']),('node',['node','--version']),('npm',['npm','--version']),
           ('java',['java','-version']),('maven',['mvn','-version']),('go',['go','version']),
           ('rustc',['rustc','--version']),('cargo',['cargo','--version'])]
    versions=[]
    for name,command in tools:
        try:
            result=subprocess.run(command,capture_output=True,text=True,timeout=15)
            value=(result.stdout+result.stderr).strip()
            versions.append(dict(component=name,exit_code=result.returncode,value=value))
        except (OSError,subprocess.TimeoutExpired) as exc:
            versions.append(dict(component=name,exit_code='unavailable',value=type(exc).__name__))
    # Source-code hashes are a provenance snapshot, not a claim that later
    # aggregation changes were loaded by an already running coordinator.
    for path in sorted(HERE.glob('*.py')):
        versions.append(dict(component='source_sha256:'+path.name,exit_code=0,value=hashlib.sha256(path.read_bytes()).hexdigest()))
    write_csv(HERE/'dynamic_host_environment.csv',versions)
    print(f'Hashed {len(rows)} retained evidence files')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True)
    snapshot(p.parse_args().raw)
