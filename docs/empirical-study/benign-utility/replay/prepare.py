#!/usr/bin/env python3
"""Copy immutable replay inputs, retain provenance, and audit instructions."""
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ['WS_RAW'])/'replay'
OUTPUT=Path(os.environ['WS_RAW']).parent/'replay/results'
ORIGINAL=Path('/workspaces/lanes/trajectory-indirect/docs/empirical-study/trajectory-indirect')
PREVIOUS=Path('/workspaces/.agent-state/actplane-research/raw/trajectory-indirect-20261028')
ENGINE=Path('/workspaces/.agent-state/actplane-research/raw/translation-models-20261028/bounded-loader')

def write(name,rows):
    with (OUTPUT/name).open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    (ROOT/'input/dynamic').mkdir(parents=True,exist_ok=True)
    for source,target in [(ORIGINAL,ROOT/'harness'),(ENGINE,ROOT/'engine'),
        (PREVIOUS/'dynamic/git-cache',ROOT/'input/dynamic/git-cache'),
        (PREVIOUS/'dynamic/toolchains',ROOT/'input/dynamic/toolchains')]:
        if not target.exists():shutil.copytree(source,target,symlinks=True)
    for source,target in [(PREVIOUS/'classified_calls.jsonl.gz',ROOT/'input/classified_calls.jsonl.gz'),
        (PREVIOUS/'dynamic/launch',ROOT/'input/dynamic/launch')]:
        if not target.exists():shutil.copy2(source,target)
    for condition in ('none','broad','scoped'):
        dynamic=ROOT/condition/'dynamic';dynamic.mkdir(parents=True,exist_ok=True)
        for name in ('toolchains','git-cache'):
            target=dynamic/name
            if not target.exists():shutil.copytree(ROOT/'input/dynamic'/name,target,symlinks=True)
        shutil.copy2(ROOT/'input/dynamic/launch',dynamic/'launch')
        for alias in (dynamic/'toolchains').iterdir():
            if alias.is_symlink() and os.path.isabs(os.readlink(alias)):
                target_name=alias.resolve().name
                alias.unlink();alias.symlink_to(target_name,target_is_directory=True)
    revision=subprocess.check_output(['git','-C',str(ORIGINAL),'rev-parse','HEAD'],text=True).strip()
    manifest=[]
    for p in (ROOT/'harness').iterdir():
        if p.is_file():manifest.append(dict(kind='copied_harness',path=p.name,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),bytes=p.stat().st_size,revision=revision))
    for p in (ROOT/'input/classified_calls.jsonl.gz',ROOT/'engine/process',ROOT/'engine/metadata.json'):
        manifest.append(dict(kind='copied_input_or_engine',path=str(p.relative_to(ROOT)),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),bytes=p.stat().st_size,revision=''))
    write('provenance.csv',manifest)
    plans=list(csv.DictReader((ROOT/'harness/dynamic_plan.csv').open()))
    write('cohort.csv',plans)
    inventory=[];directives=[];full=[]
    for row in plans:
        base=['git','--git-dir',str(ROOT/'input/dynamic/git-cache'/row['repository'].replace('/','__'))]
        names=subprocess.check_output(base+['ls-tree','-r','--name-only',row['base_commit']],text=True).splitlines()
        for name in names:
            if Path(name).name not in ('AGENTS.md','CLAUDE.md','.cursorrules'):continue
            content=subprocess.check_output(base+['show',row['base_commit']+':'+name])
            text=content.decode(errors='replace')
            record=dict(dynamic_id=row['dynamic_id'],repository=row['repository'],base_commit=row['base_commit'],path=name,sha256=hashlib.sha256(content).hexdigest(),bytes=len(content))
            inventory.append(record);full.append(dict(**record,text=text))
            for i,line in enumerate(text.splitlines(),1):
                if any(t in line.lower() for t in ('never','do not','must not','always','before committing','before commit')):
                    reason='source-content-or-workflow requirement, not a syscall-level action predicate'
                    if 'pull request autonomously' in line.lower():reason='requires external human authorization context; compound gh subcommands not exactly expressible'
                    if 'make check' in line.lower():reason='requires successful compound make check argv gate; exec gate cannot match both executable and check argument'
                    if name.startswith(('adapters/','docs/','frontend/','marimo/','crates/','packages/','ui/','apps/')):reason='nested instruction scope; '+reason
                    directives.append(dict(**record,line=i,directive=line.strip(),disposition='not_lowered',reason=reason))
    (ROOT/'instruction-audit.json').write_text(json.dumps(full,indent=2))
    write('instruction_inventory.csv',inventory)
    write('instruction_exclusions.csv',directives)
    print('prepared',len(plans),'fixed trajectories;',len(inventory),'instruction files;',len(directives),'candidate directives')

if __name__=='__main__':main()
