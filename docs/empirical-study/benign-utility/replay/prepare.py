#!/usr/bin/env python3
"""Copy immutable replay inputs, retain provenance, and audit instructions."""
import csv
import hashlib
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ['WS_RAW'])/'replay'
OUTPUT=Path(os.environ['WS_RAW']).parent/'replay/results'
ORIGINAL=Path('/workspaces/lanes/trajectory-indirect/docs/empirical-study/trajectory-indirect')
PREVIOUS=Path('/workspaces/.agent-state/actplane-research/raw/trajectory-indirect-20261028')
ENGINE=Path('/workspaces/.agent-state/actplane-research/raw/translation-models-20261028/bounded-loader')

def compact_closed_tool(run):
    """Share identical retained tool bytes only after the actual worker exited."""
    if not (run/'done.json').exists() or not (run/'utility-metadata.json').exists():return 0
    metadata=json.loads((run/'utility-metadata.json').read_text())
    pid=metadata.get('workspace_popen_pid')
    # Never use an initial-kernel PID to inspect namespaced /proc. Older
    # attempts without an explicit Workspace PID remain untouched.
    if not pid or Path(f'/proc/{pid}').exists():return 0
    tool=run/'replay/bin/uv'
    if tool.is_symlink() or not tool.is_file():return 0
    if not tool.resolve().is_relative_to(ROOT.resolve()):raise ValueError('tool outside owned raw directory')
    state=tool.stat();digest=hashlib.sha256(tool.read_bytes()).hexdigest()
    shared=ROOT/'retained-tools';shared.mkdir(exist_ok=True)
    canonical=shared/('uv-'+digest)
    try:os.link(tool,canonical)
    except FileExistsError:pass
    stored=canonical.stat()
    if state.st_ino==stored.st_ino:return 0
    if (state.st_mode,state.st_mtime_ns)!=(stored.st_mode,stored.st_mtime_ns):return 0
    if hashlib.sha256(canonical.read_bytes()).hexdigest()!=digest:raise ValueError('retained tool checksum mismatch')
    temporary=tool.with_name('.uv-retained-'+uuid.uuid4().hex)
    os.link(canonical,temporary);os.replace(temporary,tool)
    return state.st_size if state.st_nlink==1 else 0

def write(name,rows):
    with (OUTPUT/name).open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    closed=list(ROOT.glob('*/dynamic/runs/t*/done.json'))+list((ROOT/'attempts').glob('*/done.json'))
    saved=sum(compact_closed_tool(p.parent) for p in closed)
    print('Retained closed-tool bytes deduplicated:',saved,flush=True)
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
    coral={r['trajectory_id']:r['dynamic_id'] for r in plans if r['repository']=='withcoral/coral'}
    scope_calls=[]
    with gzip.open(ROOT/'input/classified_calls.jsonl.gz','rt') as stream:
        for line in stream:
            call=json.loads(line)
            if call['trajectory_id'] not in coral:continue
            args=call['args'];encoded=json.dumps(args,sort_keys=True)
            target=args.get('command',args.get('cmd',args.get('file_path',args.get('path',''))))
            scope_calls.append(dict(dynamic_id=coral[call['trajectory_id']],call_index=call['call_index'],tool=call['tool'],
                command_or_path=str(target),arguments_sha256=hashlib.sha256(encoded.encode()).hexdigest()))
    write('instruction_scope_calls.csv',scope_calls)
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
                    if 'make check' in line.lower():reason='requires the compound make check invocation; exec gate cannot match both executable and check argument'
                    if name.startswith(('adapters/','docs/','frontend/','marimo/','crates/','packages/','ui/','apps/')):reason='nested instruction scope; '+reason
                    disposition='not_lowered'
                    if row['repository']=='withcoral/coral' and name=='ui/tests/ui/AGENTS.md':
                        disposition='out_of_scope'
                        reason='nested UI-test instructions; selected trajectories only inspect/edit/test Rust crates/coral-spec (instruction_scope_calls.csv)'
                    directives.append(dict(**record,line=i,directive=line.strip(),disposition=disposition,reason=reason))
    (ROOT/'instruction-audit.json').write_text(json.dumps(full,indent=2))
    write('instruction_inventory.csv',inventory)
    write('instruction_exclusions.csv',directives)
    print('prepared',len(plans),'fixed trajectories;',len(inventory),'instruction files;',len(directives),'candidate directives')

if __name__=='__main__':main()
