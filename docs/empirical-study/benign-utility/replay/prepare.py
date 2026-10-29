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
import datetime
import signal
import time

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ['WS_RAW'])/'replay'
OUTPUT=Path(os.environ['WS_RAW']).parent/'replay/results'
ORIGINAL=Path('/workspaces/lanes/trajectory-indirect/docs/empirical-study/trajectory-indirect')
PREVIOUS=Path('/workspaces/.agent-state/actplane-research/raw/trajectory-indirect-20261028')
ENGINE=Path('/workspaces/.agent-state/actplane-research/raw/translation-models-20261028/bounded-loader')

def compact_closed_tool(run):
    """Share identical retained tool bytes only after the actual worker exited."""
    if not (run/'done.json').exists():return 0
    metadata=json.loads((run/'utility-metadata.json').read_text()) if (run/'utility-metadata.json').exists() else {}
    pid=metadata.get('workspace_popen_pid')
    # Never use an initial-kernel PID to inspect namespaced /proc.
    if pid:
        if Path(f'/proc/{pid}').exists():return 0
    else:
        # The copied harness waits/kills+waits the worker before done.json, then
        # removes these disposable runtime trees. Their absence is an older
        # attempt's cleanup completion proof, without inventing a namespace PID.
        done=json.loads((run/'done.json').read_text())
        payload=[run/name for name in ('repo','venv','tmp','home','cache')]
        if (not done.get('run_phase','').startswith('benign-utility') or metadata.get('open_audit')
                or any(path.exists() or path.is_symlink() for path in payload)):return 0
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


def compact_closed_runtime(run):
    """Archive a closed forensic runtime, compare every byte, then free copies."""
    receipt=run/'utility-metadata.json'
    if not (run/'done.json').exists() or not receipt.exists():return 0
    metadata=json.loads(receipt.read_text())
    pid=metadata.get('workspace_popen_pid')
    if not metadata.get('open_audit') or not pid or Path(f'/proc/{pid}').exists():return 0
    if not run.resolve().is_relative_to(ROOT.resolve()):raise ValueError('runtime outside owned raw directory')
    if metadata.get('cache_backing')=='tmpfs':
        owner=metadata.get('cache_controller_workspace_pid')
        if owner!=os.getpid():
            # Another mount namespace cannot see the live RAM cache. Never
            # replace its evidence with an archive of the empty host mountpoint.
            if owner and Path(f'/proc/{owner}').exists():return 0
            if not (run/'runtime-cache.tar.gz').exists():return 0
        return (archive_closed_group(run,('repo','venv','tmp','home'),'runtime.tar.gz')+
                archive_closed_group(run,('cache',),'runtime-cache.tar.gz'))
    return archive_closed_group(run,('repo','venv','tmp','home','cache'),'runtime.tar.gz')


def archive_closed_group(run,names,archive_name):
    payload=[name for name in names if (run/name).exists()]
    archive=run/archive_name
    if not payload or archive.exists():return 0
    for name in payload:
        path=run/name
        if path.is_symlink() or not path.resolve().is_relative_to(run.resolve()):raise ValueError('runtime payload escaped owned run')
    if any(run.glob(archive_name+'.partial*')):return 0
    size=sum(int(subprocess.check_output(['du','-sb',str(run/name)],text=True).split()[0]) for name in payload)
    # Isolate a closed snapshot from legacy startup scans while it is archived.
    # No worker or future action uses it; restore its exact path in all cases.
    staging_root=ROOT/'compaction';staging_root.mkdir(exist_ok=True)
    staging=staging_root/(run.parents[2].name+'-'+run.name+'-'+uuid.uuid4().hex)
    if not staging.resolve().is_relative_to(ROOT.resolve()):raise ValueError('staging escaped owned raw directory')
    run.rename(staging)
    print('Archiving closed snapshot:',run,'via',staging,flush=True)
    try:
        base=['tar','--acls','--xattrs','--numeric-owner','--atime-preserve=system','-I','gzip -1']
        # Count the actual compressed bytes without writing a second disk copy.
        estimate=subprocess.Popen(base+['-cf','-','--',*payload],cwd=staging,stdout=subprocess.PIPE)
        compressed=0
        while chunk:=estimate.stdout.read(1048576):compressed+=len(chunk)
        estimate.stdout.close()
        if estimate.wait():raise RuntimeError('closed snapshot compression estimate failed')
        space=os.statvfs(staging);headroom=int(space.f_blocks*space.f_frsize*.85)-(space.f_blocks-space.f_bavail)*space.f_frsize
        if compressed+1048576>headroom:
            print('Closed forensic archive waits for capacity:',run.name,'compressed bytes',compressed,'headroom',headroom,flush=True);return 0
        temporary=staging/(archive_name+'.partial')
        process=subprocess.Popen(base+['-cf',str(temporary),'--',*payload],cwd=staging,start_new_session=True)
        while process.poll() is None:
            space=os.statvfs(staging)
            if 1-space.f_bavail/space.f_blocks>=.85:
                os.killpg(process.pid,signal.SIGTERM);process.wait()
                temporary.unlink(missing_ok=True)
                print('Closed archive cancelled by85percent guard; original snapshot retained:',run.name,flush=True);return 0
            time.sleep(.1)
        if process.returncode:raise RuntimeError('closed snapshot archive failed')
        subprocess.run(['gzip','-t',str(temporary)],check=True)
        subprocess.run(['tar','--compare','--gzip','--file',str(temporary)],cwd=staging,check=True)
        temporary.rename(staging/archive_name)
        for name in payload:
            shutil.rmtree(staging/name,ignore_errors=os.path.ismount(staging/name))
        archived=(staging/archive_name).stat().st_size
        print('Archived closed forensic payload:',run.name,size,'bytes to',archived,flush=True)
        return size-archived
    finally:
        staging.rename(run)


def compact_closed_trace(run):
    """Losslessly gzip a finished strace after verifying its plaintext SHA256."""
    source=run/'successful-opens.strace';compressed=run/'successful-opens.strace.gz'
    if not (run/'done.json').exists() or not (run/'utility-metadata.json').exists() or not source.exists() or compressed.exists():return 0
    metadata=json.loads((run/'utility-metadata.json').read_text());pid=metadata.get('workspace_popen_pid')
    if not metadata.get('open_audit') or not pid or Path(f'/proc/{pid}').exists():return 0
    if not source.resolve().is_relative_to(ROOT.resolve()):raise ValueError('trace outside owned raw directory')
    space=os.statvfs(run)
    if 1-space.f_bavail/space.f_blocks>=.85:return 0
    state=source.stat();temporary=run/'successful-opens.strace.gz.partial'
    first=hashlib.sha256()
    with source.open('rb') as original,temporary.open('wb') as output:
        with gzip.GzipFile(fileobj=output,mode='wb',compresslevel=1,mtime=int(state.st_mtime)) as archive:
            while chunk:=original.read(1048576):
                space=os.statvfs(run)
                if 1-space.f_bavail/space.f_blocks>=.85:
                    archive.close();output.close();temporary.unlink(missing_ok=True)
                    print('Trace compression waits for85percent capacity:',run.name,flush=True);return 0
                first.update(chunk);archive.write(chunk)
    second=hashlib.sha256()
    with gzip.open(temporary,'rb') as archive:
        while chunk:=archive.read(1048576):second.update(chunk)
    if first.digest()!=second.digest():raise RuntimeError('compressed trace plaintext digest mismatch')
    temporary.chmod(state.st_mode);os.chown(temporary,state.st_uid,state.st_gid)
    os.utime(temporary,ns=(state.st_atime_ns,state.st_mtime_ns))
    temporary.rename(compressed);source.unlink()
    saved=state.st_size-compressed.stat().st_size
    print('Lossless closed trace bytes reclaimed:',run.name,saved,flush=True)
    return saved


def deduplicate_closed_inputs():
    """Share immutable distribution files/object packs in inactive own copies."""
    saved=0
    canonical_hashes={}
    for condition in ('none','broad','scoped','block-broad','block-scoped'):
        dynamic=ROOT/condition/'dynamic'
        runs=list((dynamic/'runs').glob('t*'))
        if len(runs)!=40 or any(not (run/'done.json').exists() for run in runs):continue
        active=False
        for run in runs:
            receipt=run/'utility-metadata.json'
            metadata=json.loads(receipt.read_text()) if receipt.exists() else {}
            pid=metadata.get('workspace_popen_pid')
            if pid and Path(f'/proc/{pid}').exists():active=True;break
        if active:continue
        for kind in ('toolchains','git-cache'):
            source=ROOT/'input/dynamic'/kind;destination=dynamic/kind
            if source.is_symlink() or destination.is_symlink():continue
            for target in destination.rglob('*'):
                if target.is_symlink() or not target.is_file():continue
                relative=target.relative_to(destination)
                # Git may rewrite refs/config; content-addressed pack/index
                # objects are immutable. Task clones use --no-hardlinks.
                if kind=='git-cache' and not ('objects/pack' in relative.as_posix() and target.suffix in ('.pack','.idx')):continue
                canonical=source/relative
                if canonical.is_symlink() or not canonical.is_file():continue
                if not target.resolve().is_relative_to(ROOT.resolve()) or not canonical.resolve().is_relative_to(ROOT.resolve()):raise ValueError('input dedup escaped owned raw directory')
                old=target.stat();original=canonical.stat()
                if old.st_ino==original.st_ino and old.st_dev==original.st_dev:continue
                fields=lambda value:(value.st_size,value.st_mode,value.st_uid,value.st_gid,value.st_mtime_ns)
                if fields(old)!=fields(original):continue
                if canonical not in canonical_hashes:canonical_hashes[canonical]=hashlib.sha256(canonical.read_bytes()).digest()
                if hashlib.sha256(target.read_bytes()).digest()!=canonical_hashes[canonical]:continue
                temporary=target.with_name('.retained-input-'+uuid.uuid4().hex)
                os.link(canonical,temporary);os.replace(temporary,target)
                if old.st_nlink==1:saved+=old.st_blocks*512
    print('Verified inactive immutable input bytes deduplicated:',saved,flush=True)
    return saved

def write(name,rows):
    with (OUTPUT/name).open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    runtime=[]
    for binary in (Path('/usr/bin/node'),):
        if not binary.exists():continue
        target=binary.resolve();state=target.stat()
        runtime.append(dict(binary=str(binary),resolved_path=str(target),
            sha256=hashlib.sha256(target.read_bytes()).hexdigest(),bytes=state.st_size,
            version=subprocess.check_output([str(binary),'--version'],text=True).strip(),
            mtime_ns=state.st_mtime_ns,ctime_ns=state.st_ctime_ns,
            observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            scope='Current host binary mounted read-only as /usr in copied replay; ctime compared against recorded run timestamps'))
    if runtime:write('runtime-provenance.csv',runtime)
    closed=list(ROOT.glob('*/dynamic/runs/t*/done.json'))+list((ROOT/'attempts').glob('*/done.json'))
    saved=sum(compact_closed_tool(p.parent) for p in closed)
    print('Retained closed-tool bytes deduplicated:',saved,flush=True)
    deduplicate_closed_inputs()
    for done in ROOT.glob('open-audit-*/dynamic/runs/t*/done.json'):
        compact_closed_trace(done.parent);compact_closed_runtime(done.parent)
    (ROOT/'input/dynamic').mkdir(parents=True,exist_ok=True)
    for source,target in [(ORIGINAL,ROOT/'harness'),(ENGINE,ROOT/'engine'),
        (PREVIOUS/'dynamic/git-cache',ROOT/'input/dynamic/git-cache'),
        (PREVIOUS/'dynamic/toolchains',ROOT/'input/dynamic/toolchains')]:
        if not target.exists():shutil.copytree(source,target,symlinks=True)
    for source,target in [(PREVIOUS/'classified_calls.jsonl.gz',ROOT/'input/classified_calls.jsonl.gz'),
        (PREVIOUS/'dynamic/launch',ROOT/'input/dynamic/launch')]:
        if not target.exists():shutil.copy2(source,target)
    for condition in ('none','broad','scoped','block-broad','block-scoped'):
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
    nodepins=[]
    for plan in plans:
        cache=ROOT/'input/dynamic/git-cache'/plan['repository'].replace('/','__')
        literal=subprocess.run(['git','--git-dir',str(cache),'show',plan['base_commit']+':.node-version'],capture_output=True)
        if literal.returncode==0:
            nodepins.append(dict(dynamic_id=plan['dynamic_id'],repository=plan['repository'],base_commit=plan['base_commit'],
                sandbox_workdir=plan['sandbox_workdir'],source_path='.node-version',literal=literal.stdout.decode().strip(),
                source_sha256=hashlib.sha256(literal.stdout).hexdigest(),
                applicability='Version-file presence only; instruction applicability/action scope independently reviewed'))
    if nodepins:write('node-version-pins.csv',nodepins)
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
