#!/usr/bin/env python3
"""Run the copied, fixed public replay cohort with process-root-scoped AgPlane."""
import argparse
import csv
import gzip
import fcntl
import hashlib
import importlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import struct
import sys
import time
from prepare import compact_closed_tool, compact_closed_runtime, compact_closed_trace

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ['WS_RAW']) / 'replay'
HARNESS = ROOT / 'harness'
sys.path.insert(0, str(HARNESS))
runner = importlib.import_module('dynamic_run')
LOADER = ROOT / 'engine/process'
CLI = Path('/workspaces/lanes/translation-models/target/release/actplane')
BROAD = ['**/*.env', '**/*.env.local', '**/*.env.production', '**/*.pem', '**/*.key', '**/*id_rsa', '**/*id_ed25519', '**/*credentials.json',
         '/root/.aws/credentials', '/root/.gemini/oauth_creds.json', '/etc/secrets/**']
TMPFS_LIMIT_BYTES=24*1024**3


def memory_snapshot():
    mem={line.split(':',1)[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemAvailable:','MemTotal:'))}
    membership=next(line.split('::',1)[1] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    root=Path('/sys/fs/cgroup');group=root/membership.lstrip('/')
    if not (group/'memory.current').exists():group=root
    current=group/'memory.current';maximum=group/'memory.max'
    if not current.exists() or not maximum.exists():raise RuntimeError('actual cgroup memory budget unavailable')
    used=int(current.read_text());limit=maximum.read_text().strip()
    headroom=min(mem['MemAvailable'],int(limit)-used) if limit!='max' else mem['MemAvailable']
    constraints=[]
    for ancestor in (group,*group.parents):
        if not ancestor.is_relative_to(root):break
        if not (ancestor/'memory.max').exists():continue
        bound=(ancestor/'memory.max').read_text().strip();consumed=int((ancestor/'memory.current').read_text())
        constraints.append(dict(path=str(ancestor),maximum=bound,current=consumed))
        if bound!='max':headroom=min(headroom,int(bound)-consumed)
    return dict(memory_available_bytes=mem['MemAvailable'],cgroup_memory_current_bytes=used,
        cgroup_memory_max_bytes=limit,memory_headroom_bytes=headroom,
        cgroup_path=membership,cgroup_memory_file=str(maximum),ancestor_constraints=constraints)


def mount_memory_cache(path):
    path=path.resolve()
    if not path.is_relative_to(ROOT.resolve()) or path.name!='cache':raise ValueError('cache mount escaped owned raw directory')
    if os.readlink('/proc/self/ns/mnt')==os.readlink('/proc/1/ns/mnt'):raise RuntimeError('tmpfs cache requires run.sh private mount namespace')
    path.mkdir(parents=True,exist_ok=True)
    if any(path.iterdir()) or os.path.ismount(path):raise RuntimeError('cache mount target is not fresh/unmounted')
    snapshot=memory_snapshot()
    if snapshot['memory_headroom_bytes']<TMPFS_LIMIT_BYTES+8*1024**3:raise RuntimeError('insufficient actual RAM headroom for bounded cache plus concurrent-process reserve')
    subprocess.run(['mount','-t','tmpfs','-o',f'size={TMPFS_LIMIT_BYTES},mode=0755','tmpfs',str(path)],check=True)
    return dict(cache_backing='tmpfs',cache_backing_provenance='recorded_private_namespace_tmpfs_mount',
        timing_stratum='tmpfs_cache',cache_tmpfs_limit_bytes=TMPFS_LIMIT_BYTES,
        memory_headroom_before_bytes=snapshot['memory_headroom_bytes'],memory_before=snapshot,
        controller_mount_namespace=os.readlink('/proc/self/ns/mnt'),cache_controller_workspace_pid=os.getpid(),cache_directory=str(path))


def policy(plan, condition, effect='kill'):
    sources = BROAD if condition == 'broad' else [
        plan['sandbox_workdir'] + '/.env', plan['sandbox_workdir'] + '/.env.local',
        plan['sandbox_workdir'] + '/.env.production', '/root/.ssh/id_rsa',
        '/root/.ssh/id_ed25519',
        '/root/.aws/credentials', '/root/.gemini/oauth_creds.json', '/etc/secrets/**']
    text = 'source COMMAND = exec "**"\n' + '\n'.join('source SECRET = file ' + json.dumps(p) for p in sources)
    return text + '\nrule no-secret-network:\n  '+effect+' connect endpoint "*" if SECRET\n  because "secret material requires trusted redaction before network access"\n'


def process_ready(argv, out, err, marker, env=None):
    stdout = out.open('w'); stderr = err.open('w')
    process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=env)
    start = time.monotonic()
    while time.monotonic() - start < 90:
        if marker in out.read_text(errors='replace') + err.read_text(errors='replace'):
            return process, stdout, stderr
        if process.poll() is not None:
            stdout.close(); stderr.close()
            raise RuntimeError('instrumentation failed: ' + err.read_text(errors='replace')[-1000:])
        time.sleep(.1)
    process.terminate(); process.wait(timeout=20)
    stdout.close(); stderr.close()
    raise RuntimeError('instrumentation readiness timeout')


def source_evidence(run,plan):
    paths=set()
    for line in (run/'sources.jsonl').read_text(errors='replace').splitlines():
        try:message=json.loads(line).get('data','')
        except json.JSONDecodeError:continue
        if isinstance(message,str) and message.startswith('READ|'):
            paths.add(message.strip().split('|',4)[4])
    if (run/'engine.jsonl').exists():
        for line in (run/'engine.jsonl').read_text(errors='replace').splitlines():
            try:event=json.loads(line)
            except json.JSONDecodeError:continue
            target=(event.get('provenance') or {}).get('target','')
            if target.startswith('/'):paths.add(target)
    metadata=json.loads((run/'utility-metadata.json').read_text()) if (run/'utility-metadata.json').exists() else {}
    evidence=[]
    for path in sorted(paths):
        host=Path(path)
        for prefix,directory in [(plan['sandbox_workdir'],'repo'),('/venv','venv'),('/root','home'),('/tmp','tmp'),('/cache','cache')]:
            if path==prefix or path.startswith(prefix+'/'):
                host=run/directory/path[len(prefix):].lstrip('/');break
        row=dict(path=path,sha256='',bytes='',classification='unknown',reason='observed source/provenance path unavailable after command')
        try:
            data=host.read_bytes();row.update(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data))
            if metadata.get('cache_backing')=='tmpfs' and host.is_relative_to(run):
                retained=run/'retained-source-bytes';retained.mkdir(exist_ok=True)
                snapshot=retained/row['sha256']
                if not snapshot.exists():shutil.copy2(host,snapshot)
                row['retained_bytes_path']=str(snapshot.relative_to(run))
            if host.is_relative_to(run/'repo'):
                relative=str(host.relative_to(run/'repo'))
                base=subprocess.run(['git','show',plan['base_commit']+':'+relative],cwd=run/'repo',capture_output=True)
                if base.returncode==0 and base.stdout==data:
                    row.update(classification='public_repository_object',reason='content bytes equal the pinned public repository object')
            if b'-----BEGIN CERTIFICATE-----' in data and b'PRIVATE KEY-----' not in data:
                row.update(classification='public_certificate',reason='PEM contains public certificate(s) and no private-key marker')
            if row['classification']=='unknown':row['reason']='file retained by hash; confidentiality intent requires individual adjudication'
        except (OSError,ValueError):pass
        evidence.append(row)
    (run/'source-evidence.json').write_text(json.dumps(evidence,indent=2))


class Instruments:
    def __init__(self, processes, run=None, plan=None): self.processes = processes; self.run = run; self.plan = plan
    def poll(self):
        # Lifecycle polling is only for teardown. request() below separately
        # invalidates a run when ANY instrument exits before/during a call.
        return None if any(p.poll() is None for p, _, _ in self.processes) else 0
    @property
    def returncode(self):
        return 0 if all(p.returncode in (0, -signal.SIGINT) for p, _, _ in self.processes) else 1
    def send_signal(self, sig):
        for p, _, _ in self.processes:
            if p.poll() is None: p.send_signal(sig)
    def wait(self, timeout):
        for p, out, err in self.processes:
            p.wait(timeout=timeout); out.close(); err.close()
        if self.run:
            (self.run/'instrument-exits.json').write_text(json.dumps([dict(pid=p.pid,exit_code=p.returncode,stdout=out.name,stderr=err.name) for p,out,err in self.processes],indent=2))
            source_evidence(self.run,self.plan)
    def kill(self):
        for p, _, _ in self.processes:
            if p.poll() is None: p.kill()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--condition', choices=['none', 'broad', 'scoped'], required=True)
    parser.add_argument('--effect', choices=['kill','block'], default='kill')
    parser.add_argument('--open-audit',action='store_true',help='Separate untimed verification replay with standard successful-open tracing')
    parser.add_argument('--cache-tmpfs',action='store_true',help='Bounded RAM backing at the unchanged disposable /cache path')
    parser.add_argument('--ids', default='')
    args = parser.parse_args()
    admission_started=time.monotonic()
    # Materialized dependencies reached several GiB in actual runs. Serialize
    # future owned replay batches instead of compounding those working sets.
    capacity_lock=(ROOT/'runtime.lock').open('a')
    fcntl.flock(capacity_lock,fcntl.LOCK_EX)
    for closed in ROOT.glob('open-audit-*/dynamic/runs/t*'):
        compact_closed_runtime(closed)
    raw_name=('block-'+args.condition) if args.effect=='block' and args.condition!='none' else args.condition
    if args.open_audit:raw_name='open-audit-'+raw_name
    raw = ROOT / raw_name
    (raw / 'dynamic').mkdir(parents=True, exist_ok=True)
    while True:
        try:runner.disk_guard(raw);break
        except RuntimeError as error:
            if 'workspace disk limit reached' not in str(error):raise
            print('Waiting before lazy-copy/materialization:',str(error),flush=True);time.sleep(5)
    batch_admission_s=time.monotonic()-admission_started
    for name in ('toolchains', 'git-cache'):
        target = raw / 'dynamic' / name
        if target.is_symlink(): target.unlink()
        if not target.exists():
            shutil.copytree(ROOT / 'input/dynamic' / name, target, symlinks=True)
    # UV's version aliases were absolute links into the source lane. Relocate
    # them within our copied, read-only toolchain mount, retaining exact builds.
    for alias in (raw/'dynamic/toolchains').iterdir():
        if alias.is_symlink() and os.path.isabs(os.readlink(alias)):
            target_name=alias.resolve().name
            alias.unlink(); alias.symlink_to(target_name, target_is_directory=True)
    shutil.copy2(ROOT / 'input/dynamic/launch', raw / 'dynamic/launch')
    original_sandbox = runner.sandbox
    worker_state = {}
    def sandbox(*values):
        run=values[2]
        backing=dict(cache_backing='disk',cache_backing_provenance='recorded_original_sandbox_directory',timing_stratum='disk_cache',cache_tmpfs_limit_bytes=0)
        if args.cache_tmpfs:
            backing=mount_memory_cache(run/'cache')
            worker_state['mounted_cache']=run/'cache'
        worker_state['backing']=backing
        (run/'utility-metadata.json').write_text(json.dumps(backing,indent=2))
        old_popen=subprocess.Popen
        def traced_popen(argv,*positional,**named):
            if argv[0]=='bwrap':
                argv=['strace','-f','-qq','-ttt','-z','-yy','-s','4096','-e',
                    'trace=open,openat,openat2,creat,truncate,rename,renameat,renameat2',
                    '-o',str(values[2]/'successful-opens.strace')]+argv
                worker_state['open_audit_argv']=argv[:argv.index('bwrap')]
            return old_popen(argv,*positional,**named)
        try:
            if args.open_audit:subprocess.Popen=traced_popen
            output = original_sandbox(*values)
        finally:subprocess.Popen=old_popen
        worker_state['pid'] = output[0].pid
        worker_state['worker'] = output[0]
        (run/'utility-metadata.json').write_text(json.dumps(dict(backing,workspace_popen_pid=output[0].pid,open_audit=args.open_audit),indent=2))
        return output
    runner.sandbox = sandbox
    original_materialize = runner.materialize
    plan_state = {}
    original_guard=runner.disk_guard
    def resource_guard(directory):
        try:return original_guard(directory)
        except RuntimeError as error:
            if 'workspace disk limit reached' in str(error) and plan_state.get('run'):
                usage=shutil.disk_usage(directory)
                current=plan_state['run']
                measured=subprocess.run(['du','-s','-B1',str(current)],capture_output=True,text=True)
                observation=dict(utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                    workspace_total=usage.total,workspace_used=usage.used,workspace_free=usage.free,
                    run_disk_bytes=int(measured.stdout.split()[0]) if measured.stdout.split() else '',
                    run=str(current),raw_condition=raw_name)
                (current/'resource-failure.json').write_text(json.dumps(observation,indent=2))
            raise
    runner.disk_guard=resource_guard
    def materialize(raw, plan, run):
        plan_state['plan'] = plan
        repo = original_materialize(raw, plan, run)
        instructions=[]
        for p in repo.rglob('*'):
            if p.is_file() and p.name in ('AGENTS.md', 'CLAUDE.md', '.cursorrules'):
                instructions.append(dict(path=p.relative_to(repo).as_posix(),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),text=p.read_text(errors='replace')))
        (run/'project-instructions.json').write_text(json.dumps(instructions,indent=2))
        return repo
    runner.materialize = materialize
    def observer_start(run):
        plan=plan_state['plan']
        env=os.environ.copy()
        env.update(BPFTRACE_MAX_STRLEN='1024', BPFTRACE_MAX_MAP_KEYS='262144')
        instruments=[]
        try:
            source=(HERE/'source_observer.bt').read_text().replace('strncmp(comm, "apti6e", 6)',
                'strncmp(comm, '+json.dumps('apti6e'+plan['dynamic_id'][1:])+', 8)')
            (run/'source-observer.bt').write_text(source)
            instruments.append(process_ready(['bpftrace','-f','json',str(run/'source-observer.bt'),'0'],
                run/'sources.jsonl',run/'sources.stderr','SOURCE_OBSERVER_READY',env))
            marker='apti6emap'+plan['dynamic_id'][1:]
            mapping=runner.request(worker_state['worker'],dict(tag=marker,command=['/usr/bin/true'],shell=False,
                cwd=plan['sandbox_workdir'],timeout_s=30,log_path='/replay/logs/root-mapping.log',log_limit=4096))
            start=time.monotonic();host_root=None
            while time.monotonic()-start<15:
                for line in (run/'sources.jsonl').read_text(errors='replace').splitlines():
                    try:message=json.loads(line).get('data','')
                    except json.JSONDecodeError:continue
                    if isinstance(message,str) and message.startswith('MAPROOT|'):
                        fields=message.strip().split('|')
                        if fields[2]==marker:host_root=int(fields[4]);break
                if host_root:break
                time.sleep(.1)
            if not host_root or mapping.get('exit_code')!=0:raise RuntimeError('initial-namespace worker-root mapping failed')
            (run/'root-mapping.json').write_text(json.dumps(dict(marker=marker,workspace_popen_pid=worker_state['pid'],initial_namespace_worker_pid=host_root,mapper_result=mapping),indent=2))
            if args.condition != 'none':
                text=policy(plan,args.condition,args.effect)
                (run/'policy.dsl').write_text(text)
                result=subprocess.run([str(CLI),'--rule',text,'compile','--out',str(run/'policy.bin')],capture_output=True,text=True)
                (run/'policy-compile.log').write_text(result.stdout+result.stderr)
                if result.returncode: raise RuntimeError('policy compile failed')
                data=(run/'policy.bin').read_bytes()
                patterns=re.findall(r'^source (\w+) = (exec|file) "([^"]*)"',text,re.M)
                count,_=struct.unpack_from('<II',data)
                if count!=len(patterns):raise RuntimeError('compiled source count mismatch')
                compiled=[]
                for i,(label,kind,pattern) in enumerate(patterns):
                    op,mode,literal,arg,add,delete,gates,invals,ip,mask,exit_code,domain=struct.unpack_from('<BB64s24s6xQQQQIIiI',data,8+i*144)
                    literal=literal.split(b'\0')[0].decode()
                    if pattern.startswith('**/*') and (mode!=2 or literal!=pattern[4:]):raise RuntimeError('unsupported source suffix')
                    compiled.append(dict(label=label,source_kind=kind,pattern=pattern,compiled_op=op,compiled_match_mode=mode,compiled_literal=literal,add_mask=add))
                (run/'compiled-sources.json').write_text(json.dumps(compiled,indent=2))
                instruments.append(process_ready([str(LOADER),'--config',str(run/'policy.bin'),'--seed-pid',str(host_root),'--seed-label','0'],
                    run/'engine.jsonl',run/'engine.stderr','ActPlane: ready'))
                if args.effect=='block' and 'ActPlane: enforce mode' not in (run/'engine.stderr').read_text():
                    raise RuntimeError('native block enforcement not active; no defended calls admitted')
            metadata=dict(condition=args.condition,root_pid=host_root,root_pid_namespace='initial-kernel-worker',workspace_popen_pid=worker_state['pid'],source_observer_string_bytes=1024,loader_sha256=hashlib.sha256(LOADER.read_bytes()).hexdigest(),
                source_observer_sha256=hashlib.sha256((run/'source-observer.bt').read_bytes()).hexdigest(),kernel=os.uname().release)
            metadata['engine_environment']={name:os.environ.get(name) for name in (
                'ACTPLANE_HOOK_PROFILE','ACTPLANE_ENABLE_ADVANCED_HOOKS','ACTPLANE_ADVANCED_TRACEPOINTS','ACTPLANE_RESERVE_FILE_FLOW')}
            metadata['enforcement_effect']='none' if args.condition=='none' else args.effect
            metadata.update(worker_state.get('backing',{}))
            metadata.update(replay_batch_serialized=True,batch_admission_s=batch_admission_s)
            metadata.update(open_audit=args.open_audit,clock_epoch_ns=time.time_ns(),clock_monotonic_ns=time.monotonic_ns())
            if args.open_audit:
                metadata.update(open_audit_argv=worker_state['open_audit_argv'],
                    strace_version=subprocess.check_output(['strace','--version'],text=True).splitlines()[0])
            (run/'utility-metadata.json').write_text(json.dumps(metadata,indent=2))
            worker_state['instruments'] = instruments
            # The copied runner owns these extra file handles and closes them.
            return Instruments(instruments,run,plan),(run/'instrument-wrapper.stdout').open('w'),(run/'instrument-wrapper.stderr').open('w')
        except Exception:
            group=Instruments(instruments);group.send_signal(signal.SIGINT);group.wait(timeout=30)
            raise
    runner.observer_start=observer_start
    original_request=runner.request
    def request(worker,job):
        instruments=worker_state.get('instruments',[])
        if any(p.poll() is not None for p,_,_ in instruments):
            raise RuntimeError('instrumentation exited unexpectedly before call')
        result=original_request(worker,job)
        if any(p.poll() is not None for p,_,_ in instruments):
            raise RuntimeError('instrumentation exited unexpectedly during call')
        if args.cache_tmpfs and worker_state.get('mounted_cache'):
            current=plan_state['run'];usage=shutil.disk_usage(raw)
            observation=dict(utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),tag=job.get('tag','setup'),
                workspace_total=usage.total,workspace_used=usage.used,workspace_free=usage.free,memory=memory_snapshot())
            for name in ('cache','repo','venv'):
                measured=subprocess.run(['du','-s','-B1',str(current/name)],capture_output=True,text=True)
                observation[name+'_bytes']=int(measured.stdout.split()[0]) if measured.stdout.split() else ''
            installed=list((current/'repo/.venv').glob('lib/python*/site-packages/certifi/cacert.pem'))
            if installed:
                destination=installed[0];digest=hashlib.sha256(destination.read_bytes()).hexdigest()
                for source in (current/'cache/uv/archive-v0').glob('*/certifi/cacert.pem'):
                    if hashlib.sha256(source.read_bytes()).hexdigest()!=digest:continue
                    left,right=source.stat(),destination.stat()
                    observation['actual_uv_copy']=dict(source=str(source),destination=str(destination),sha256=digest,
                        source_device=left.st_dev,destination_device=right.st_dev,source_inode=left.st_ino,destination_inode=right.st_ino,
                        same_inode=left.st_dev==right.st_dev and left.st_ino==right.st_ino,
                        source_mode=left.st_mode,destination_mode=right.st_mode)
                    break
            with (current/'resource-samples.jsonl').open('a') as stream:stream.write(json.dumps(observation)+'\n')
        return result
    runner.request=request
    runner.CFG['run_phase']='benign-utility-'+('open-audit-' if args.open_audit else '')+args.effect+'-'+args.condition
    plans=list(csv.DictReader((HARNESS/'dynamic_plan.csv').open()))
    if args.ids: plans=[p for p in plans if p['dynamic_id'] in args.ids.split(',')]
    calls={p['trajectory_id']:[] for p in plans}
    with gzip.open(ROOT/'input/classified_calls.jsonl.gz','rt') as f:
        for line in f:
            row=json.loads(line)
            if row['trajectory_id'] in calls: calls[row['trajectory_id']].append(row)
    for plan in plans:
        worker_state.pop('instruments',None)
        run=raw/'dynamic/runs'/plan['dynamic_id']
        plan_state.update(run=run,plan=plan)
        if (run/'done.json').exists():
            done=json.loads((run/'done.json').read_text())
            metadata=json.loads((run/'utility-metadata.json').read_text()) if (run/'utility-metadata.json').exists() else {}
            expected=(HERE/'source_observer.bt').read_text().replace('strncmp(comm, "apti6e", 6)',
                'strncmp(comm, '+json.dumps('apti6e'+plan['dynamic_id'][1:])+', 8)')
            reasons=[]
            if done.get('fatal'): reasons.append('fatal replay/instrumentation failure')
            if done.get('executed_calls')!=len(calls[plan['trajectory_id']]):reasons.append('incomplete recorded-call replay')
            if metadata.get('source_observer_sha256')!=hashlib.sha256(expected.encode()).hexdigest():reasons.append('observer protocol changed before fixed full matrix')
            if metadata.get('source_observer_string_bytes')!=1024:reasons.append('observer buffer differs from final validated protocol')
            if args.condition!='none' and metadata.get('root_pid_namespace')!='initial-kernel-worker':reasons.append('unvalidated namespace root')
            if args.condition!='none' and metadata.get('enforcement_effect', 'kill')!=args.effect:reasons.append('enforcement effect differs from selected cohort')
            if bool(metadata.get('open_audit'))!=args.open_audit:reasons.append('independent audit status differs from selected cohort')
            if args.cache_tmpfs and metadata.get('cache_backing')!='tmpfs':reasons.append('requested RAM cache backing differs from prior run')
            source_log=(run/'sources.jsonl').read_text(errors='replace') if (run/'sources.jsonl').exists() else ''
            if re.search(r'(?i)"type"\s*:\s*"[^"\n]*(?:error|lost|drop|overflow)[^"\n]*"',source_log):reasons.append('observer helper failure/event loss')
            exits=json.loads((run/'instrument-exits.json').read_text()) if (run/'instrument-exits.json').exists() else []
            if not exits or any(e['exit_code'] not in (0,-2) for e in exits):reasons.append('per-instrument exit receipt missing/nonzero')
            if reasons:
                attempts=ROOT/'attempts';attempts.mkdir(exist_ok=True)
                target=attempts/(args.condition+'-'+plan['dynamic_id']+'-'+str(time.time_ns()))
                shutil.move(str(run),target)
                (target/'exclusion-reason.json').write_text(json.dumps(dict(reasons=reasons),indent=2))
        try:
            runner.replay(raw,plan,sorted(calls[plan['trajectory_id']],key=lambda c:c['call_index']),cleanup=not args.open_audit)
            compact_closed_tool(run)
            if args.open_audit:
                compact_closed_trace(run);compact_closed_runtime(run)
        finally:
            mounted=worker_state.pop('mounted_cache',None)
            if mounted:
                if args.open_audit:
                    while not (run/'runtime-cache.tar.gz').exists():
                        compact_closed_runtime(run)
                        if (run/'runtime-cache.tar.gz').exists():break
                        print('Persisting RAM cache before unmount:',plan['dynamic_id'],flush=True);time.sleep(5)
                subprocess.run(['umount',str(mounted)],check=True)
                shutil.rmtree(mounted,ignore_errors=True)


if __name__=='__main__': main()
