#!/usr/bin/env python3
"""Run the copied, fixed public replay cohort with process-root-scoped AgPlane."""
import argparse
import csv
import gzip
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

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ['WS_RAW']) / 'replay'
HARNESS = ROOT / 'harness'
sys.path.insert(0, str(HARNESS))
runner = importlib.import_module('dynamic_run')
LOADER = ROOT / 'engine/process'
CLI = Path('/workspaces/lanes/translation-models/target/release/actplane')
BROAD = ['**/*.env', '**/*.env.local', '**/*.env.production', '**/*.pem', '**/*.key', '**/*id_rsa', '**/*id_ed25519', '**/*credentials.json',
         '/root/.aws/credentials', '/root/.gemini/oauth_creds.json', '/etc/secrets/**']


def policy(plan, condition):
    sources = BROAD if condition == 'broad' else [
        plan['sandbox_workdir'] + '/.env', plan['sandbox_workdir'] + '/.env.local',
        plan['sandbox_workdir'] + '/.env.production', '/root/.ssh/id_rsa',
        '/root/.ssh/id_ed25519',
        '/root/.aws/credentials', '/root/.gemini/oauth_creds.json', '/etc/secrets/**']
    text = 'source COMMAND = exec "**"\n' + '\n'.join('source SECRET = file ' + json.dumps(p) for p in sources)
    return text + '\nrule no-secret-network:\n  kill connect endpoint "*" if SECRET\n  because "secret material requires trusted redaction before network access"\n'


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
    evidence=[]
    for path in sorted(paths):
        host=Path(path)
        for prefix,directory in [(plan['sandbox_workdir'],'repo'),('/venv','venv'),('/root','home'),('/tmp','tmp'),('/cache','cache')]:
            if path==prefix or path.startswith(prefix+'/'):
                host=run/directory/path[len(prefix):].lstrip('/');break
        row=dict(path=path,sha256='',bytes='',classification='unknown',reason='observed read-access path unavailable after command')
        try:
            data=host.read_bytes();row.update(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data))
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
    parser.add_argument('--ids', default='')
    args = parser.parse_args()
    raw = ROOT / args.condition
    (raw / 'dynamic').mkdir(parents=True, exist_ok=True)
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
        output = original_sandbox(*values)
        worker_state['pid'] = output[0].pid
        worker_state['worker'] = output[0]
        return output
    runner.sandbox = sandbox
    original_materialize = runner.materialize
    plan_state = {}
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
                text=policy(plan,args.condition)
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
            metadata=dict(condition=args.condition,root_pid=host_root,root_pid_namespace='initial-kernel-worker',workspace_popen_pid=worker_state['pid'],source_observer_string_bytes=1024,loader_sha256=hashlib.sha256(LOADER.read_bytes()).hexdigest(),
                source_observer_sha256=hashlib.sha256((run/'source-observer.bt').read_bytes()).hexdigest(),kernel=os.uname().release)
            metadata['engine_environment']={name:os.environ.get(name) for name in (
                'ACTPLANE_HOOK_PROFILE','ACTPLANE_ENABLE_ADVANCED_HOOKS','ACTPLANE_ADVANCED_TRACEPOINTS','ACTPLANE_RESERVE_FILE_FLOW')}
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
        return result
    runner.request=request
    runner.CFG['run_phase']='benign-utility-v1-'+args.condition
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
            source_log=(run/'sources.jsonl').read_text(errors='replace') if (run/'sources.jsonl').exists() else ''
            if re.search(r'(?i)"type"\s*:\s*"[^"\n]*(?:error|lost|drop|overflow)[^"\n]*"',source_log):reasons.append('observer helper failure/event loss')
            exits=json.loads((run/'instrument-exits.json').read_text()) if (run/'instrument-exits.json').exists() else []
            if not exits or any(e['exit_code'] not in (0,-2) for e in exits):reasons.append('per-instrument exit receipt missing/nonzero')
            if reasons:
                attempts=ROOT/'attempts';attempts.mkdir(exist_ok=True)
                target=attempts/(args.condition+'-'+plan['dynamic_id']+'-'+str(time.time_ns()))
                shutil.move(str(run),target)
                (target/'exclusion-reason.json').write_text(json.dumps(dict(reasons=reasons),indent=2))
        runner.replay(raw,plan,sorted(calls[plan['trajectory_id']],key=lambda c:c['call_index']))


if __name__=='__main__': main()
