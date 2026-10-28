#!/usr/bin/env python3
"""Replay fixed public call sequences in isolated local namespaces under eBPF.

The coordinator and environment setup are outside the observed lineage. Only
tagged replay children and their descendants contribute observer effects.
"""
import argparse
import csv
import gzip
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import time

from analyze import HERE

CFG=json.loads((HERE/'dynamic_config.json').read_text())


def disk_guard(raw):
    usage=shutil.disk_usage(raw)
    if 100*usage.used/usage.total>=CFG['workspace_limit_pct']:
        raise RuntimeError('workspace disk limit reached')
    measured=subprocess.run(['du','-sb',str(raw)],capture_output=True,text=True)
    if not measured.stdout.split():raise RuntimeError('raw storage measurement failed')
    size=int(measured.stdout.split()[0])
    if measured.returncode:
        with (raw/'dynamic'/'resource_scan_errors.jsonl').open('a') as f:
            f.write(json.dumps(dict(utc=time.time(),exit=measured.returncode,detail=measured.stderr))+'\n')
    if size>=CFG['raw_limit_bytes']:
        raise RuntimeError('raw storage limit reached')
    return size,round(100*usage.used/usage.total,3)


def checked(argv,log,timeout=300,cwd=None):
    env=os.environ.copy()
    env.update(GIT_TERMINAL_PROMPT='0',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null')
    with open(log,'ab') as f:
        f.write((json.dumps(argv)+'\n').encode())
        result=subprocess.run(argv,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'command failed with exit {result.returncode}; see {log.name}')


def materialize(raw,plan,run):
    cache=raw/'dynamic'/'git-cache'/plan['repository'].replace('/','__')
    cache.parent.mkdir(parents=True,exist_ok=True)
    log=run/'clone.log'
    sha=plan['base_commit']
    if not cache.exists():
        checked(['git','init','--bare',str(cache)],log)
    present=subprocess.run(['git','--git-dir',str(cache),'cat-file','-e',sha+'^{commit}'],capture_output=True).returncode==0
    if not present:
        checked(['git','--git-dir',str(cache),'fetch','--depth','1','https://github.com/'+plan['repository']+'.git',sha],log,timeout=300)
        checked(['git','--git-dir',str(cache),'update-ref','refs/heads/base-'+sha[:12],sha],log)
    repo=run/'repo'
    if not repo.exists():
        checked(['git','clone','--no-hardlinks','--no-checkout',str(cache),str(repo)],log)
        checked(['git','checkout','--detach',sha],log,cwd=repo)
        # Public origin, without a credential helper or any private credential.
        checked(['git','remote','set-url','origin','https://github.com/'+plan['repository']+'.git'],log,cwd=repo)
    actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
    assert actual==sha,'base checkout mismatch'
    return repo


def sandbox(raw,plan,run,repo):
    root=raw/'dynamic'
    shared=run/'cache';shared.mkdir(exist_ok=True)
    for name in ('venv','home','tmp','replay','replay/requests','replay/logs'):
        (run/name).mkdir(parents=True,exist_ok=True)
    for name in ('replay_worker.py','replay_tools.py'):
        shutil.copy2(HERE/name,run/'replay'/name)
    shutil.copy2(root/'launch',run/'replay'/'launch')
    (run/'replay'/'bin').mkdir(exist_ok=True)
    patch=run/'replay'/'bin'/'apply_patch'
    patch.write_text('#!/bin/sh\nexec /usr/bin/python3 /replay/replay_tools.py --patch-stdin\n')
    patch.chmod(0o755)
    uv=shutil.which('uv') or str(Path(sys.executable).with_name('uv'))
    if Path(uv).exists():shutil.copy2(uv,run/'replay'/'bin'/'uv')
    command=['bwrap','--unshare-all','--share-net','--die-with-parent','--new-session','--cap-drop','ALL',
             '--ro-bind','/usr','/usr','--ro-bind','/etc','/etc',
             '--symlink','usr/bin','/bin','--symlink','usr/sbin','/sbin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
             '--proc','/proc','--dev','/dev','--bind',str(run/'tmp'),'/tmp','--bind',str(run/'home'),'/root',
             '--bind',str(run/'venv'),'/venv','--bind',str(shared),'/cache','--bind',str(run/'replay'),'/replay',
             '--bind',str(repo),plan['sandbox_workdir'],
             '--ro-bind',str(root/'toolchains'),str(root/'toolchains'),
             '--dir','/opt','--symlink','/venv','/opt/venv','--dir','/opt/miniconda3','--dir','/opt/miniconda3/envs',
             '--symlink','/venv','/opt/miniconda3/envs/testbed','--dir','/opt/conda','--dir','/opt/conda/envs',
             '--symlink','/venv','/opt/conda/envs/testbed','--clearenv']
    variables=dict(PATH='/venv/bin:/replay/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin',HOME='/root',USER='root',
                   LANG='C.UTF-8',LC_ALL='C.UTF-8',TERM='dumb',PIP_CACHE_DIR='/cache/pip',UV_CACHE_DIR='/cache/uv',
                   UV_PYTHON_INSTALL_DIR=str(root/'toolchains'),UV_PYTHON_DOWNLOADS='never',
                   CARGO_HOME='/cache/cargo',RUSTUP_HOME='/usr/local/rustup',CARGO_BUILD_JOBS='2',
                   GOMAXPROCS='2',GOCACHE='/cache/go-build',GOMODCACHE='/cache/go-mod',GOPATH='/cache/go',
                   MAKEFLAGS='-j2',NPY_NUM_BUILD_JOBS='2',npm_config_cache='/cache/npm',
                   GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0',
                   JAVA_HOME='/usr/lib/jvm/java-21-openjdk-amd64',VIRTUAL_ENV='/venv')
    variables['MAVEN_OPTS']='-Dmaven.repo.local=/cache/maven'
    for key,value in variables.items():command.extend(['--setenv',key,value])
    command.extend(['--chdir',plan['sandbox_workdir'],'/usr/bin/python3','-u','/replay/replay_worker.py'])
    allowed=sorted(os.sched_getaffinity(0))[:2]
    def affinity():os.sched_setaffinity(0,allowed)
    stderr=open(run/'worker.stderr','w')
    proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,text=True,bufsize=1,preexec_fn=affinity)
    ready=proc.stdout.readline()
    if not ready or not json.loads(ready).get('worker_ready'):
        raise RuntimeError('sandbox worker did not become ready')
    return proc,stderr,variables,allowed


def request(worker,job):
    worker.stdin.write(json.dumps(job)+'\n');worker.stdin.flush()
    selector=selectors.DefaultSelector()
    selector.register(worker.stdout,selectors.EVENT_READ)
    if not selector.select(timeout=job['timeout_s']+30):
        raise RuntimeError('sandbox protocol timeout')
    line=worker.stdout.readline()
    if not line:raise RuntimeError('sandbox worker exited')
    return json.loads(line)


def setup(worker,raw,plan,run):
    version='3.9' if plan['source']=='mini' else '3.12'
    toolchains=raw/'dynamic'/'toolchains'
    python=next(toolchains.glob('cpython-'+version+'*/bin/python'+version))
    meta=[]
    commands=[str(python)+' -m venv /venv',
              '/venv/bin/python -m pip install --disable-pip-version-check "setuptools<70" wheel "pytest<8"']
    language=plan['language']
    if language=='python':
        if plan['source']=='mini':
            commands.append('/venv/bin/python -m pip install --disable-pip-version-check "numpy<1.24" "scipy<1.11" "Cython<3" mock pillow requests')
        commands.append('/venv/bin/python -m pip install --disable-pip-version-check -e .')
    elif language in ('typescript','javascript'):
        commands.append('if [ -f package.json ]; then npm install --no-audit --no-fund; fi')
    elif language=='rust':commands.append('cargo fetch --locked')
    elif language=='go':commands.append('go mod download')
    elif language=='java':commands.append('mvn -B -q -DskipTests dependency:go-offline')
    for i,command in enumerate(commands):
        result=request(worker,dict(command=command,shell=True,cwd=plan['sandbox_workdir'],timeout_s=CFG['environment_setup_timeout_s'],
                                   log_path=f'/replay/logs/setup-{i}.log',log_limit=CFG['stdout_log_limit_bytes']))
        meta.append(dict(command=command,**result))
        (run/'setup.json').write_text(json.dumps(meta,indent=2))
        disk_guard(raw)
    result=request(worker,dict(command='python --version; python -m pip freeze; node --version; java -version; go version; rustc --version; uname -a',
                               shell=True,cwd=plan['sandbox_workdir'],timeout_s=60,log_path='/replay/logs/versions.log',log_limit=CFG['stdout_log_limit_bytes']))
    return meta


def observer_start(run):
    frozen=run/'observer.bt'
    shutil.copy2(HERE/'observer.bt',frozen)
    (run/'observer_metadata.json').write_text(json.dumps(dict(observer_sha256=hashlib.sha256(frozen.read_bytes()).hexdigest(),
                                                            host_kernel=os.uname().release,config=CFG),indent=2))
    stdout=open(run/'observer.jsonl','w')
    stderr=open(run/'observer.stderr','w')
    env=os.environ.copy();env.update(BPFTRACE_MAX_STRLEN=str(CFG['observer_string_bytes']),BPFTRACE_MAX_MAP_KEYS=str(CFG['observer_max_map_keys']))
    proc=subprocess.Popen(['bpftrace','-f','json',str(frozen)],stdout=stdout,stderr=stderr,env=env)
    start=time.monotonic()
    while time.monotonic()-start<30:
        if 'OBSERVER_READY' in (run/'observer.jsonl').read_text():return proc,stdout,stderr
        if proc.poll() is not None:break
        time.sleep(.1)
    raise RuntimeError('observer did not become ready; see observer.stderr')


def save_final(worker,run,plan):
    if worker.poll() is not None:return
    for name,command in [('final-diff','git diff --binary'),('final-status','git status --porcelain'),('final-freeze','python -m pip freeze')]:
        try:request(worker,dict(command=command,shell=True,cwd=plan['sandbox_workdir'],timeout_s=30,
                                log_path=f'/replay/logs/{name}.log',log_limit=20*1024*1024))
        except Exception:pass


def replay(raw,plan,calls,cleanup=True):
    run=raw/'dynamic'/'runs'/plan['dynamic_id']
    run.mkdir(parents=True,exist_ok=True)
    if (run/'done.json').exists():
        print('cached',plan['dynamic_id'],flush=True);return
    worker=None;observer=None;setup_results=[];fatal=''
    started=time.time();completed=[]
    try:
        disk_guard(raw)
        repo=materialize(raw,plan,run)
        worker,worker_stderr,env,affinity=sandbox(raw,plan,run,repo)
        (run/'environment.json').write_text(json.dumps(dict(variables=env,affinity=affinity,host_kernel=os.uname().release),indent=2))
        setup_results=setup(worker,raw,plan,run)
        observer,observer_stdout,observer_stderr=observer_start(run)
        cwd=plan['sandbox_workdir']
        with open(run/'calls.jsonl','a') as log:
            for call in calls:
                if time.time()-started>CFG['per_trajectory_timeout_s']:
                    raise RuntimeError('trajectory time budget reached')
                if call['call_index']%10==0:disk_guard(raw)
                tag='apti6e'+plan['dynamic_id'][1:]+f"{call['call_index']:05d}"
                args=call['args'];tool=call['tool'].lower()
                call_cwd=args.get('workdir',args.get('cwd',cwd))
                if plan['source']=='mini':call_cwd=plan['sandbox_workdir']
                shell=tool in ('bash','shell','exec_command','shell_command','execute_bash','monitor')
                if shell:
                    command=args.get('command',args.get('cmd',''))
                else:
                    filename=f'/replay/requests/{call["call_index"]:05d}.json'
                    (run/'replay'/'requests'/f'{call["call_index"]:05d}.json').write_text(json.dumps(dict(tool=call['tool'],args=args)))
                    command=['/usr/bin/python3','/replay/replay_tools.py',filename]
                result=request(worker,dict(tag=tag,command=command,shell=shell,cwd=call_cwd,
                                            timeout_s=CFG['per_call_timeout_s'],log_path=f'/replay/logs/call-{call["call_index"]:05d}.log',
                                            log_limit=CFG['stdout_log_limit_bytes']))
                record=dict(call_id=call['call_id'],dynamic_id=plan['dynamic_id'],tag=tag,call_index=call['call_index'],
                            tool=call['tool'],classification=call['classification'],original_status=call['status'],
                            cwd_before=call_cwd,executed=1,shell=int(shell),**result)
                log.write(json.dumps(record)+'\n');log.flush();completed.append(record)
                if plan['framework']=='Claude Code' and shell:cwd=result['cwd_after']
                print(plan['dynamic_id'],f"{len(completed)}/{len(calls)}",call['classification'],result.get('exit_code'),flush=True)
        save_final(worker,run,plan)
    except KeyboardInterrupt:
        fatal='KeyboardInterrupt: replay coordinator interrupted'
        raise
    except Exception as exc:
        fatal=type(exc).__name__+': '+str(exc)
        (run/'fatal.txt').write_text(fatal)
        print('FAILED',plan['dynamic_id'],fatal,flush=True)
    finally:
        if worker and worker.poll() is None:
            try:worker.stdin.write(json.dumps({'shutdown':True})+'\n');worker.stdin.flush();worker.wait(timeout=10)
            except Exception:worker.kill();worker.wait()
            worker_stderr.close()
        if observer and observer.poll() is None:
            time.sleep(.2)
            observer.send_signal(signal.SIGINT)
            try:observer.wait(timeout=30)
            except subprocess.TimeoutExpired:observer.kill();observer.wait();fatal+='; observer shutdown timeout'
            observer_stdout.close();observer_stderr.close()
        done=dict(dynamic_id=plan['dynamic_id'],trajectory_id=plan['trajectory_id'],run_phase=CFG['run_phase'],recorded_calls=len(calls),executed_calls=len(completed),
                  fatal=fatal,setup_steps=len(setup_results),setup_failed_steps=sum(r.get('exit_code')!=0 for r in setup_results),
                  elapsed_s=round(time.time()-started,3),observer_exit=observer.returncode if observer else None,
                  started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(started)),finished_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
        (run/'done.json').write_text(json.dumps(done,indent=2))
        # The frozen inputs, base Git objects, environment receipts, final diff,
        # logs, and observer counts are retained. Build/dependency trees are disposable.
        if cleanup:
            for directory in ('repo','venv','tmp','home','cache'):
                shutil.rmtree(run/directory,ignore_errors=True)
    print('DONE',plan['dynamic_id'],json.dumps(done),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--raw',type=Path,required=True)
    parser.add_argument('--ids',default='')
    parser.add_argument('--keep-runtime',action='store_true')
    parser.add_argument('--observer-string-bytes',type=int,default=None,
                        help='Instrumentation retry override, retained in per-run observer metadata')
    args=parser.parse_args()
    if args.observer_string_bytes is not None:
        if args.observer_string_bytes<256:parser.error('observer string buffer must be at least 256 bytes')
        CFG['observer_string_bytes']=args.observer_string_bytes
    root=args.raw/'dynamic';root.mkdir(exist_ok=True)
    checked(['gcc','-O2','-Wall','-Wextra',str(HERE/'launch.c'),'-o',str(root/'launch')],root/'build-launch.log')
    plans=list(csv.DictReader((HERE/'dynamic_plan.csv').open()))
    if args.ids:plans=[p for p in plans if p['dynamic_id'] in args.ids.split(',')]
    wanted={p['trajectory_id'] for p in plans};calls={key:[] for key in wanted}
    with gzip.open(args.raw/'classified_calls.jsonl.gz','rt') as f:
        for line in f:
            row=json.loads(line)
            if row['trajectory_id'] in wanted:calls[row['trajectory_id']].append(row)
    for plan in plans:
        replay(args.raw,plan,sorted(calls[plan['trajectory_id']],key=lambda c:c['call_index']),not args.keep_runtime)
