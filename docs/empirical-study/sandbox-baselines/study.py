#!/usr/bin/env python3
"""Run frozen RQ2 tool effects inside shipping sandbox boundaries (Linux only)."""
import argparse
import ast
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import tempfile

HERE = Path(__file__).resolve().parent
LANE = Path('/workspaces/exp/sandbox-baselines')
RAW = LANE / 'raw'
SOURCE_RAW = Path('/workspaces/.agent-state/actplane-research/raw/translation-models-20261028')
VENDOR = HERE / 'vendor'
sys.path.insert(0, str(VENDOR))
import replay


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def manifest(work):
    result = {}
    for p in sorted(work.rglob('*')):
        if p.is_symlink():
            result[str(p.relative_to(work))] = {'link': os.readlink(p)}
        elif p.is_file():
            try:
                b = p.read_bytes()
                result[str(p.relative_to(work))] = dict(sha256=hashlib.sha256(b).hexdigest(),
                    size=len(b), mode=p.stat().st_mode & 0o7777)
            except OSError as e:
                result[str(p.relative_to(work))] = {'error': str(e)}
    return result


def worker():
    """Execute the copied worker's original environment and tool-loop AST nodes."""
    payload = json.load(sys.stdin)
    assert Path('/tmp/repo/.eval-home').is_dir()
    tree = ast.parse((VENDOR / 'replay.py').read_text())
    original = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'worker')
    selected = []
    for n in original.body:
        if isinstance(n, ast.Assign):
            target = n.targets[0]
            if isinstance(target, ast.Name) and target.id in ('env', 'rows'):
                selected.append(n)
            elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == 'env':
                selected.append(n)
        elif isinstance(n, ast.For):
            selected.append(n)
    # The fixture chmod loop is setup, already completed by prepared_case.
    selected = [n for n in selected if not (isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == 'fixture')]
    namespace = dict(replay.__dict__, payload=payload, raw=SOURCE_RAW, work=Path('/tmp/repo'),
                     file_script=replay.artifact_helpers(SOURCE_RAW)[1])
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(VENDOR / 'replay.py'), 'exec'), namespace)


def prepared_case(payload):
    out = Path(payload['out'])
    subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/tmp'], check=True)
    work = Path('/tmp/repo')
    sd = Path(payload['statement'])
    source = SOURCE_RAW / 'selected-rule-fixtures' / sd.parent.name / sd.name
    archive = replay.archive_path(source, SOURCE_RAW)
    backing_parent = Path(tempfile.mkdtemp(prefix='checkout-', dir=RAW))
    backing = backing_parent / 'repo'
    replay.copy_fixture(source, backing, archive)
    work.mkdir()
    subprocess.run(['mount', '--bind', str(backing), str(work)], check=True)
    fixture = sd / 'fixtures'
    if fixture.exists():
        shutil.copytree(fixture, work / '.eval-fixtures', dirs_exist_ok=True)
    install, _ = replay.artifact_helpers(SOURCE_RAW)
    install(work)
    (work / '.eval-safe-bin/python').symlink_to(sys.executable)
    for f in (work / '.eval-fixtures').rglob('*'):
        if f.is_file() and (f.parent.name == 'bin' or f.suffix == '.sh'):
            f.chmod(f.stat().st_mode | 0o755)
    (work / '.eval-home').mkdir(exist_ok=True)
    os.chdir(work)
    records = [json.loads(x) for x in Path(payload['trace']).read_text().splitlines()]
    body = dict(work=str(work), raw=str(SOURCE_RAW), records=records)
    dump(out / 'before.json', manifest(work))
    env = dict(PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               HOME=str(work / '.eval-home'), LANG='C.UTF-8',
               CODEX_HOME=str(RAW / 'codex-home'))
    base = [sys.executable, str(HERE / 'study.py'), '--worker']
    system = payload['system']
    if system == 'control':
        command = base
    elif system == 'codex':
        command = [str(RAW / 'codex-real'), 'sandbox', '-c', 'sandbox_mode="workspace-write"', '--'] + base
    elif system.startswith('srt'):
        command = [str(RAW / 'tools/node_modules/.bin/srt')]
        if system == 'srt-cwd':
            command += ['--settings', str(HERE / 'srt-cwd.json')]
        command += ['--'] + base
    elif system == 'docker':
        # No security override. Bind mounts only provide workload/input/output.
        command = ['docker', 'run', '--rm', '-i', '-w', '/tmp/repo',
                   '-v', f'{backing}:/tmp/repo',
                   '-v', f'{SOURCE_RAW}:{SOURCE_RAW}:ro',
                   '-v', f'{HERE}:{HERE}:ro', '-v', f'{out}:/audit',
                   'actplane-sandbox-baselines:trixie',
                   'strace', '-f', '-qq', '-s', '2000', '-e', 'trace=%file,%process',
                   '-o', '/audit/syscalls.log'] + base
    else:
        raise ValueError(system)
    if system != 'docker':
        command = ['strace', '-f', '-qq', '-s', '2000', '-e', 'trace=%file,%process',
                   '-o', str(out / 'syscalls.log')] + command
    dump(out / 'command.json', command)
    start = time.monotonic()
    with (out / 'tools.jsonl').open('w') as stdout, (out / 'stderr.txt').open('w') as stderr:
        proc = subprocess.run(command, input=json.dumps(body), text=True, env=env,
                              stdout=stdout, stderr=stderr, timeout=240)
    dump(out / 'after.json', manifest(work))
    dump(out / 'execution.json', dict(returncode=proc.returncode,
         elapsed_s=round(time.monotonic()-start, 3), tools_expected=len(replay.tools_in_trace(records)),
         fixture_archive=archive.name, fixture_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
    shutil.rmtree(backing_parent)


def original_case(payload):
    # The complete upstream coordinator/worker path, with no edits or interception.
    replay.ROOT = Path('/workspaces/lanes/translation-models')
    sd = Path(payload['statement'])
    row = replay.replay_one(SOURCE_RAW, sd, Path(payload['trace']), 'original-control',
                           'source AGENT = exec "python3"\nrule audit:\n notify exec "__never__" if AGENT\n because "control"',
                           Path(payload['out']), no_engine=True)
    print(json.dumps(row), flush=True)
    if row['status'] != 'ok':
        raise RuntimeError(row['error'])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--worker', action='store_true')
    ap.add_argument('--case')
    ap.add_argument('--original')
    ap.add_argument('--systems', default='control,codex,srt,srt-cwd,docker')
    ap.add_argument('--limit', type=int)
    ap.add_argument('--tag', default='main')
    args = ap.parse_args()
    if args.worker:
        worker(); return
    if args.case:
        prepared_case(json.loads(Path(args.case).read_text())); return
    if args.original:
        original_case(json.loads(Path(args.original).read_text())); return
    traces = [(s.parent, s.parent / n) for s in sorted((SOURCE_RAW / 'artifact/docs/corpus-test').glob('*/*/statement.json'))
              for n in json.loads(s.read_text())['trace_files']]
    if args.limit:
        traces = traces[:args.limit]
    for system in args.systems.split(','):
        for sd, trace in traces:
            out = RAW / args.tag / system / sd.parent.name / sd.name / trace.stem
            if (out / 'execution.json').exists():
                continue
            while shutil.disk_usage('/workspaces').used / shutil.disk_usage('/workspaces').total >= .85:
                print('waiting for shared disk below user ceiling', system, trace, flush=True)
                time.sleep(5)
            out.mkdir(parents=True, exist_ok=True)
            payload = dict(statement=str(sd), trace=str(trace), out=str(out), system=system)
            dump(out / 'payload.json', payload)
            start = time.monotonic()
            try:
                command = (['python3', str(HERE / 'study.py'), '--original', str(out / 'payload.json')]
                           if system == 'original' else
                           ['unshare', '--mount', '--propagation', 'private', '--',
                            'python3', str(HERE / 'study.py'), '--case', str(out / 'payload.json')])
                p = subprocess.run(command, capture_output=True, text=True, timeout=300)
                (out / 'setup.stdout').write_text(p.stdout)
                (out / 'setup.stderr').write_text(p.stderr)
                if p.returncode:
                    dump(out / 'failure.json', dict(returncode=p.returncode, error=p.stderr[-3000:]))
                if system == 'original' and p.returncode == 0:
                    dump(out / 'execution.json', {'returncode':0})
                print(args.tag, system, sd.parent.name, sd.name, trace.stem, p.returncode,
                      round(time.monotonic()-start, 2), flush=True)
            except Exception as e:
                dump(out / 'failure.json', {'error':str(e)})
                print(system, trace, type(e).__name__, str(e), flush=True)


if __name__ == '__main__':
    main()
