#!/usr/bin/env python3
"""Replay frozen tool effects under a private, seeded real eBPF engine.

No agent continuation or model judge is involved. Each trace gets fresh process,
file, endpoint, gate, and repository state. Only clause effects become notify.
"""
import argparse
import ast
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import time
import tempfile

import yaml

from prepare import HERE, ROOT, DEFAULT_RAW, csv_write, sha
from pack_fixtures import archive_path


def artifact_helpers(raw):
    """Load only passive tool implementation helpers, without SDK imports."""
    source = raw / 'artifact/docs/eval_scripts/agent_sdk_eval.py'
    tree = ast.parse(source.read_text())
    wanted = {'_write_executable', 'install_eval_safety_bin'}
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    file_script = next(ast.literal_eval(n.value) for n in tree.body
                       if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'FILE_CHANGE_SCRIPT' for t in n.targets))
    ns = {'Path': Path, 'SAFE_BIN_NAME': '.eval-safe-bin'}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), ns)
    return ns['install_eval_safety_bin'], file_script


def tools_in_trace(records):
    return [t for r in records if r.get('type') == 'assistant'
            for t in r.get('content', []) if isinstance(t, dict) and t.get('type') == 'tool_use']


def worker(payload):
    backing_work = Path(payload['work'])
    raw = Path(payload['raw'])
    _, file_script = artifact_helpers(raw)
    # Private mount and network namespaces were created by the coordinator.
    subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/tmp'], check=True)
    work = Path('/tmp/repo')
    work.mkdir()
    subprocess.run(['mount', '--bind', str(backing_work), str(work)], check=True)
    os.chdir(work)
    env = {'PATH': f'{work}/.eval-safe-bin:{work}/.eval-fixtures/bin:' + os.defpath + ':/usr/local/bin',
           'HOME': str(work / '.eval-home'), 'LANG': 'C.UTF-8',
           'GIT_TERMINAL_PROMPT': '0', 'UV_NO_SYNC': '1', 'UV_OFFLINE': '1',
           'PIP_NO_INDEX': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    env['PATH'] = f'{raw}/pythondeps/bin:' + env['PATH']
    Path(env['HOME']).mkdir(exist_ok=True)
    # Stop before any replay effect; resume only after the loader prints ready.
    os.kill(os.getpid(), signal.SIGSTOP)
    control_fd = payload['control_fd']
    os.write(control_fd, b'S')
    rows = []
    for step, tool in enumerate(tools_in_trace(payload['records']), 1):
        name, inp = tool['name'], tool['input']
        row = dict(step=step, tool=name, input=inp, returncode=0)
        try:
            if name == 'Read':
                p = Path(inp['file_path'])
                if p.is_absolute():
                    p = Path(str(p).lstrip('/'))
                # The artifact's Read tool opens an absolute safe_path in the
                # harness process. Keep it short enough for kernel path buffers.
                row['bytes_read'] = len((work / p).read_bytes())
            elif name in ('Write', 'Edit'):
                data = dict(inp, op=name.lower(), path=inp['file_path'].lstrip('/'))
                proc = subprocess.run([sys.executable, '-c', file_script], input=json.dumps(data),
                                      text=True, capture_output=True, env=env, timeout=30)
                row.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
            elif name == 'Bash':
                proc = subprocess.run(['/bin/bash', '-c', inp['command']], env=env,
                                      text=True, capture_output=True, timeout=30)
                row.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
            else:
                raise ValueError(f'Unsupported tool: {name}')
        except Exception as e:
            row.update(returncode=124 if isinstance(e, subprocess.TimeoutExpired) else 126,
                       error=f'{type(e).__name__}: {e}')
        rows.append(row)
    # Keep harness result serialization outside the monitored interval. Tool
    # subprocess stdout remains unchanged and is part of the replayed effects.
    os.write(control_fd, b'D')
    os.kill(os.getpid(), signal.SIGSTOP)
    os.close(control_fd)
    for row in rows:
        print(json.dumps(row), flush=True)


def notify_policy(text):
    return re.sub(r'(?m)^(\s*)(?:block|kill)(\s+(?:exec|open|read|write|unlink|connect|recv)\b)', r'\1notify\2', text)


def runner_label(text):
    # Mirror collect_label_names / runner_label in the pinned Rust source.
    # Remove strings/comments before extracting source/xform/condition labels.
    clean = re.sub(r'"(?:\\.|[^"\\])*"|#[^\n]*', '""', text)
    names = set(re.findall(r'(?m)^\s*(?:source|declassify|endorse)\s+(\w+)', clean))
    for expr in re.findall(r'\bif\s+([^\n]+)', clean):
        expr = re.split(r'\bunless\b', expr)[0]
        names.update(x for x in re.findall(r'\b[A-Za-z_]\w*\b', expr) if x not in ('and', 'or', 'not', 'true'))
    label = 'COMMAND' if 'COMMAND' in names else 'AGENT' if 'AGENT' in names else None
    return 1 << sorted(names).index(label) if label else 0


def wait_for(predicate, timeout):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return True
        time.sleep(.025)
    return False


def stopped(proc):
    try:
        return Path(f'/proc/{proc.pid}/stat').read_text().rsplit(')', 1)[1].split()[0] == 'T'
    except FileNotFoundError:
        return False


def wait_trace_done(child, control_fd, timeout=180):
    deadline = time.monotonic() + timeout
    received = b''
    while received != b'SD':
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([control_fd], [], [], remaining)[0]:
            raise TimeoutError('trace completion handshake timed out')
        part = os.read(control_fd, 2 - len(received))
        if not part:
            raise RuntimeError('worker exited before trace completion')
        received += part
    if not wait_for(lambda: stopped(child), 5):
        raise RuntimeError('worker did not stop after trace')


def copy_fixture(source, work, archive=None):
    # Source selection uses symlinks. Resolve before cp -a so each replay gets
    # an independent directory rather than a symlink to the frozen baseline.
    if archive is not None and archive.exists():
        work.mkdir()
        subprocess.run(['tar', '-xzf', str(archive), '--no-same-owner', '-C', str(work)], check=True)
    else:
        subprocess.run(['cp', '-a', '--reflink=auto', str(source.resolve()), str(work)], check=True)


def remove_checkout(work):
    if work.is_symlink():
        work.unlink()
    elif work.exists():
        shutil.rmtree(work)


def replay_one(raw, statement, trace, model, policy, out, no_engine=False, loader_bin=None, translation_status=None):
    out.mkdir(parents=True, exist_ok=True)
    records = list(map(json.loads, trace.read_text().splitlines()))
    row = dict(model=model, repo=statement.parent.name, statement_id=statement.name,
               trace=trace.name, family=trace.stem.replace('trace_', ''),
               violation=int(records[0]['violation']), status='ok', fired='', events='',
               tool_errors='', elapsed_s='', artifact_fired='', agreement='', error='')
    row['kernel'] = os.uname().release
    ephemeral = raw / 'guest-work'
    local_dir = Path(tempfile.mkdtemp(prefix='trace-', dir=ephemeral)) if os.path.ismount(ephemeral) else None
    work = local_dir / 'checkout' if local_dir else out / 'checkout'
    row['fixture_fs'] = 'guest-tmpfs' if local_dir else 'shared-filesystem'
    loader = child = None
    control_read = control_write = None
    start = time.monotonic()
    if not policy.strip():
        unavailable = translation_status in ('access_failure', 'identity_failure')
        row.update(status='translation_unavailable' if unavailable else 'translation_failed',
                   fired='' if unavailable else 0, events=0, tool_errors=0, elapsed_s=0,
                   error=f'No compiled translation: {translation_status or "compiler_failure"}')
        if local_dir:
            local_dir.rmdir()
        (out / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
        return row
    try:
        remove_checkout(work)
        source = raw / 'selected-rule-fixtures' / statement.parent.name / statement.name
        if not source.exists():
            source = raw / 'repos' / statement.parent.name
        archive = archive_path(source, raw)
        copy_fixture(source, work, archive)
        row['fixture_archive'] = archive.name if archive.exists() else 'unpacked-synthetic-control'
        row['fixture_commit'] = (source / '.fixture-ready').read_text().strip() if (source / '.fixture-ready').exists() else 'synthetic-control'
        row['loader_sha256'] = sha((loader_bin or ROOT / 'bpf/process').read_bytes())
        fixture = statement / 'fixtures'
        if fixture.exists():
            shutil.copytree(fixture, work / '.eval-fixtures', dirs_exist_ok=True)
        install, _ = artifact_helpers(raw)
        install(work)
        (work / '.eval-safe-bin/python').symlink_to(sys.executable)
        text = notify_policy(policy)
        (out / 'notify.dsl').write_text(text)
        row['policy_sha256'] = sha(policy.encode())
        row['notify_sha256'] = sha(text.encode())
        compiled = subprocess.run([str(ROOT / 'target/release/actplane'), '--rule', text,
                                   'compile', '--out', str(out / 'config.bin'), '--force'],
                                  text=True, capture_output=True, timeout=30)
        (out / 'compile.stderr').write_text(compiled.stderr)
        if compiled.returncode:
            raise RuntimeError('compile_failed: ' + compiled.stderr[:500])
        control_read, control_write = os.pipe()
        payload = dict(work=str(work), raw=str(raw), records=records, control_fd=control_write)
        # A namespace isolates networking and /tmp. It does not fake kernel events.
        argv = ['unshare', '--net', '--mount', '--propagation', 'private', '--',
                sys.executable, str(Path(__file__).resolve()), '--worker']
        with (out / 'tools.jsonl').open('w') as log, (out / 'worker.stderr').open('w') as err:
            child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=log, stderr=err,
                                     text=True, start_new_session=True, pass_fds=(control_write,))
            os.close(control_write)
            control_write = None
            child.stdin.write(json.dumps(payload))
            child.stdin.close()
            if not wait_for(lambda: stopped(child) or child.poll() is not None, 15) or child.poll() is not None:
                raise RuntimeError('worker_not_stopped: ' + (out / 'worker.stderr').read_text()[:300])
            if not no_engine:
                with (out / 'engine.jsonl').open('w') as events, (out / 'engine.stderr').open('w') as err:
                    loader = subprocess.Popen([str(loader_bin or ROOT / 'bpf/process'), '--config', str(out / 'config.bin'),
                                               '--seed-pid', str(child.pid), '--seed-label', str(runner_label(text))],
                                              stdout=events, stderr=err)
                    ready = wait_for(lambda: 'ActPlane: ready' in (out / 'engine.stderr').read_text()
                                     or loader.poll() is not None, 60)
                    if not ready or loader.poll() is not None:
                        raise RuntimeError('loader_not_ready: ' + (out / 'engine.stderr').read_text()[-500:])
                    child.send_signal(signal.SIGCONT)
                    wait_trace_done(child, control_read)
                    time.sleep(.3)
                    loader.terminate()
                    loader.wait(timeout=10)
                    child.send_signal(signal.SIGCONT)
                    child.wait(timeout=15)
            else:
                child.send_signal(signal.SIGCONT)
                wait_trace_done(child, control_read)
                child.send_signal(signal.SIGCONT)
                child.wait(timeout=15)
            if child.returncode:
                raise RuntimeError(f'worker_exit_{child.returncode}')
        tools = list(map(json.loads, (out / 'tools.jsonl').read_text().splitlines()))
        row['tool_errors'] = sum(t['returncode'] != 0 for t in tools)
        if len(tools) != len(tools_in_trace(records)):
            raise RuntimeError('tool_count_mismatch')
        if not no_engine:
            events = [json.loads(x) for x in (out / 'engine.jsonl').read_text().splitlines() if x.startswith('{')]
            events = [x for x in events if x.get('event') == 'TAINT_VIOLATION']
            row.update(fired=int(bool(events)), events=len(events))
    except Exception as e:
        row.update(status='error', error=f'{type(e).__name__}: {e}')
    finally:
        for fd in (control_read, control_write):
            if fd is not None:
                os.close(fd)
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGCONT)
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        if loader is not None and loader.poll() is None:
            loader.terminate()
            loader.wait(timeout=10)
        remove_checkout(work)
        if local_dir:
            local_dir.rmdir()
    row['elapsed_s'] = round(time.monotonic() - start, 4)
    (out / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
    return row


def artifact_outcomes(raw):
    rows = {}
    for f in (raw / 'artifact/docs/artifact/rq2-qwen-primary/results/actplane-opaque').glob('*/*/trace*.jsonl/*.json'):
        d = json.loads(f.read_text())
        key = (f.parents[2].name, f.parents[1].name, f.parent.name)
        if key in rows:
            raise ValueError(f'duplicate artifact result: {key}')
        rows[key] = int(d['setup_fired'])
    return rows


def main():
    if '--worker' in sys.argv:
        worker(json.load(sys.stdin))
        return
    ap = argparse.ArgumentParser()
    ap.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    ap.add_argument('--model', default='reference')
    ap.add_argument('--limit', type=int)
    ap.add_argument('--no-engine', action='store_true')
    ap.add_argument('--redo-errors', action='store_true')
    ap.add_argument('--run-tag', default='guest68')
    ap.add_argument('--select', help='Optional statement path substring for diagnostic smoke runs')
    ap.add_argument('--loader', type=Path)
    args = ap.parse_args()
    original = artifact_outcomes(args.raw)
    rows = []
    for statement in sorted((args.raw / 'artifact/docs/corpus-test').glob('*/*/statement.json')):
        sd = statement.parent
        if args.select and args.select not in str(sd):
            continue
        if args.model == 'reference':
            policy = yaml.safe_load((sd / 'rule.yaml').read_text())['policy']
            translation_status = 'reference'
        else:
            trial = args.raw / 'translations/rq2' / args.model.replace('/', '__') / f'{sd.parent.name}__{sd.name}' / 'result.json'
            if not trial.exists():
                continue
            result = json.loads(trial.read_text())
            translation_status = result['status']
            policy = result.get('policy')
            if not policy:
                policy = ''
        for name in json.loads(statement.read_text())['trace_files']:
            out = args.raw / ('preflight' if args.no_engine else 'replay') / args.run_tag / args.model.replace('/', '__') / sd.parent.name / sd.name / name
            cached = out / 'result.json'
            if cached.exists() and not (args.redo_errors and json.loads(cached.read_text())['status'] != 'ok'):
                row = json.loads(cached.read_text())
            else:
                row = replay_one(args.raw, sd, sd / name, args.model, policy, out, args.no_engine, args.loader, translation_status)
                print(sd.parent.name, sd.name, name, row['status'], row['fired'], flush=True)
            key = (sd.parent.name, sd.name, name)
            row['artifact_fired'] = original.get(key, '')
            if row['fired'] != '' and row['artifact_fired'] != '':
                row['agreement'] = int(row['fired'] == row['artifact_fired'])
            rows.append(row)
            if args.limit and len(rows) >= args.limit:
                break
        if args.limit and len(rows) >= args.limit:
            break
    if rows:
        fields = sorted(set().union(*(r.keys() for r in rows)))
        rows = [{k: r.get(k, '') for k in fields} for r in rows]
        prefix = 'preflight-' if args.no_engine else 'replay-'
        if args.limit or args.select:
            prefix = 'diagnostic-' + args.run_tag + '-' + prefix
        csv_write(HERE / (prefix + args.model.replace('/', '__') + '.csv'), rows)


if __name__ == '__main__':
    main()
