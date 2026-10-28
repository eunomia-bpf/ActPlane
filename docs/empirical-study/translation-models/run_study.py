#!/usr/bin/env python3
"""Resumable lane driver: reference, sample translations, full corpus, reporting.

Only this lane's branch and artifacts are committed/pushed. No PR operations.
Existing initial jobs can be adopted so endpoint concurrency is not doubled.
"""
import argparse
import csv
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from prepare import HERE, ROOT, DEFAULT_RAW

STATE = Path('/workspaces/.agent-state/actplane-translation-models')
BRANCH = 'experiments/translation-models-20261028'


def command(script, *args):
    return [sys.executable, str(HERE / script), *map(str, args)]


def run(argv):
    print('RUN', ' '.join(argv), flush=True)
    subprocess.run(argv, cwd=ROOT, check=True)


def alive(pid, needle):
    if not pid:
        return False
    try:
        return needle.encode() in Path(f'/proc/{pid}/cmdline').read_bytes()
    except FileNotFoundError:
        return False


def derive():
    for script in ('prompt_manifest.py', 'compile_references.py', 'prices.py', 'export_attempts.py', 'summarize.py', 'report.py'):
        run(command(script))


def checkpoint(message):
    derive()
    # File scope is explicit. Raw files live outside this path. Generated CSV
    # writes are atomic, and all empirical prose is regenerated from those CSVs.
    paths = [p for p in HERE.iterdir() if p.suffix in ('.py', '.h', '.csv', '.md', '.tex', '.pdf') or p.name == '.gitattributes']
    run(['git', 'add', *map(str, sorted(paths))])
    run(['git', 'diff', '--cached', '--check'])
    changed = subprocess.run(['git', 'diff', '--cached', '--quiet'], cwd=ROOT).returncode
    if changed:
        run(['git', 'commit', '-m', message])
        run(['git', 'push', 'origin', f'HEAD:refs/heads/{BRANCH}'])


def write_status(phase):
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / 'study-status.json').write_text(json.dumps(dict(phase=phase, pid=os.getpid(), utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())), indent=2) + '\n')


def wait_adopted(pid, needle, phase):
    last = time.monotonic()
    while alive(pid, needle):
        write_status(phase)
        if time.monotonic() - last > 600:
            checkpoint('experiments: checkpoint ongoing translation measurements')
            last = time.monotonic()
        time.sleep(30)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--adopt-rq2-pid', type=int, default=0)
    ap.add_argument('--adopt-reference-pid', type=int, default=0)
    args = ap.parse_args()
    lock = (DEFAULT_RAW / 'study-driver.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    branch = subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip()
    if branch != BRANCH:
        raise SystemExit('Refusing to run on an unexpected branch')
    run(command('test_protocol.py'))
    write_status('reference validation')
    wait_adopted(args.adopt_reference_pid, 'guest.py', 'reference validation')
    run(command('guest.py', '--log', 'reference-final-resume', '--', *command('replay.py', '--run-tag', 'guest68-scored-v2', '--loader', DEFAULT_RAW / 'bounded-loader/process')))
    checkpoint('experiments: record full reference replay and artifact agreement')
    write_status('sample translations')
    wait_adopted(args.adopt_rq2_pid, 'translate.py', 'sample translations')
    run(command('translate.py', '--corpus', 'rq2'))
    checkpoint('experiments: record policy-sample model translations')
    write_status('corpus translations and model replay')
    logs = DEFAULT_RAW / 'orchestration'
    logs.mkdir(exist_ok=True)
    with (logs / 'rq1.log').open('w') as out1, (logs / 'model-replay.log').open('w') as out2:
        rq1 = subprocess.Popen(command('translate.py', '--corpus', 'rq1'), cwd=ROOT, stdout=out1, stderr=subprocess.STDOUT)
        replay = subprocess.Popen(command('guest.py', '--log', 'model-replays', '--', *command('replay_batch.py')), cwd=ROOT, stdout=out2, stderr=subprocess.STDOUT)
        last = time.monotonic()
        while rq1.poll() is None or replay.poll() is None:
            if time.monotonic() - last > 600:
                checkpoint('experiments: checkpoint corpus compilation and kernel outcomes')
                last = time.monotonic()
            time.sleep(30)
        if rq1.returncode or replay.returncode:
            raise RuntimeError(f'Background phase failed: rq1={rq1.returncode}, replay={replay.returncode}; resume this driver after inspecting logs')
    derive()
    run(command('validate_outputs.py'))
    checkpoint('experiments: finalize model comparison, figure, and paper snippets')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    rows = list(csv.DictReader((HERE / 'summary.csv').open()))
    table = ['| Model | Sample compile@3 | Corpus compile@3 | Detection | FTR | F1 |', '| --- | --- | --- | --- | --- | --- |']
    for r in rows:
        if r['access_status'] not in ('ok', 'reference'):
            continue
        def pct(x): return f'{float(x)*100:.1f}%' if x != '' else 'unavailable'
        table.append(f"| {r['model']} | {r['rq2_compiled_at_3']}/{r['rq2_completed']} | {r['rq1_compiled_at_3']}/{r['rq1_completed']} | {pct(r['detection_rate'])} | {pct(r['false_trigger_rate'])} | {r['f1'] or 'unavailable'} |")
    (STATE / 'SUMMARY.md').write_text(f'''# Translation-model lane

Branch: `{BRANCH}`
Final commit: `{commit}`

Measured compiler acceptance, bounded compiler revisions, response identities,
tokens, wall time, uncached list-price equivalents, and deterministic kernel replay.
No agent continuation or model judge was used.

{chr(10).join(table)}

Committed files: `docs/empirical-study/translation-models/`.
Raw inputs and logs: `{DEFAULT_RAW}`.

See the README and summary CSV for reference-artifact agreement, trace-family
breakdowns, access failures, failed kernel loads, and excluded preliminary calls.
The kernel engine uses documented experimental verifier changes and recovered
source fixtures. Compilation is not semantic accuracy. Provider and CLI defaults
differ. Missing scores remain unavailable rather than becoming true negatives.
No PR was opened or modified. The operator consolidates lane branches.
''')
    write_status('complete')
    print('Study complete', commit, flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        write_status('driver error')
        with (STATE / 'BLOCKED.md').open('a') as f:
            f.write(f'\nDriver stopped: {type(error).__name__}: {error}. Inspect raw orchestration logs and resume run_study.py.\n')
        raise
