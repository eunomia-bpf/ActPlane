#!/usr/bin/env python3
"""Serial recovery of overloaded-provider transports, with a campaign cutoff.

No returned translation is resampled. All original model requests finish before
this worker starts. The cutoff bounds new policy starts, leaving time for the
last bounded transport/compiler trajectory and final reporting.
"""
import argparse
import concurrent.futures
import csv
import datetime as dt
import fcntl
import json
import subprocess
import sys
import time

from prepare import DEFAULT_RAW, HERE, ROOT, csv_write, json_write
from translate import inputs, translate_one, export_trials, cooldown_path, cache_is_terminal, result_path

CONFIGS = {
    'zai/glm-4.7-flash': dict(workers=1, corpora=('rq2', 'rq1'), quiescent_s=0,
                            lock='provider-recovery.lock'),
    'qwen3.8-27b-nvfp4': dict(workers=4, corpora=('rq1',), quiescent_s=600,
                            lock='local-provider-recovery.lock'),
}
BUDGET = 6
DEADLINE = dt.datetime(2026, 10, 29, 8, 30, tzinfo=dt.timezone.utc)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', choices=list(CONFIGS), default='zai/glm-4.7-flash')
    model = parser.parse_args().model
    config = CONFIGS[model]
    lock = (DEFAULT_RAW / config['lock']).open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with (DEFAULT_RAW / 'recovery-protocol.lock').open('w') as protocol_lock:
        fcntl.flock(protocol_lock, fcntl.LOCK_EX)
        path = HERE / 'recovery-protocol.csv'
        rows = list(csv.DictReader(path.open())) if path.exists() else []
        rows = [r for r in rows if r['model'] != model]
        rows += [dict(model=model, corpus=corpus, maximum_transports=BUDGET,
                      worker_limit=config['workers'], cutoff_utc=DEADLINE.isoformat(),
                      trigger='original corpus model queue complete',
                      selection='access failures only; returned answers cached',
                      quiescent_s=config['quiescent_s']) for corpus in config['corpora']]
        for row in rows:
            row.setdefault('quiescent_s', 0)
        csv_write(path, rows)
    expected = {r['uid'].replace('::', '__').replace('/', '__') for r in inputs(DEFAULT_RAW, 'rq1')}
    directory = DEFAULT_RAW / 'translations/rq1' / model.replace('/', '__')
    while {p.parent.name for p in directory.glob('*/result.json')} != expected:
        time.sleep(30)
    print('Original model queue complete. Starting access recovery:', model, flush=True)
    if config['quiescent_s'] and time.time() < DEADLINE.timestamp():
        json_write(cooldown_path(DEFAULT_RAW, model), dict(
            retry_after_unix=time.time() + config['quiescent_s'], reason='quiescence before access recovery'))
    for corpus in config['corpora']:
        def recover(item):
            if time.time() >= DEADLINE.timestamp():
                return None
            return translate_one(DEFAULT_RAW, corpus, model, item, transport_limit=BUDGET)
        pending = [item for item in inputs(DEFAULT_RAW, corpus)
                   if not cache_is_terminal(result_path(DEFAULT_RAW, corpus, model, item), BUDGET)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=config['workers']) as pool:
            futures = [pool.submit(recover, item) for item in pending]
            for future in concurrent.futures.as_completed(futures):
                if future.result() is not None:
                    export_trials(DEFAULT_RAW, corpus, model)
        export_trials(DEFAULT_RAW, corpus, model)
        if corpus == 'rq2':
            # Old successful replays remain cached. Newly returned rules replace
            # only prior unavailable outcomes under the same kernel and fixtures.
            subprocess.run([sys.executable, str(HERE / 'guest.py'), '--log', 'provider-recovery', '--',
                            sys.executable, str(HERE / 'replay.py'), '--model', model,
                            '--run-tag', 'guest68-scored-v3',
                            '--loader', str(DEFAULT_RAW / 'bounded-loader/process')], cwd=ROOT, check=True)
    print('Provider access recovery complete:', model, flush=True)


if __name__ == '__main__':
    main()
