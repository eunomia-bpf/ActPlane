#!/usr/bin/env python3
"""Serial recovery of overloaded-provider transports, with a campaign cutoff.

No returned translation is resampled. All original model requests finish before
this worker starts. The cutoff bounds new policy starts, leaving time for the
last bounded transport/compiler trajectory and final reporting.
"""
import datetime as dt
import fcntl
import json
from pathlib import Path
import subprocess
import sys
import time

from prepare import DEFAULT_RAW, HERE, ROOT, csv_write
from translate import inputs, translate_one, export_trials

MODEL = 'zai/glm-4.7-flash'
BUDGET = 6
DEADLINE = dt.datetime(2026, 10, 29, 8, 30, tzinfo=dt.timezone.utc)


def main():
    lock = (DEFAULT_RAW / 'provider-recovery.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    csv_write(HERE / 'recovery-protocol.csv', [dict(model=MODEL, corpus=corpus,
              maximum_transports=BUDGET, worker_limit=1, cutoff_utc=DEADLINE.isoformat(),
              trigger='original corpus model queue complete',
              selection='access failures only; returned answers cached') for corpus in ('rq2', 'rq1')])
    expected = {r['uid'].replace('::', '__').replace('/', '__') for r in inputs(DEFAULT_RAW, 'rq1')}
    directory = DEFAULT_RAW / 'translations/rq1' / MODEL.replace('/', '__')
    while {p.parent.name for p in directory.glob('*/result.json')} != expected:
        time.sleep(30)
    print('Original model queue complete. Starting serial provider recovery.', flush=True)
    for corpus in ('rq2', 'rq1'):
        for item in inputs(DEFAULT_RAW, corpus):
            if time.time() >= DEADLINE.timestamp():
                print('Recovery cutoff reached. Remaining baseline access failures retained.', flush=True)
                break
            translate_one(DEFAULT_RAW, corpus, MODEL, item, transport_limit=BUDGET)
            export_trials(DEFAULT_RAW, corpus, MODEL)
        if corpus == 'rq2':
            # Old successful replays remain cached. Newly returned rules replace
            # only prior unavailable outcomes under the same kernel and fixtures.
            subprocess.run([sys.executable, str(HERE / 'guest.py'), '--log', 'provider-recovery', '--',
                            sys.executable, str(HERE / 'replay.py'), '--model', MODEL,
                            '--redo-errors', '--run-tag', 'guest68-scored-v3',
                            '--loader', str(DEFAULT_RAW / 'bounded-loader/process')], cwd=ROOT, check=True)
    print('Serial provider recovery complete.', flush=True)


if __name__ == '__main__':
    main()
