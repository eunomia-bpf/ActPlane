#!/usr/bin/env python3
"""Recover session-limit transports after the original model queue finishes.

This is a deterministic study worker, not an agent or supervisor session.
Returned model answers remain cached. The translator honors provider reset times.
"""
import argparse
import fcntl
import time
from translate import run_model, inputs
from prepare import DEFAULT_RAW
from models import MODELS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', choices=[m for m, (_, k) in MODELS.items() if k in ('claude', 'codex')], required=True)
    args = parser.parse_args()
    safe = args.model.replace('/', '__')
    lock = (DEFAULT_RAW / ('recovery-' + safe + '.lock')).open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    directory = DEFAULT_RAW / 'translations/rq1' / safe
    expected = len(inputs(DEFAULT_RAW, 'rq1'))
    while len(list(directory.glob('*/result.json'))) != expected:
        time.sleep(30)
    print('Original model queue complete. Recovering bounded transport failures:', args.model, flush=True)
    run_model(DEFAULT_RAW, 'rq1', args.model)
    print('Model transport recovery complete:', args.model, flush=True)


if __name__ == '__main__':
    main()
