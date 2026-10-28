#!/usr/bin/env python3
"""Run independent model replays in one guest with bounded concurrency."""
import concurrent.futures
import csv
from pathlib import Path
import subprocess
import sys

from prepare import HERE, DEFAULT_RAW


def main():
    models = [r['model'] for r in csv.DictReader((HERE / 'model-access.csv').open())
              if r['status'] == 'ok' and r['identity_verified'] == '1']
    def run(model):
        out = DEFAULT_RAW / 'model-replay-logs'
        out.mkdir(exist_ok=True)
        with (out / (model.replace('/', '__') + '.log')).open('w') as f:
            p = subprocess.run([sys.executable, str(HERE / 'replay.py'), '--model', model,
                                '--run-tag', 'guest68-scored-v2', '--loader', str(DEFAULT_RAW / 'bounded-loader/process')],
                               stdout=f, stderr=subprocess.STDOUT)
        if p.returncode:
            raise RuntimeError(f'Model replay failed: {model}; inspect {out}')
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(run, models))


if __name__ == '__main__':
    main()
