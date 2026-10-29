#!/usr/bin/env python3
"""Finish the finite frozen rescue after its inference controller exits."""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import DEFAULT_RAW, HERE, log, now, read_csv
from complete import checkpoint


def main(args):
    if args.wait_pid:
        proc = Path(f'/proc/{args.wait_pid}/cmdline')
        while proc.exists() and b'rescue/run_frozen.py' in proc.read_bytes():
            time.sleep(15)
    selection = json.loads((HERE / 'rescue/frozen_selection.json').read_text())
    events = DEFAULT_RAW / 'rescue-controller.jsonl'
    assert events.exists() and any(json.loads(line).get('event') == 'inference_completed'
        and json.loads(line).get('revision') == selection['revision']
        for line in events.read_text().splitlines()), 'Frozen inference did not complete'
    expected = {r['statement_id'] for r in read_csv(DEFAULT_RAW / 'rescue-source-inputs.csv')}
    for name in ['qwen', 'glm', 'adjudicated']:
        rows = read_csv(HERE / f'rescue/source-{name}.csv')
        assert len(rows) == len(expected) and {r['statement_id'] for r in rows} == expected
        assert all(r['status'] == 'ok' for r in rows)
    steps = [('rescue/deploy.py', []), ('analyze.py', []), ('figures.py', []),
             ('rescue/correct_prevalence.py', []), ('rescue/plot_corrected.py', []),
             ('rescue/validate_rescue.py', []), ('validate.py', ['--require-complete']),
             ('validate_figures.py', ['--previews']), ('audit_runs.py', []), ('report.py', [])]
    for script, options in steps:
        print(now(), 'Running', script, flush=True)
        subprocess.run([sys.executable, str(HERE / script), *options], check=True)
        log(DEFAULT_RAW / 'rescue-finalization.jsonl', dict(at=now(), event='step_completed', script=script))
    if args.commit:
        checkpoint('Publish rescued enforcement and context metrics with bootstrap corrections')
    print('Numerical rescue finalized. Inspect exported PDF previews before final handoff.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wait-pid', type=int)
    parser.add_argument('--commit', action='store_true')
    main(parser.parse_args())
