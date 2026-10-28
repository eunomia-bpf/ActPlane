#!/usr/bin/env python3
"""Check trial coverage, identity, retries, trace labels, and PDF embedding."""
import csv
from collections import Counter
import json

from prepare import DEFAULT_RAW, HERE, csv_write
from translate import inputs


def read(name):
    return list(csv.DictReader((HERE / name).open()))


def main():
    models = [r['model'] for r in read('model-access.csv') if r['status'] == 'ok' and r['identity_verified'] == '1']
    checks = []
    prompts = {(r['corpus'], r['uid']): r['prompt_sha256'] for r in read('prompt-manifest.csv')}
    def check(name, expected, actual):
        checks.append(dict(check=name, expected=expected, actual=actual, passed=int(expected == actual)))
    for model in models:
        safe = model.replace('/', '__')
        for corpus in ('rq2', 'rq1'):
            expected = {r['uid'] for r in inputs(DEFAULT_RAW, corpus)}
            rows = read(f'translations-{corpus}-{safe}.csv')
            check(f'{corpus}:{model}:rows', len(expected), len(rows))
            check(f'{corpus}:{model}:uids', expected == {r['uid'] for r in rows}, True)
            check(f'{corpus}:{model}:shared_prompt', True, all(r['prompt_sha256'] == prompts[corpus, r['uid']] for r in rows))
            check(f'{corpus}:{model}:retry_limit', True, all(1 <= int(r['attempts']) <= 3 for r in rows))
            check(f'{corpus}:{model}:compiled_identity', True, all(r['identity_verified'] == '1' for r in rows if r['status'] == 'compiled'))
    attempts = read('attempts.csv')
    check('transport records join canonical policy IDs', True,
          all((r['corpus'], r['uid']) in prompts for r in attempts))
    valid_answers = Counter((r['corpus'], r['model'], r['uid'], r['attempt']) for r in attempts if r['status'] == 'ok')
    check('no returned answer resampling within compiler attempt', True, all(n == 1 for n in valid_answers.values()))
    for corpus, budget in [('rq2', 3), ('rq1', 4)]:
        check(f'{corpus}:bounded transport retries', True, all(int(r['transport']) <= budget for r in attempts if r['corpus'] == corpus))
    loader_hash = json.loads((DEFAULT_RAW / 'bounded-loader/metadata.json').read_text())['loader_sha256']
    for model in ['reference'] + models:
        rows = read('replay-' + model.replace('/', '__') + '.csv')
        check(f'replay:{model}:guest_local_fixtures', True, all(r.get('fixture_fs') == 'guest-tmpfs' for r in rows))
        check(f'replay:{model}:kernel', True, all(r['kernel'] == '6.8.0-138-generic' for r in rows))
        check(f'replay:{model}:same_loader', True, all(r['loader_sha256'] == loader_hash for r in rows if r['status'] == 'ok'))
        check(f'replay:{model}:rows', 190, len(rows))
        check(f'replay:{model}:unique', 190, len({(r['repo'], r['statement_id'], r['trace']) for r in rows}))
        check(f'replay:{model}:violation_labels', 114, sum(int(r['violation']) for r in rows))
        check(f'replay:{model}:compliant_labels', 76, sum(r['violation'] == '0' for r in rows))
    controls = read('controls-guest68-scored-v3.csv')
    parallel = read('controls-guest68-parallel-v3.csv')
    check('all parallel kernel controls pass', True, all(r['control_passed'] == '1' for r in parallel))
    check('all kernel controls pass', True, all(r['control_passed'] == '1' for r in controls))
    summary = read('summary.csv')
    expected_points = {r['model'] for r in summary if r['detection_rate'] != '' and r['false_trigger_rate'] != ''}
    plotted = read('figure-data.csv')
    check('figure matches complete score rows', expected_points == {r['model'] for r in plotted}, True)
    check('PDF embeds TrueType', True, b'/FontFile2' in (HERE / 'comparison.pdf').read_bytes())
    csv_write(HERE / 'validation.csv', checks)
    if not all(r['passed'] for r in checks):
        raise SystemExit('Output validation failed; inspect validation.csv')
    print('Output validation passed')


if __name__ == '__main__':
    main()
