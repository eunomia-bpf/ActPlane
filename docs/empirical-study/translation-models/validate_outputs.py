#!/usr/bin/env python3
"""Check trial coverage, identity, retries, trace labels, and PDF embedding."""
import csv

from prepare import DEFAULT_RAW, HERE, csv_write
from translate import inputs


def read(name):
    return list(csv.DictReader((HERE / name).open()))


def main():
    models = [r['model'] for r in read('model-access.csv') if r['status'] == 'ok' and r['identity_verified'] == '1']
    checks = []
    def check(name, expected, actual):
        checks.append(dict(check=name, expected=expected, actual=actual, passed=int(expected == actual)))
    for model in models:
        safe = model.replace('/', '__')
        for corpus in ('rq2', 'rq1'):
            expected = {r['uid'] for r in inputs(DEFAULT_RAW, corpus)}
            rows = read(f'translations-{corpus}-{safe}.csv')
            check(f'{corpus}:{model}:rows', len(expected), len(rows))
            check(f'{corpus}:{model}:uids', expected == {r['uid'] for r in rows}, True)
            check(f'{corpus}:{model}:retry_limit', True, all(1 <= int(r['attempts']) <= 3 for r in rows))
            check(f'{corpus}:{model}:compiled_identity', True, all(r['identity_verified'] == '1' for r in rows if r['status'] == 'compiled'))
    for model in ['reference'] + models:
        rows = read('replay-' + model.replace('/', '__') + '.csv')
        check(f'replay:{model}:rows', 190, len(rows))
        check(f'replay:{model}:unique', 190, len({(r['repo'], r['statement_id'], r['trace']) for r in rows}))
        check(f'replay:{model}:violation_labels', 114, sum(int(r['violation']) for r in rows))
        check(f'replay:{model}:compliant_labels', 76, sum(r['violation'] == '0' for r in rows))
    check('PDF embeds TrueType', True, b'/FontFile2' in (HERE / 'comparison.pdf').read_bytes())
    csv_write(HERE / 'validation.csv', checks)
    if not all(r['passed'] for r in checks):
        raise SystemExit('Output validation failed; inspect validation.csv')
    print('Output validation passed')


if __name__ == '__main__':
    main()
