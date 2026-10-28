#!/usr/bin/env python3
"""Preserve and audit the interrupted run with incompatible compiler CLI flags."""
import json
from pathlib import Path

from prepare import DEFAULT_RAW, HERE, csv_write
from translate import usage_of


def main():
    raw = DEFAULT_RAW
    source = raw / 'translations/rq2'
    dest = raw / 'invalid-protocol/compiler-cli-flags/rq2'
    if source.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            raise SystemExit('Archive already exists; refusing to overwrite it')
        source.rename(dest)
    rows = []
    for p in sorted(dest.glob('*/*/attempt-*/response.json')):
        response = json.loads(p.read_text())
        model = p.parents[2].name.replace('__', '/')
        rows.append(dict(model=model, uid=p.parents[1].name, attempt=p.parent.name,
                         response_model=response.get('response_model', ''), status=response['status'],
                         elapsed_s=response['elapsed_s'], **usage_of(response, model),
                         exclusion='invalid harness: compile --out conflicts with --json'))
    csv_write(HERE / 'invalid-protocol-calls.csv', rows)
    for p in HERE.glob('translations-rq2-*.csv'):
        p.unlink()
    print(f'Preserved invalid run at {dest}')


if __name__ == '__main__':
    main()
