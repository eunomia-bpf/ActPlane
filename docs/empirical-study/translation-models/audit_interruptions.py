#!/usr/bin/env python3
"""Preserve interrupted requests without inventing responses, usage, or charges."""
import argparse
import json
import time
from prepare import DEFAULT_RAW, HERE, csv_write
from translate import inputs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--label')
    ap.add_argument('--export-only', action='store_true')
    args = ap.parse_args()
    audit = DEFAULT_RAW / 'interrupted-requests'
    audit.mkdir(exist_ok=True)
    rows = []
    if not args.export_only:
        if not args.label:
            ap.error('--label is required when recording interruptions')
        destination = audit / (args.label + '.json')
        if destination.exists():
            raise SystemExit('Audit labels are immutable. Use --export-only to regenerate the CSV.')
        for attempt in sorted((DEFAULT_RAW / 'translations').glob('*/*/*/attempt-*')):
            if (attempt / 'response.json').exists() or (attempt.parent / 'result.json').exists():
                continue
            rows.append(dict(label=args.label, corpus=attempt.parents[2].name,
                             model=attempt.parents[1].name.replace('__', '/'), uid=attempt.parent.name,
                             attempt=attempt.name, status='interrupted_response_unknown',
                             usage='unknown', charge='unknown',
                             recorded_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))
        destination.write_text(json.dumps(rows, indent=2) + '\n')
    all_rows = [r for p in sorted(audit.glob('*.json')) for r in json.loads(p.read_text())]
    uids = {corpus: {r['uid'].replace('::', '__').replace('/', '__'): r['uid']
                     for r in inputs(DEFAULT_RAW, corpus)} for corpus in ('rq1', 'rq2')}
    for row in all_rows:
        row['trial_directory'] = row['uid']
        row['uid'] = uids[row['corpus']][row['trial_directory']]
    if all_rows:
        csv_write(HERE / 'interrupted-requests.csv', all_rows)
    print('Interrupted requests preserved', len(rows), flush=True)


if __name__ == '__main__':
    main()
