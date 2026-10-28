#!/usr/bin/env python3
"""Export completed response/transport records without committing response text."""
import json

from prepare import DEFAULT_RAW, HERE, csv_write
from translate import usage_of


def main():
    rows = []
    for path in sorted((DEFAULT_RAW / 'translations').glob('*/*/*/attempt-*/response.json')):
        final = json.loads(path.read_text())
        model = path.parents[2].name.replace('__', '/')
        transports = final.get('transport_attempts', []) + [final]
        for number, response in enumerate(transports, 1):
            rows.append(dict(corpus=path.parents[3].name, model=model, uid=path.parents[1].name,
                             attempt=path.parent.name, transport=number, status=response['status'],
                             response_model=response.get('response_model', ''),
                             identity_verified=int(response.get('identity_verified', False)),
                             http_status=response.get('http_status', ''), elapsed_s=response['elapsed_s'],
                             **usage_of(response, model)))
    if rows:
        csv_write(HERE / 'attempts.csv', rows)


if __name__ == '__main__':
    main()
