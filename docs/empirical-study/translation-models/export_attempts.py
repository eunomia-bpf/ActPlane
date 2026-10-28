#!/usr/bin/env python3
"""Export completed response/transport records without committing response text."""
import json

from prepare import DEFAULT_RAW, HERE, csv_write
from translate import usage_of, usage_reported, finish_reason, export_trials, access_category
from models import MODELS


def main():
    for corpus in ('rq2', 'rq1'):
        for model in MODELS:
            export_trials(DEFAULT_RAW, corpus, model)
    rows = []
    for path in sorted((DEFAULT_RAW / 'translations').glob('*/*/*/attempt-*/response.json')):
        final = json.loads(path.read_text())
        model = path.parents[2].name.replace('__', '/')
        transports = final.get('transport_attempts', []) + [final]
        for number, response in enumerate(transports, 1):
            rows.append(dict(corpus=path.parents[3].name, model=model, uid=path.parents[1].name,
                             attempt=path.parent.name, transport=number, status=response['status'],
                             access_category=access_category(response) if response['status'] != 'ok' else '',
                             backoff_before_s=response.get('backoff_before_s', 15 * (number - 1)),
                             response_model=response.get('response_model', ''),
                             finish_reason=finish_reason(response, model),
                             identity_verified=int(response.get('identity_verified', False)),
                             http_status=response.get('http_status', ''), elapsed_s=response['elapsed_s'],
                             usage_reported=int(usage_reported(response, model)),
                             **usage_of(response, model)))
    if rows:
        csv_write(HERE / 'attempts.csv', rows)


if __name__ == '__main__':
    main()
