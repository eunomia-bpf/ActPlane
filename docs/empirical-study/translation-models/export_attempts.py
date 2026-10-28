#!/usr/bin/env python3
"""Export completed response/transport records without committing response text."""
import json

from prepare import DEFAULT_RAW, HERE, csv_write
from translate import usage_of, usage_reported, finish_reason, export_trials, access_category, inputs
from models import MODELS


def main():
    uids = {corpus: {r['uid'].replace('::', '__').replace('/', '__'): r['uid']
                     for r in inputs(DEFAULT_RAW, corpus)} for corpus in ('rq1', 'rq2')}
    for corpus in ('rq2', 'rq1'):
        for model in MODELS:
            export_trials(DEFAULT_RAW, corpus, model)
    rows = []
    for path in sorted((DEFAULT_RAW / 'translations').glob('*/*/*/attempt-*/response.json')):
        final = json.loads(path.read_text())
        model = path.parents[2].name.replace('__', '/')
        corpus = path.parents[3].name
        directory = path.parents[1].name
        transports = final.get('transport_attempts', []) + [final]
        for number, response in enumerate(transports, 1):
            rows.append(dict(corpus=corpus, model=model, uid=uids[corpus][directory], trial_directory=directory,
                             attempt=path.parent.name, transport=number, status=response['status'],
                             access_category=access_category(response) if response['status'] != 'ok' else '',
                             backoff_before_s=response.get('backoff_before_s', 15 * (number - 1)),
                             observed_at_unix=response.get('observed_at_unix', ''),
                             retry_after_unix=response.get('retry_after_unix', ''),
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
