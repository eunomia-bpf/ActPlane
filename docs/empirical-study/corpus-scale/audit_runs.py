#!/usr/bin/env python3
"""Summarize retained retries/failures without publishing raw provider errors."""
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from common import DEFAULT_RAW, HERE, read_csv, write_csv


def main(a):
    rows = []
    identities = Counter()
    for filename in ['github-requests.jsonl', 'model-requests.jsonl', 'label-failures.jsonl',
                     'extraction-chunks.jsonl', 'downloads.jsonl', 'optional-processes.jsonl']:
        path = a.raw / filename
        counts = Counter()
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                counts[('', 'incomplete_log_record', '')] += 1
                continue
            model = r.get('model', '')
            if filename == 'model-requests.jsonl' and r.get('returned_model'):
                identities[(model, r['returned_model'])] += 1
            status = str(r.get('http_status', r.get('status', r.get('error', 'recorded'))))
            if filename == 'label-failures.jsonl':
                status = 'invalid_response_or_failed_request'
            attempt = str(r.get('attempt', ''))
            counts[(model, status, attempt)] += 1
        for (model, status, attempt), count in sorted(counts.items()):
            rows.append(dict(source=filename, model=model, status=status, attempt=attempt, count=count))
    write_csv(HERE / 'run_audit.csv', rows)
    write_csv(HERE / 'model_identity.csv', [dict(requested_model=k[0], returned_model=k[1],
        successful_requests=v) for k, v in sorted(identities.items())])
    scope_path = HERE / 'file_scopes.csv'
    if scope_path.exists():
        scopes = {(r['repo'], r['content_sha256']): r for r in read_csv(scope_path)}
        unique = {}
        for f in read_csv(HERE / 'corpus_manifest.csv'):
            key = (f['repo'], f['content_sha256'])
            if f['status'] == 'included' and key not in unique:
                s = scopes.get(key, {})
                unique[key] = dict(repo=f['repo'], content_sha256=f['content_sha256'],
                    file_path=f['file_path'], scope=s.get('scope', 'unclassified'),
                    status=s.get('status', 'not_completed'))
        write_csv(HERE / 'scope_coverage.csv', unique.values())
    # Reviewable samples of reference/model mismatches, sampled without cherry-picking.
    gold = read_csv(HERE / 'paper_labels.csv')
    disagreements = []
    for model in ['qwen', 'glm', 'adjudicated']:
        path = HERE / f'calibration_{model}.csv'
        if not path.exists():
            continue
        pred = {r['statement_id']: r for r in read_csv(path)}
        taken = Counter()
        for g in sorted(gold, key=lambda r: r['statement_id']):
            p = pred.get(g['statement_id'], {})
            if p.get('status') != 'ok':
                continue
            for dim in ['type', 'topic', 'enforceability', 'context_required']:
                if g.get(dim, '') == p.get(dim, ''):
                    continue
                key = (dim, g.get(dim, ''), p.get(dim, ''))
                if taken[key] < 3:
                    disagreements.append(dict(model=model, dimension=dim, statement_id=g['statement_id'],
                        gold=g.get(dim, ''), prediction=p.get(dim, ''), text=g['text']))
                    taken[key] += 1
    write_csv(HERE / 'calibration_disagreement_examples.csv', disagreements)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    main(p.parse_args())
