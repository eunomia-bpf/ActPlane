#!/usr/bin/env python3
"""Cached two-model classification and disagreement adjudication.

Each command invokes exactly one named model. Run the primary models separately,
then adjudicate disagreements with --other. Calibration never includes gold
labels in any prompt. Raw completions and failures remain outside git.
"""
import argparse
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

from common import DEFAULT_RAW, HERE, digest, log, now, read_csv, write_csv

DIMS = ['type', 'topic', 'enforceability', 'context_required']
TOPICS = ['System Overview', 'AI Integration', 'Documentation', 'Architecture',
          'Implementation Details', 'Build and Run', 'Testing', 'Configuration & Environment',
          'DevOps', 'Development Process', 'Maintenance', 'Security']
ALLOWED = {'type': ['description', 'directive'], 'topic': TOPICS,
           'enforceability': ['', 'semantic_only', 'content', 'per_event', 'cross_event'],
           'context_required': ['', 'none', 'project', 'task']}


def guide_for_dimensions(full, dimensions):
    """Keep the original full calibration prompt, focus reduced deployments.

    Reduced guides are independently calibrated before use. Removing unused
    axes avoids paying for reasoning about labels that will be withheld.
    """
    if set(dimensions) == set(DIMS):
        return full
    examples_at = full.index('\nExamples (')
    sections = {}
    first = full.index('\ntype:')
    for i, dim in enumerate(DIMS):
        start = full.index('\n' + dim + ':')
        end = full.index('\n' + DIMS[i + 1] + ':') if i + 1 < len(DIMS) else examples_at
        sections[dim] = full[start:end]
    guide = full[:first].replace('The four dimensions below', 'The requested dimensions below')
    guide += ''.join(sections[d] for d in dimensions)
    guide += '\nExamples (' + ', '.join(dimensions) + '):\n'
    for line in full[examples_at:].splitlines():
        if ' => ' not in line:
            continue
        text, values = line.split(' => ', 1)
        labels = values.split(', ')
        if len(labels) == len(DIMS):
            guide += text + ' => ' + ', '.join(labels[DIMS.index(d)] for d in dimensions) + '\n'
    guide += '\nApply only the requested dimensions. Keep deliberation brief. Do not repeat the statements or the coding guide.\n'
    return guide


def parse_json(content):
    text = re.sub(r'^```(?:json)?\s*|\s*```$', '', content.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find('{'), text.rfind('}')
        return json.loads(text[start:end + 1])


def complete(a, system, payload, budget=4096):
    local = a.model == 'qwen3.8-27b-nvfp4'
    base = 'http://qwen38-vllm.models.svc.cluster.local:8000/v1' if local else os.environ['LITELLM_BASE_URL']
    request = dict(model=a.model, temperature=0, max_tokens=budget,
        messages=[dict(role='system', content=system), dict(role='user', content=json.dumps(payload, ensure_ascii=False))])
    if local:
        request['chat_template_kwargs'] = {'enable_thinking': False}
    else:
        # GLM-5.3 always reasons. The gateway rejects thinking/type:disabled.
        request['reasoning_effort'] = 'low'
    key = digest(json.dumps(request, sort_keys=True, ensure_ascii=False))
    path = a.raw / 'model-cache' / (key + '.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return json.loads(path.read_text())['response']
    headers = {'Content-Type': 'application/json'}
    if not local:
        headers['Authorization'] = 'Bearer ' + os.environ['LITELLM_API_KEY']
    for attempt in range(1, a.retries + 1):
        started = time.monotonic()
        try:
            r = requests.post(base.rstrip('/') + '/chat/completions', json=request,
                              headers=headers, timeout=600 if local else 240)
            elapsed = round(time.monotonic() - started, 3)
            event = dict(at=now(), model=a.model, key=key, attempt=attempt,
                         elapsed_s=elapsed, http_status=r.status_code)
            if r.status_code != 200:
                # Error bodies can reveal provider configuration, so remain raw.
                (path.parent / f'{key}.attempt{attempt}.error.txt').write_text(r.text)
                log(a.raw / 'model-requests.jsonl', event)
                if r.status_code == 429:
                    delay = max(60, float(r.headers.get('Retry-After', 60)))
                    log(a.raw / 'model-requests.jsonl', dict(at=now(), model=a.model,
                        key=key, attempt=attempt, backoff_seconds=delay))
                    while delay > 0:
                        time.sleep(min(30, delay))
                        delay -= min(30, delay)
                    continue
                r.raise_for_status()
            response = r.json()
            event.update(returned_model=response.get('model'), usage=response.get('usage'),
                         finish_reason=response.get('choices', [{}])[0].get('finish_reason'))
            log(a.raw / 'model-requests.jsonl', event)
            path.write_text(json.dumps(dict(request=request, response=response)))
            return response
        except requests.RequestException as e:
            log(a.raw / 'model-requests.jsonl', dict(at=now(), model=a.model, key=key,
                attempt=attempt, error=type(e).__name__))
            time.sleep(min(45, 3 ** attempt))
    raise RuntimeError('model_request_failed')


def classify(a, batch, guide, dims, other):
    entries = []
    for i, row in enumerate(batch):
        entry = dict(id=i, text=row['text'])
        if other is not None:
            entry['annotations'] = [{k: row.get(k, '') for k in dims},
                {k: other[row['statement_id']].get(k, '') for k in dims}]
        entries.append(entry)
    instruction = ('Independently assign labels to each statement.' if other is None else
        'Adjudicate the two anonymized annotations by rereading each statement and the coding guide. '
        'Neither annotation has priority. Return your final judgment, including dimensions that agree.')
    system = guide + '\n' + instruction + '\nReturn JSON only: {"labels": [[id, ' + ', '.join(dims) + '], ...]}. '
    system += 'Return every supplied id exactly once, using only the defined values. Empty inapplicable labels use "". No explanation.'
    try:
        response = complete(a, system, dict(statements=entries),
                            budget=max(2048, len(batch) * 100) if a.model == 'qwen3.8-27b-nvfp4' else 12000)
        message = response['choices'][0]['message']['content']
        parsed = parse_json(message)['labels']
        result = {}
        for values in parsed:
            if isinstance(values, dict):
                values = [values['id'], *[values[d] for d in dims]]
            i, *labels = values
            if isinstance(i, str) and i.isdigit():
                i = int(i)
            if not isinstance(i, int) or i < 0 or i >= len(batch) or i in result or len(labels) != len(dims):
                raise ValueError('invalid_id_or_label_length')
            pred = dict(zip(dims, labels))
            for d, value in pred.items():
                if value not in ALLOWED[d]:
                    raise ValueError('invalid_label:' + d + ':' + str(value))
            result[i] = dict(statement_id=batch[i]['statement_id'], **pred,
                model=a.model, returned_model=response.get('model', ''), status='ok',
                adjudicated=bool(other is not None))
        if len(result) != len(batch):
            raise ValueError('missing_ids')
        return [result[i] for i in range(len(batch))]
    except Exception as e:
        log(a.raw / 'label-failures.jsonl', dict(at=now(), model=a.model,
            ids=[r['statement_id'] for r in batch], error=str(e)[:160]))
        # Split malformed/truncated batches once down to individual statements.
        if len(batch) > 1 and str(e) != 'model_request_failed':
            mid = len(batch) // 2
            return classify(a, batch[:mid], guide, dims, other) + classify(a, batch[mid:], guide, dims, other)
        return [dict(statement_id=batch[0]['statement_id'], model=a.model, status='failed', error=str(e)[:160])]


def run(a):
    rows = read_csv(a.input)
    if a.limit:
        rows = rows[:a.limit]
    dims = a.dimensions.split(',')
    guide = guide_for_dimensions((HERE / 'taxonomy.txt').read_text(), dims)
    other = None
    retained = []
    if a.other:
        primary = {r['statement_id']: r for r in read_csv(a.primary)}
        other = {r['statement_id']: r for r in read_csv(a.other)}
        pending = []
        for r in rows:
            sid = r['statement_id']
            left, right = primary.get(sid, {}), other.get(sid, {})
            if left.get('status') == right.get('status') == 'ok' and all(left.get(d, '') == right.get(d, '') for d in dims):
                retained.append(dict(left, model='agreement', adjudicated=False))
            elif left.get('status') == right.get('status') == 'ok':
                pending.append(dict(r, **{d: left.get(d, '') for d in dims}))
            else:
                retained.append(dict(statement_id=sid, model='incomplete_pair', status='failed'))
        rows = pending
    done = {r['statement_id']: r for r in read_csv(a.output)} if a.output.exists() else {}
    # A failed row remains visible and is retried on explicit resumption.
    rows = [r for r in rows if done.get(r['statement_id'], {}).get('status') != 'ok']
    done.update({r['statement_id']: r for r in retained})
    batches, batch = [], []
    chars = 0
    for r in rows:
        if batch and (len(batch) >= a.batch_size or chars + len(r['text']) > 18000):
            batches.append(batch)
            batch, chars = [], 0
        batch.append(r)
        chars += len(r['text'])
    if batch:
        batches.append(batch)
    print('model', a.model, 'pending', len(rows), 'batches', len(batches), flush=True)
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures = [pool.submit(classify, a, b, guide, dims, other) for b in batches]
        for i, future in enumerate(as_completed(futures), 1):
            for row in future.result():
                done[row['statement_id']] = row
            write_csv(a.output, sorted(done.values(), key=lambda r: r['statement_id']),
                      ['statement_id', *DIMS, 'model', 'returned_model', 'status', 'adjudicated', 'error'])
            print('completed', i, '/', len(batches), 'rows', len(done), flush=True)
    if not batches:
        write_csv(a.output, sorted(done.values(), key=lambda r: r['statement_id']))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, default=HERE / 'paper_labels.csv')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--model', required=True)
    p.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--batch-size', type=int, default=16)
    p.add_argument('--retries', type=int, default=3)
    p.add_argument('--limit', type=int)
    p.add_argument('--thinking', action='store_true')
    p.add_argument('--dimensions', default=','.join(DIMS))
    p.add_argument('--primary', type=Path)
    p.add_argument('--other', type=Path)
    args = p.parse_args()
    if args.workers > (8 if args.model == 'qwen3.8-27b-nvfp4' else 4):
        p.error('worker count exceeds the shared-endpoint budget')
    run(args)
