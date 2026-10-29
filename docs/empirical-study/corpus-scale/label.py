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


def protocol_name(a):
    if getattr(a, 'retry_policy', 'invalid') == 'batch':
        return 'legacy_batch'
    return 'invalid_' + getattr(a, 'schema_repair_mode', 'batch') + '_feedback'


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


def schema_error(pred, dims):
    for d in dims:
        if pred.get(d, '') not in ALLOWED[d]:
            return 'invalid_label:' + d
    if 'enforceability' in dims and bool(pred.get('enforceability')) != (pred.get('type') == 'directive'):
        return 'inconsistent_enforcement_applicability'
    if 'context_required' in dims:
        expected = pred.get('type') == 'directive' and pred.get('enforceability') in ('content', 'per_event', 'cross_event')
        if bool(pred.get('context_required')) != expected:
            return 'inconsistent_context_applicability'
    return ''


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
                              headers=headers, timeout=600 if local else getattr(a, 'remote_timeout', 240))
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


def classify(a, batch, guide, dims, other, schema_retry=0):
    entries = []
    for i, row in enumerate(batch):
        entry = dict(id=i, text=row['text'])
        if other is not None:
            annotations = [{k: row.get(k, '') for k in dims},
                {k: other[row['statement_id']].get(k, '') for k in dims}]
            if int(digest(row['statement_id'])[:2], 16) & 1:
                annotations.reverse()
            entry['annotations'] = annotations
        entries.append(entry)
    instruction = ('Independently assign labels to each statement.' if other is None else
        'Adjudicate the two anonymized annotations by rereading each statement and the coding guide. '
        'Neither annotation has priority. Return your final judgment, including dimensions that agree.')
    system = guide + '\n' + instruction + '\nReturn JSON only: {"labels": [[id, ' + ', '.join(dims) + '], ...]}. '
    system += 'Return every supplied id exactly once, using only the defined values. Empty inapplicable labels use "". No explanation.'
    if schema_retry:
        system += (f'\nSchema repair attempt {schema_retry}: the preceding response was invalid. '
                   'Use exactly one permitted value for each requested dimension. '
                   'Type and topic cannot be blank. Apply the same coding guide. Permitted values: '
                   + json.dumps({d: ALLOWED[d] for d in dims}) + '.')
    try:
        response = complete(a, system, dict(statements=entries),
                            budget=max(2048, len(batch) * 100) if a.model == 'qwen3.8-27b-nvfp4' else 12000)
        message = response['choices'][0]['message']['content']
        obj = parse_json(message)
        if isinstance(obj, list) and len(obj) == 1 and isinstance(obj[0], dict) and 'labels' in obj[0]:
            obj = obj[0]
        parsed = obj['labels'] if isinstance(obj, dict) and 'labels' in obj else [obj] if isinstance(obj, dict) and 'id' in obj else obj
        result, seen, invalid = {}, set(), []
        retry_policy = getattr(a, 'retry_policy', 'invalid')
        for values in parsed:
            if isinstance(values, dict):
                values = [values['id'], *[values[d] for d in dims]]
            i, *labels = values
            if isinstance(i, str) and i.isdigit():
                i = int(i)
            if not isinstance(i, int) or i < 0 or i >= len(batch) or i in seen or len(labels) != len(dims):
                raise ValueError('invalid_id_or_label_length')
            seen.add(i)
            pred = dict(zip(dims, labels))
            error = schema_error(pred, dims)
            if error:
                if retry_policy == 'batch':
                    raise ValueError(error)
                invalid.append((i, error))
                continue
            result[i] = dict(statement_id=batch[i]['statement_id'], **pred,
                model=a.model, returned_model=response.get('model', ''), status='ok',
                adjudicated=bool(other is not None), retry_protocol=protocol_name(a))
        missing = set(range(len(batch))) - seen
        if missing and retry_policy == 'batch':
            raise ValueError('missing_ids')
        invalid.extend((i, 'missing_id') for i in sorted(missing))
        if invalid:
            if not result:
                # No usable labels. Splitting changes the prompt context and
                # eventually records an explicit singleton failure.
                raise ValueError('no_valid_rows')
            log(a.raw / 'label-failures.jsonl', dict(at=now(), model=a.model,
                ids=[batch[i]['statement_id'] for i, _ in invalid],
                error='retry_invalid_rows', reasons=[error for _, error in invalid]))
            repaired = classify(a, [batch[i] for i, _ in invalid], guide, dims, other)
            for (i, _), row in zip(invalid, repaired):
                result[i] = row
        return [result[i] for i in range(len(batch))]
    except Exception as e:
        log(a.raw / 'label-failures.jsonl', dict(at=now(), model=a.model,
            ids=[r['statement_id'] for r in batch], error=str(e)[:160], schema_retry=schema_retry))
        if ((len(batch) == 1 or getattr(a, 'schema_repair_mode', 'batch') == 'batch')
                and getattr(a, 'retry_policy', 'invalid') == 'invalid'
                and str(e) != 'model_request_failed' and schema_retry < 2):
            return classify(a, batch, guide, dims, other, schema_retry + 1)
        # Split malformed/truncated batches once down to individual statements.
        if len(batch) > 1 and str(e) != 'model_request_failed':
            mid = len(batch) // 2
            return classify(a, batch[:mid], guide, dims, other) + classify(a, batch[mid:], guide, dims, other)
        return [dict(statement_id=row['statement_id'], model=a.model,
                     status='failed', error=str(e)[:160], retry_protocol=protocol_name(a)) for row in batch]


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
                retained.append(dict(left, model='agreement', adjudicated=False, retry_protocol='agreement'))
            elif left.get('status') == right.get('status') == 'ok':
                pending.append(dict(r, **{d: left.get(d, '') for d in dims}))
            else:
                retained.append(dict(statement_id=sid, model='incomplete_pair', status='failed'))
        rows = pending
    done = {r['statement_id']: r for r in read_csv(a.output)} if a.output.exists() else {}
    for r in done.values():
        if r.get('status') == 'ok' and not r.get('retry_protocol'):
            # Existing accepted annotations precede batched schema feedback.
            r['retry_protocol'] = ('agreement' if r.get('model') == 'agreement' else
                'legacy_batch' if getattr(a, 'retry_policy', 'invalid') == 'batch' else
                'invalid_singleton_feedback')
        error = schema_error(r, dims) if r.get('status') == 'ok' else ''
        if error:
            log(a.raw / 'label-schema-errors.jsonl', dict(at=now(), model=a.model,
                statement_id=r['statement_id'], error=error,
                previous_prediction={d: r.get(d, '') for d in dims}))
            r.update(status='failed', error=error)
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
                      ['statement_id', *DIMS, 'model', 'returned_model', 'status', 'adjudicated', 'error', 'retry_protocol'])
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
    p.add_argument('--retry-policy', choices=['invalid', 'batch'], default='invalid',
                   help='Retry invalid/missing IDs only, or reproduce legacy whole-batch retry.')
    p.add_argument('--schema-repair-mode', choices=['batch', 'singleton'], default='batch',
                   help='Apply the unchanged schema feedback before splitting an unusable batch, or reproduce v2 singleton repairs.')
    args = p.parse_args()
    if args.workers > (8 if args.model == 'qwen3.8-27b-nvfp4' else 4):
        p.error('worker count exceeds the shared-endpoint budget')
    run(args)
