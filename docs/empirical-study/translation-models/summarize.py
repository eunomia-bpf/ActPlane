#!/usr/bin/env python3
"""Derive tables from trial CSVs. Missing/invalid kernel runs never become TNs."""
import csv
import json
from pathlib import Path
import statistics

from prepare import HERE, DEFAULT_RAW, csv_write
from translate import inputs


def read(name):
    p = HERE / name
    return list(csv.DictReader(p.open())) if p.exists() else []


def detection(rows):
    valid = [r for r in rows if r['status'] in ('ok', 'translation_failed') and r['fired'] != '']
    tp = sum(r['violation'] == '1' and r['fired'] == '1' for r in valid)
    fp = sum(r['violation'] == '0' and r['fired'] == '1' for r in valid)
    pos = sum(r['violation'] == '1' for r in valid)
    neg = len(valid) - pos
    # Scores require all planned trace outcomes, including unavailable-policy
    # nondetections. Failed engine loads are a separate coverage failure.
    complete = len(valid) == 190
    result = dict(replay_rows=len(rows), replay_valid=len(valid), replay_errors=sum(r['status'] == 'error' for r in rows),
                  violation_traces=pos, compliant_traces=neg, true_positives=tp, false_positives=fp,
                  detection_rate=tp / pos if complete and pos else '',
                  false_trigger_rate=fp / neg if complete and neg else '',
                  f1=2*tp/(2*tp+fp+pos-tp) if complete and pos else '',
                  agreement_traces=sum(r.get('agreement') != '' for r in valid),
                  agreements=sum(r.get('agreement') == '1' for r in valid),
                  tool_error_traces=sum(int(r.get('tool_errors') or 0) > 0 for r in valid))
    for name, family in [('direct', 'visible_violation'), ('script', 'script_visible_violation'), ('hidden', 'opaque_fixture_violation')]:
        part = [r for r in valid if r['family'] == family]
        result[name + '_n'] = len(part)
        result[name + '_detected'] = sum(r['fired'] == '1' for r in part)
        result[name + '_rate'] = result[name + '_detected'] / len(part) if complete and part else ''
    return result


def main():
    access = read('model-access.csv')
    prices = {r['model']: r for r in read('prices.csv')}
    summary, failures = [], []
    corpus_rows = []
    for corpus in ('rq2', 'rq1'):
        records = inputs(DEFAULT_RAW, corpus)
        corpus_rows.append(dict(corpus=corpus, policies=len(records)))
    trace_rows = []
    for p in sorted((DEFAULT_RAW / 'artifact/docs/corpus-test').glob('*/*/statement.json')):
        for trace in json.loads(p.read_text())['trace_files']:
            gt = json.loads((p.parent / trace).read_text().splitlines()[0])
            trace_rows.append(dict(repo=p.parent.parent.name, statement_id=p.parent.name, trace=trace, violation=int(gt['violation'])))
    csv_write(HERE / 'corpus-counts.csv', corpus_rows)
    csv_write(HERE / 'trace-manifest.csv', trace_rows)
    all_access = [dict(model='reference', status='reference', identity_verified='1', error='')] + access
    for a in all_access:
        model = a['model']
        r = dict(model=model, access_status=a['status'], identity_verified=a['identity_verified'], access_error=a['error'])
        for corpus, expected in [('rq2', len(inputs(DEFAULT_RAW, 'rq2'))), ('rq1', len(inputs(DEFAULT_RAW, 'rq1')))]:
            trials = read(f'translations-{corpus}-{model.replace("/", "__")}.csv')
            n = len(trials)
            c1 = sum(int(t['compile_at_1']) for t in trials)
            c3 = sum(int(t['compile_at_3']) for t in trials)
            r.update({corpus + '_planned': expected, corpus + '_completed': n,
                      corpus + '_compiled_at_1': c1, corpus + '_compiled_at_3': c3,
                      corpus + '_compile_at_1_rate': c1/n if n else '', corpus + '_compile_at_3_rate': c3/n if n else '',
                      corpus + '_input_tokens_mean': statistics.mean(int(t['input_tokens']) for t in trials) if n else '',
                      corpus + '_output_tokens_mean': statistics.mean(int(t['output_tokens']) for t in trials) if n else '',
                      corpus + '_wall_s_mean': statistics.mean(float(t['wall_s']) for t in trials) if n else '',
                      corpus + '_retries': sum(max(0,int(t['attempts'])-1) for t in trials),
                      corpus + '_access_failures': sum(t['status']=='access_failure' for t in trials)})
            price = prices.get(model)
            usd = ''
            if n and price and price['input_usd_per_million'] != '':
                usd = sum(int(t['input_tokens']) * float(price['input_usd_per_million']) + int(t['output_tokens']) * float(price['output_usd_per_million']) for t in trials)/1e6
            r[corpus + '_uncached_list_usd'] = usd
            r[corpus + '_uncached_list_usd_mean'] = usd/n if usd != '' and n else ''
            for t in trials:
                if t['status'] != 'compiled':
                    failures.append(dict(corpus=corpus, model=model, uid=t['uid'], status=t['status'], failure_category=t['failure_category']))
        replay = read(f'replay-{model.replace("/", "__")}.csv')
        r.update(detection(replay))
        if model == 'reference':
            refs = read('reference-compilation.csv')
            r.update(rq2_completed=len(refs), rq2_compiled_at_1=sum(int(t['compiled']) for t in refs),
                     rq2_compiled_at_3=sum(int(t['compiled']) for t in refs))
        summary.append(r)
    csv_write(HERE / 'summary.csv', summary)
    if failures:
        csv_write(HERE / 'failures.csv', failures)
    for r in summary:
        if r['access_status'] in ('ok', 'reference'):
            print(r['model'], 'rq2',r['rq2_completed'],r['rq2_compiled_at_1'],r['rq2_compiled_at_3'],
                  'rq1',r['rq1_completed'],'replay',r['replay_valid'],r['replay_errors'])


if __name__ == '__main__':
    main()
