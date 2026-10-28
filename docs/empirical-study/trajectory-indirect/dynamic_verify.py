#!/usr/bin/env python3
"""Check replay provenance, call coverage and aggregate accounting against raw evidence."""
import argparse
from collections import Counter
import csv
import gzip
import hashlib
import json
from pathlib import Path

from analyze import HERE,write_csv
from dynamic_effects import parse_observer


def read(name):
    return list(csv.DictReader((HERE/name).open()))


def verify(raw,require_complete=False):
    plans=read('dynamic_plan.csv');replays=read('dynamic_replays.csv')
    calls=read('dynamic_calls.csv');summaries=read('dynamic_summary.csv')
    indexed={r['dynamic_id']:r for r in replays}
    expected_hash=hashlib.sha256((HERE/'observer.bt').read_bytes()).hexdigest()
    checks=[]
    def check(name,actual,expected):
        checks.append(dict(check=name,actual=actual,expected=expected,passed=int(actual==expected)))
    check('unique_planned_ids',len(set(p['dynamic_id'] for p in plans)),len(plans))
    check('completed_receipt_count',len(replays),len(plans) if require_complete else len(replays))
    check('no_unplanned_replays',len(set(indexed)-{p['dynamic_id'] for p in plans}),0)
    check('metadata_preparation_errors',sum(bool(p['preparation_error']) for p in plans),0)
    cfg=json.loads((HERE/'dynamic_config.json').read_text())
    for framework,model in cfg['groups']:
        check(framework+'_'+model+'_planned_count',sum((p['framework'],p['model'])==(framework,model) for p in plans),cfg['per_group'])
    check('unique_call_ids',len(set(c['call_id'] for c in calls)),len(calls))
    known_tags=set()
    metadata_hashes={}
    for plan in plans:
        ident=plan['dynamic_id']
        if ident not in indexed:continue
        metadata_file=(raw/'dynamic/swebench_verified.parquet' if plan['source']=='mini'
                       else raw/'dynamic/task_archives'/(plan['instance_id']+'.tar.gz'))
        if metadata_file not in metadata_hashes:
            metadata_hashes[metadata_file]=hashlib.sha256(metadata_file.read_bytes()).hexdigest()
        check(ident+'_task_metadata_hash',metadata_hashes[metadata_file],plan['metadata_file_sha256'])
        run=raw/'dynamic/runs'/ident
        check(ident+'_base_checkout_command',json.dumps(['git','checkout','--detach',plan['base_commit']]) in (run/'clone.log').read_text(),True)
        done=json.loads((run/'done.json').read_text())
        metadata=json.loads((run/'observer_metadata.json').read_text())
        check(ident+'_observer_hash',metadata['observer_sha256'],expected_hash)
        check(ident+'_frozen_observer_hash',hashlib.sha256((run/'observer.bt').read_bytes()).hexdigest(),expected_hash)
        check(ident+'_phase',done.get('run_phase'),json.loads((HERE/'dynamic_config.json').read_text())['run_phase'])
        check(ident+'_not_diagnostic',bool(done.get('diagnostic_only')),False)
        receipts=[json.loads(line) for line in (run/'calls.jsonl').read_text().splitlines()]
        selected=[c for c in calls if c['dynamic_id']==ident]
        check(ident+'_recorded_calls',len(selected),int(plan['recorded_calls']))
        check(ident+'_executed_calls',sum(int(c['replay_executed']) for c in selected),done['executed_calls'])
        check(ident+'_receipt_calls',len(receipts),done['executed_calls'])
        counts,byte_counts,errors=parse_observer(run/'observer.jsonl')
        check(ident+'_observer_errors',len(errors),0)
        check(ident+'_observer_exit',done['observer_exit'],0)
        tags={r['tag'] for r in receipts}
        check(ident+'_unique_tags',len(tags),len(receipts))
        check(ident+'_new_tags',len(tags&known_tags),0)
        known_tags|=tags
        check(ident+'_unknown_lineage_tags',len({tag for tag,kind,path in counts}-tags),0)
        check(ident+'_one_dispatcher_per_launched_call',sum(n for (tag,kind,path),n in counts.items() if kind==9),
              sum(not r.get('worker_error') for r in receipts))
        check(ident+'_bytes_have_write_counts',sum(key not in counts for key in byte_counts),0)
        check(ident+'_nonnegative_events',sum(n<0 for n in counts.values()),0)
    overall=next(r for r in summaries if (r['framework'],r['model'],r['classification'])==('ALL','ALL','ALL'))
    check('overall_call_count',int(overall['recorded_calls']),len(calls))
    effect_totals=Counter()
    with gzip.open(raw/'dynamic/effects.jsonl.gz','rt') as f:
        for line in f:
            effect=json.loads(line)
            kind=effect['effect'];effect_totals[kind+'_events']+=effect['events']
            effect_totals[kind+'_objects']+=1
            if effect['named']==0:
                effect_totals['unnamed_'+kind+'_events']+=effect['events']
                effect_totals['unnamed_'+kind+'_objects']+=1
    for kind in ('write','exec','truncate'):
        for prefix in ('','unnamed_'):
            for suffix in ('events','objects'):
                key=prefix+kind+'_'+suffix
                check('raw_'+key,effect_totals[key],int(overall[key]))
                check('calls_'+key,sum(int(c[key]) for c in calls),int(overall[key]))
    filtered=next(r for r in read('dynamic_sensitivity.csv') if (r['framework'],r['model'],r['classification'])==('ALL','ALL','ALL'))
    for unit in ('events','objects'):
        removed=sum(int(c['profile_helper_exec_'+unit]) for c in calls)
        unnamed_removed=sum(int(c['unnamed_profile_helper_exec_'+unit]) for c in calls)
        check('filtered_exec_'+unit,int(filtered['exec_'+unit]),int(overall['exec_'+unit])-removed)
        check('filtered_unnamed_exec_'+unit,int(filtered['unnamed_exec_'+unit]),int(overall['unnamed_exec_'+unit])-unnamed_removed)
    write_csv(HERE/'dynamic_verification.csv',checks)
    failed=[c['check'] for c in checks if not c['passed']]
    if failed:raise SystemExit('Verification failed: '+', '.join(failed))
    print(f'Passed {len(checks)} evidence/accounting checks for {len(replays)} replay receipts')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True)
    p.add_argument('--require-complete',action='store_true')
    args=p.parse_args();verify(args.raw,args.require_complete)
