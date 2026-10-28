#!/usr/bin/env python3
"""Cross-check committed CSVs against the cached calls and pinned source bytes."""
import argparse
from collections import Counter,defaultdict
import csv
import gzip
import hashlib
import json
from pathlib import Path

from analyze import HERE,CLASSES,write_csv


def read(name):
    return list(csv.DictReader((HERE/name).open()))


def main(raw):
    summary=read('summary.csv')
    trajectories=read('trajectories.csv')
    by_trajectory=defaultdict(list)
    calls={}
    with gzip.open(raw/'classified_calls.jsonl.gz','rt') as f:
        for line in f:
            c=json.loads(line)
            assert c['call_id'] not in calls,'duplicate call ID'
            calls[c['call_id']]=c
            by_trajectory[c['trajectory_id']].append(c)
    ids=[r['trajectory_id'] for r in trajectories]
    assert len(ids)==len(set(ids)), 'duplicate trajectory ID'
    assert set(by_trajectory)<=set(ids),'calls with no trajectory row'
    groups=defaultdict(list)
    for row in trajectories:
        actual=by_trajectory[row['trajectory_id']]
        assert int(row['calls'])==len(actual), 'trajectory call count mismatch'
        for category in CLASSES:
            assert int(row[category])==sum(c['classification']==category for c in actual),'trajectory class count mismatch'
        for metric in ['author_then_execute','earlier_call_author_then_execute','same_call_author_then_execute','confirmed_author_then_execute','create_then_execute','no_prior_write_script','project_runner']:
            assert int(row['any_'+metric])==int(any(c[metric] for c in actual)),'trajectory flag mismatch'
        assert int(row['any_indirect'])==int(any(c['classification']=='indirect' for c in actual))
        groups[(row['framework'],row['model'])].append(row)
    for row in summary:
        group=groups[(row['framework'],row['model'])]
        assert int(row['trajectories'])==len(group)
        assert int(row['calls'])==sum(int(t['calls']) for t in group)
        assert sum(int(row[c]) for c in CLASSES)==int(row['calls'])
        for category in CLASSES:
            assert int(row[category])==sum(int(t[category]) for t in group)
            assert abs(float(row[category+'_pct'])-100*int(row[category])/int(row['calls']))<.000051
        for metric in ['indirect','author_then_execute','earlier_call_author_then_execute','same_call_author_then_execute','confirmed_author_then_execute','create_then_execute','no_prior_write_script','project_runner']:
            assert int(row['any_'+metric])==sum(int(t['any_'+metric]) for t in group)
    for row in read('normalization_audit.csv'):
        source_field={'nebius':'nebius_action_slots','mini':'mini_harness_actions','native':'native_tool_events','openhands':'openhands_function_markers'}[row['source']]
        assert row[source_field]==row['extracted_calls'],'adapter coverage mismatch'
    for row in read('dataset_manifest.csv'):
        p=raw/row['source']/row['file']
        assert p.stat().st_size==int(row['bytes']), 'source file size changed'
        assert hashlib.sha256(p.read_bytes()).hexdigest()==row['sha256'],'pinned data bytes changed'
    for row in read('sample_calls.csv'):
        actual=calls[row['call_id']]
        assert row['classification']==actual['classification']
        assert row['argument_sha256']==actual['argument_sha256']
    for row in read('validation_labels.csv'):
        actual=calls[row['call_id']]
        assert row['heuristic']==actual['classification'],'validation classifier drift'
        assert row['label_a'] in CLASSES and row['label_b'] in CLASSES
    quality=[]
    task_balanced=[]
    for (framework,model),rows in sorted(groups.items()):
        source_ids=[r['instance_id'] for r in rows if r['instance_id']!='unavailable']
        sequences=[]
        success_indirect=Counter()
        successful_author=Counter()
        status=Counter()
        for row in rows:
            cs=by_trajectory[row['trajectory_id']]
            sequences.append(hashlib.sha256(json.dumps([(c['tool'],c['argument_sha256']) for c in cs]).encode()).hexdigest())
            for call in cs:
                if call['classification']=='indirect':
                    status[call['status']]+=1
                    if call['status']=='success':
                        success_indirect[row['trajectory_id']]+=1
                if call['author_then_execute'] and call['status']=='success':
                    successful_author[row['trajectory_id']]+=1
        quality.append(dict(framework=framework,model=model,trajectories=len(rows),
                            distinct_known_instance_ids=len(set(source_ids)),
                            repeated_known_instance_rows=len(source_ids)-len(set(source_ids)),
                            unavailable_instance_ids=len(rows)-len(source_ids),
                            duplicate_action_sequence_rows=len(sequences)-len(set(sequences)),
                            successful_indirect_calls=status['success'],failed_indirect_calls=status['failed'],unknown_status_indirect_calls=status['unknown'],
                            any_successful_indirect_traj=len(success_indirect),any_successful_indirect_pct=100*len(success_indirect)/len(rows),
                            successful_author_calls=sum(successful_author.values()),any_successful_author_traj=len(successful_author),
                            any_successful_author_pct=100*len(successful_author)/len(rows)))
        tasks=defaultdict(list)
        for row in rows:
            if row['instance_id']!='unavailable':
                tasks[row['instance_id']].append(row)
        task_call_rates=[]
        for attempts in tasks.values():
            n_calls=sum(int(r['calls']) for r in attempts)
            if n_calls:
                task_call_rates.append(100*sum(int(r['indirect']) for r in attempts)/n_calls)
        entry=dict(framework=framework,model=model,known_tasks=len(tasks),trajectory_rows=len(rows),zero_call_tasks=len(tasks)-len(task_call_rates),
                   task_mean_indirect_call_pct=sum(task_call_rates)/len(task_call_rates) if task_call_rates else '')
        for metric in ['any_indirect','any_author_then_execute','any_create_then_execute','any_project_runner','any_no_prior_write_script']:
            entry['task_mean_'+metric+'_pct']=sum(100*sum(int(r[metric]) for r in attempts)/len(attempts) for attempts in tasks.values())/len(tasks) if tasks else ''
        task_balanced.append(entry)
    write_csv(HERE/'trajectory_quality.csv',quality)
    write_csv(HERE/'task_balanced_summary.csv',task_balanced)
    checks=[dict(check='unique_call_ids_and_trajectory_ids',status='passed',items=len(calls)),
            dict(check='trajectory_counts_and_history_flags',status='passed',items=len(trajectories)),
            dict(check='group_counts_and_percentages',status='passed',items=len(summary)),
            dict(check='adapter_action_slot_coverage',status='passed',items=len(read('normalization_audit.csv'))),
            dict(check='pinned_source_sha256_and_size',status='passed',items=len(read('dataset_manifest.csv'))),
            dict(check='sample_locators_and_argument_hashes',status='passed',items=len(read('sample_calls.csv'))),
            dict(check='frozen_blind_validation_predictions',status='passed',items=len(read('validation_labels.csv')))]
    write_csv(HERE/'verification.csv',checks)
    print('All source hashes, adapter counts, CSV aggregates, and frozen validation predictions verified.')


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--raw',type=Path,required=True)
    main(p.parse_args().raw)
