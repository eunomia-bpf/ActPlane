#!/usr/bin/env python3
"""Reconcile replay calls, instrumentation coverage, and independently known sources."""
import csv
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
from collections import defaultdict
import adjudicate

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ['WS_RAW'])/'replay'
OUTPUT=Path(os.environ['WS_RAW']).parent/'replay/results'

def load(path,default=None):
    return json.loads(path.read_text()) if path.exists() else default

def lines(path):
    if not path.exists():return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

def write(name,rows,fields=None):
    with (OUTPUT/name).open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields or list(rows[0]));writer.writeheader();writer.writerows(rows)

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    plans=list(csv.DictReader((ROOT/'harness/dynamic_plan.csv').open()))
    wanted={p['trajectory_id'] for p in plans};original=defaultdict(list)
    with gzip.open(ROOT/'input/classified_calls.jsonl.gz','rt') as f:
        for line in f:
            row=json.loads(line)
            if row['trajectory_id'] in wanted:original[row['trajectory_id']].append(row)
    runs=[];calls=[];interventions=[];sources=[];compiled=[]
    for condition in ('none','broad','scoped'):
        for plan in plans:
            run=ROOT/condition/'dynamic/runs'/plan['dynamic_id']
            done=load(run/'done.json',{})
            metadata=load(run/'utility-metadata.json',{})
            exits=load(run/'instrument-exits.json',[])
            evidence={r['path']:r for r in load(run/'source-evidence.json',[])}
            recorded=sorted(original[plan['trajectory_id']],key=lambda c:c['call_index'])
            receipts={r['call_index']:r for r in lines(run/'calls.jsonl')}
            prefix='apti6e'+plan['dynamic_id'][1:]
            events=[];pid_owners=defaultdict(list);source_events=[];connections=[]
            observer_rows=lines(run/'sources.jsonl')
            for row in observer_rows:
                message=row.get('data','')
                if not isinstance(message,str):continue
                fields=message.strip().split('|',4)
                if len(fields)!=5 or fields[0] not in ('EXEC','FORK','READ','CONNECT') or not fields[2].startswith(prefix):continue
                try:kind,timestamp,owner,pid,payload=fields;timestamp=int(timestamp);pid=int(pid);index=int(owner[len(prefix):])
                except ValueError:continue
                events.append((timestamp,kind,pid,index,payload))
                pid_owners[pid].append((timestamp,index))
                if kind=='FORK':pid_owners[int(payload)].append((timestamp,index))
                if kind=='READ':source_events.append((timestamp,pid,index,payload))
                if kind=='CONNECT':connections.append((timestamp,pid,index,int(payload)))
            errors=[]
            if any(re.search(r'(?i)error|lost|drop|overflow', str(r.get('type',''))) for r in observer_rows):
                errors.append('observer reported event loss/helper failure')
            stderr=(run/'sources.stderr').read_text(errors='replace') if (run/'sources.stderr').exists() else ''
            if re.search(r'(?i)\b(error|lost|dropped|failed|overflow)\b',stderr):errors.append('observer diagnostic: '+stderr[-500:])
            if done.get('fatal'):errors.append(done['fatal'])
            if done and done.get('executed_calls')!=len(recorded):errors.append('recorded calls lack complete receipts')
            if done and done.get('observer_exit')!=0:errors.append('instrument group nonzero/unavailable exit')
            if condition!='none' and done and metadata.get('root_pid_namespace')!='initial-kernel-worker':errors.append('engine root namespace unvalidated')
            expected=(HERE/'source_observer.bt').read_text().replace('strncmp(comm, "apti6e", 6)',
                'strncmp(comm, '+json.dumps(prefix)+', 8)')
            if done and metadata.get('source_observer_sha256')!=hashlib.sha256(expected.encode()).hexdigest():errors.append('observer differs from frozen final protocol')
            if done and metadata.get('source_observer_string_bytes')!=1024:errors.append('observer buffer configuration differs from frozen final protocol')
            if done and (not exits or any(e['exit_code'] not in (0,-2) for e in exits)):errors.append('per-instrument exit receipt missing/nonzero')
            observed_indices={index for _,kind,_,index,_ in events if kind=='EXEC'}
            if done and any(index not in observed_indices for index in receipts):errors.append('executed call lacks independent tagged exec receipt')
            if condition!='none' and done:
                engine_stderr=(run/'engine.stderr').read_text(errors='replace') if (run/'engine.stderr').exists() else ''
                if 'ActPlane: ready' not in engine_stderr or f"seeded pid {metadata.get('root_pid')} label 0x0" not in engine_stderr:
                    errors.append('clean mapped engine readiness not established')
            coverage='complete' if done and not errors else ('partial' if done else 'pending')
            runrow=dict(condition=condition,dynamic_id=plan['dynamic_id'],trajectory_id=plan['trajectory_id'],framework=plan['framework'],model=plan['model'],
                recorded_calls=len(recorded),executed_calls=len(receipts),fatal=done.get('fatal',''),coverage=coverage,
                coverage_detail='; '.join(errors),setup_failed_steps=done.get('setup_failed_steps',''),elapsed_s=done.get('elapsed_s',''),
                root_pid=metadata.get('root_pid',''),root_pid_namespace=metadata.get('root_pid_namespace',''),source_observer_sha256=metadata.get('source_observer_sha256',''),
                engine_environment=json.dumps(metadata.get('engine_environment','unknown'),sort_keys=True))
            runs.append(runrow)
            percall=defaultdict(list)
            for event in lines(run/'engine.jsonl'):
                if event.get('event')!='TAINT_VIOLATION':continue
                timestamp=int(event['timestamp']);pid=int(event['pid']);candidates=[]
                for p in (pid,int(event.get('ppid',0))):
                    candidates.extend((t,i) for t,i in pid_owners.get(p,[]) if t<=timestamp)
                index=max(candidates)[1] if candidates else ''
                provenance=event.get('provenance') or {}
                path=provenance.get('target','')
                source=evidence.get(path,{})
                adjudication='unknown'
                reason='no independent confidential-source intent determination'
                # A public source is a candidate false taint, not automatically
                # a false intervention: full competing source flows must be reviewed.
                if source.get('classification') in ('public_certificate','public_repository_object'):
                    reason='public provenance source independently established; competing flows not exhaustively adjudicated'
                intervened=int(bool(event.get('killed') or event.get('blocked')))
                row=dict(condition=condition,dynamic_id=plan['dynamic_id'],trajectory_id=plan['trajectory_id'],call_index=index,
                    timestamp_ns=timestamp,pid=pid,rule_id=event.get('rule_id',''),effect=event.get('effect',''),intervened=intervened,
                    target=event.get('target',''),source_path=path,source_classification=source.get('classification','unknown'),
                    compiled_rule_match=1,adjudication=adjudication,adjudication_reason=reason,source_sha256=source.get('sha256',''),coverage=coverage)
                interventions.append(row)
                if index!='':percall[index].append(row)
            sourcecounts=defaultdict(int);networkcounts=defaultdict(int);ipv4counts=defaultdict(int)
            for timestamp,pid,index,path in source_events:
                sourcecounts[index]+=1
                source=evidence.get(path,{})
                sources.append(dict(condition=condition,dynamic_id=plan['dynamic_id'],trajectory_id=plan['trajectory_id'],call_index=index,timestamp_ns=timestamp,pid=pid,
                    path=path,path_maybe_truncated=int(len(path)>=1023),classification=source.get('classification','unknown'),sha256=source.get('sha256',''),
                    evidence_reason=source.get('reason','no post-command content receipt'),coverage=coverage))
            for _,_,index,family in connections:
                networkcounts[index]+=1
                if family==2:ipv4counts[index]+=1
            for position,call in enumerate(recorded,1):
                index=call['call_index'];receipt=receipts.get(index,{})
                matched=percall[index]
                calls.append(dict(condition=condition,dynamic_id=plan['dynamic_id'],trajectory_id=plan['trajectory_id'],call_id=call['call_id'],call_index=index,position=position,
                    tool=call['tool'],executed=int(bool(receipt)),exit_code=receipt.get('exit_code',''),timed_out=receipt.get('timed_out',''),elapsed_s=receipt.get('elapsed_s',''),
                    network_calls=networkcounts[index],ipv4_connect_attempts=ipv4counts[index],source_read_accesses=sourcecounts[index],
                    intervention_count=sum(r['intervened'] for r in matched),fp_count=0,true_count=0,unknown_count=sum(r['intervened'] for r in matched),coverage=coverage))
            for row in load(run/'compiled-sources.json',[]):compiled.append(dict(condition=condition,dynamic_id=plan['dynamic_id'],**row))
    annotations=adjudicate.review(interventions,sources)
    adjudicate.save(annotations)
    reviewed={(r['condition'],r['dynamic_id'],str(r['timestamp_ns'])):r for r in annotations}
    percall=defaultdict(list)
    perrun=defaultdict(list)
    for event in interventions:
        annotation=reviewed[(event['condition'],event['dynamic_id'],str(event['timestamp_ns']))]
        event['adjudication']=annotation['adjudication'];event['adjudication_reason']=annotation['evidence']
        perrun[(event['condition'],event['dynamic_id'])].append(event)
        if event['call_index']!='':percall[(event['condition'],event['dynamic_id'],event['call_index'])].append(event)
    for call in calls:
        matched=percall[(call['condition'],call['dynamic_id'],call['call_index'])]
        call.update(fp_count=sum(e['intervened'] and e['adjudication']=='false_intervention' for e in matched),
            true_count=sum(e['intervened'] and e['adjudication']=='true_violation' for e in matched),
            unknown_count=sum(e['intervened'] and e['adjudication']=='unknown' for e in matched))
    for run in runs:
        matched=perrun[(run['condition'],run['dynamic_id'])]
        run.update(unattributed_intervention_events=sum(e['intervened'] and e['call_index']=='' for e in matched),
            intervention_events=sum(e['intervened'] for e in matched),
            confirmed_false_events=sum(e['intervened'] and e['adjudication']=='false_intervention' for e in matched),
            confirmed_true_events=sum(e['intervened'] and e['adjudication']=='true_violation' for e in matched),
            unknown_intervention_events=sum(e['intervened'] and e['adjudication']=='unknown' for e in matched))
    write('runs.csv',runs);write('calls.csv',calls)
    write('interventions.csv',interventions,['condition','dynamic_id','trajectory_id','call_index','timestamp_ns','pid','rule_id','effect','intervened','target','source_path','source_classification','compiled_rule_match','adjudication','adjudication_reason','source_sha256','coverage'])
    write('source_read_accesses.csv',sources,['condition','dynamic_id','trajectory_id','call_index','timestamp_ns','pid','path','path_maybe_truncated','classification','sha256','evidence_reason','coverage'])
    write('compiled_sources.csv',compiled,['condition','dynamic_id','label','source_kind','pattern','compiled_op','compiled_match_mode','compiled_literal','add_mask'])
    bins=[];summary=[]
    for condition in ('none','broad','scoped'):
        selected=[r for r in calls if r['condition']==condition]
        valid=[r for r in selected if r['coverage']=='complete' and r['executed']]
        for lower in range(1,max(r['position'] for r in selected)+1,10):
            batch=[r for r in selected if lower<=r['position']<lower+10]
            usable=[r for r in batch if r['coverage']=='complete' and r['executed']]
            affected=sum(r['intervention_count']>0 for r in usable)
            bins.append(dict(condition=condition,position_start=lower,position_end=lower+9,recorded_calls=len(batch),executed_calls=sum(r['executed'] for r in batch),
                valid_covered_calls=len(usable),intervened_calls=affected,intervention_events=sum(r['intervention_count'] for r in usable),fp_events=sum(r['fp_count'] for r in usable),
                unknown_intervention_events=sum(r['unknown_count'] for r in usable),intervention_rate=affected/len(usable) if usable else ''))
        relevant_runs=[r for r in runs if r['condition']==condition]
        summary.append(dict(condition=condition,planned_trajectories=len(relevant_runs),complete_trajectories=sum(r['coverage']=='complete' for r in relevant_runs),
            recorded_calls=len(selected),executed_calls=sum(r['executed'] for r in selected),valid_covered_calls=len(valid),
            exit_zero_calls=sum(r['exit_code']==0 for r in valid),intervened_calls=sum(r['intervention_count']>0 for r in valid),
            intervention_events=sum(r['intervention_events'] for r in relevant_runs if r['coverage']=='complete'),fp_events=sum(r['fp_count'] for r in valid),true_events=sum(r['true_count'] for r in valid),unknown_intervention_events=sum(r['unknown_intervention_events'] for r in relevant_runs if r['coverage']=='complete'),
            unattributed_intervention_events=sum(r['unattributed_intervention_events'] for r in relevant_runs if r['coverage']=='complete'),
            source_read_accesses=sum(r['source_read_accesses'] for r in valid),ipv4_connect_attempts=sum(r['ipv4_connect_attempts'] for r in valid),
            call_elapsed_s=sum(float(r['elapsed_s']) for r in valid)))
    write('bins.csv',bins);write('summary.csv',summary)
    attempts=[]
    for p in sorted((ROOT/'attempts').glob('*/done.json')):
        done=load(p,{})
        attempts.append(dict(attempt=p.parent.name,dynamic_id=done.get('dynamic_id',''),recorded_calls=done.get('recorded_calls',''),executed_calls=done.get('executed_calls',''),
            fatal=done.get('fatal',''),observer_exit=done.get('observer_exit',''),elapsed_s=done.get('elapsed_s',''),exclusion=json.dumps(load(p.parent/'exclusion-reason.json',{}),sort_keys=True)))
    write('attempts.csv',attempts,['attempt','dynamic_id','recorded_calls','executed_calls','fatal','observer_exit','elapsed_s','exclusion'])
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
