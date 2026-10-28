#!/usr/bin/env python3
"""Aggregate OS-observed effects and compare their object names to original args.

The primary visibility test is deliberately permissive: any literal basename or
an explicit shell-style glob anywhere in an argument counts as naming the object.
Directory names alone do not name every descendant. Strict path matching is also
retained as a sensitivity result. Injected dispatcher execs never enter metrics.
"""
import argparse
from collections import Counter,defaultdict
import csv
import fnmatch
import gzip
import hashlib
import json
from pathlib import Path
import posixpath
import re
import shlex

import bashlex

from analyze import HERE,write_csv,walk


def strings(value):
    if isinstance(value,str):yield value
    elif isinstance(value,dict):
        for item in value.values():yield from strings(item)
    elif isinstance(value,list):
        for item in value:yield from strings(item)


def visibility(path,args,cwd,effect):
    if not path or path.endswith('..') or len(path.encode())>=255:
        return dict(named=-1,strict_named=-1,match='unresolved_or_truncated_path')
    values=list(strings(args))
    name=posixpath.basename(path)
    boundary=r'[A-Za-z0-9_.-]'
    expression=r'(?<!'+boundary+')'+re.escape(name)+r'(?!'+boundary+')'
    literal=any(re.search(expression,s) for s in values) if name else False
    absolute=path if path.startswith('/') else posixpath.normpath(posixpath.join(cwd,path))
    relative=posixpath.relpath(absolute,cwd) if cwd else absolute
    path_boundary=r'[A-Za-z0-9_./-]'
    strict=any(re.search(r'(?<!'+path_boundary+')'+re.escape(p)+r'(?!'+path_boundary+')',value)
               for value in values for p in (absolute,relative) if p not in ('.','..'))
    glob=False
    command=args.get('command',args.get('cmd','')) if isinstance(args,dict) else ''
    def shell_words(command):
        try:
            normalized=re.sub(r"<<(\-?)\s*(['\"])([A-Za-z_]\w*)\2",r"<<\1\3",command)
            nodes=[n for root in bashlex.parse(normalized+'\n') for n in walk(root)]
        except Exception:return []
        words=[]
        for n in nodes:
            if n.kind!='command':continue
            args=[p.word for p in n.parts if p.kind=='word']
            words.extend(args)
            if args and posixpath.basename(args[0]) in ('bash','sh'):
                for i,arg in enumerate(args[1:],1):
                    if arg.startswith('-') and 'c' in arg and i+1<len(args):
                        words.extend(shell_words(args[i+1]))
                        break
        return words
    if command:
        for token in shell_words(command):
            if not re.fullmatch(r'[A-Za-z0-9_./~*?\[\]@+:-]+',token):continue
            if not any(c in token for c in '*?['):continue
            pattern=posixpath.basename(token)
            if fnmatch.fnmatchcase(name,pattern):glob=True
    # An explicit executable basename is sufficient for PATH-resolved exec names.
    if effect=='exec' and literal:strict=True
    return dict(named=int(literal or glob),strict_named=int(strict and (literal or glob)),
                match='literal_basename' if literal else 'explicit_glob' if glob else 'absent_from_arguments')


def parse_observer(path):
    counts={};byte_counts={};errors=[];ready=False
    if not path.exists():return counts,byte_counts,['observer output missing']
    with path.open() as f:
        for line in f:
            if not line.strip():continue
            try:row=json.loads(line)
            except ValueError:
                errors.append('malformed observer JSON');continue
            if row.get('type')=='printf' and 'OBSERVER_READY' in row.get('data',''):ready=True
            if row.get('type')=='helper_error':errors.append(row.get('msg','helper error'))
            if row.get('type') in ('lost_events','error'):errors.append(json.dumps(row))
            if row.get('type')!='map':continue
            for key,values in row.get('data',{}).items():
                target=counts if key=='@counts' else byte_counts if key=='@bytes' else None
                if target is not None:
                    for composite,value in values.items():
                        parts=composite.split(',',2)
                        if len(parts)!=3:errors.append('malformed observer map key');continue
                        target[(parts[0],int(parts[1]),parts[2])]=int(value)
    if not ready:errors.append('observer readiness missing')
    return counts,byte_counts,errors


def analyze(raw):
    plans=list(csv.DictReader((HERE/'dynamic_plan.csv').open()))
    wanted={p['trajectory_id'] for p in plans}
    by_trajectory=defaultdict(list)
    with gzip.open(raw/'classified_calls.jsonl.gz','rt') as f:
        for line in f:
            call=json.loads(line)
            if call['trajectory_id'] in wanted:by_trajectory[call['trajectory_id']].append(call)
    all_calls=[];all_effects=[];replays=[]
    for plan in plans:
        run=raw/'dynamic'/'runs'/plan['dynamic_id']
        if not (run/'done.json').exists():continue
        done=json.loads((run/'done.json').read_text())
        records={r['call_id']:r for r in map(json.loads,(run/'calls.jsonl').read_text().splitlines())} if (run/'calls.jsonl').exists() else {}
        counts,bytes_,errors=parse_observer(run/'observer.jsonl')
        effects_by_tag=defaultdict(list)
        for (tag,kind,path),events in counts.items():
            effects_by_tag[tag].append((kind,path,events,bytes_.get((tag,kind,path),0)))
        replay=dict(**plan,executed_calls=done['executed_calls'],fatal=done['fatal'],setup_steps=done['setup_steps'],
                    setup_failed_steps=done['setup_failed_steps'],observer_exit=done['observer_exit'],observer_errors=len(errors),
                    observer_error_detail='; '.join(errors[:10]),elapsed_s=done['elapsed_s'],finished_utc=done['finished_utc'])
        replay['successful_calls']=sum(r.get('exit_code')==0 for r in records.values())
        replay['failed_calls']=sum(r.get('exit_code') not in (None,0) for r in records.values())
        replay['timed_out_calls']=sum(r.get('timed_out',0) for r in records.values())
        replays.append(replay)
        for call in by_trajectory[plan['trajectory_id']]:
            receipt=records.get(call['call_id'],{})
            tag=receipt.get('tag','')
            row=dict(dynamic_id=plan['dynamic_id'],call_id=call['call_id'],framework=plan['framework'],model=plan['model'],
                     instance_id=plan['instance_id'],call_index=call['call_index'],tool=call['tool'],classification=call['classification'],
                     replay_executed=int(bool(receipt)),exit_code=receipt.get('exit_code',''),timed_out=receipt.get('timed_out',0),
                     original_status=call['status'],trace_valid=int(not errors),elapsed_s=receipt.get('elapsed_s',0))
            totals=Counter()
            for kind,path,n,byte_count in effects_by_tag.get(tag,[]):
                if kind in (8,9):
                    totals['failed_exec_attempts' if kind==8 else 'dispatcher_execs']+=n
                    continue
                effect={1:'write',2:'exec',3:'truncate'}.get(kind,'unknown')
                decision=visibility(path,call['args'],receipt.get('cwd_before',plan['sandbox_workdir']),effect)
                effects=dict(dynamic_id=plan['dynamic_id'],call_id=call['call_id'],framework=plan['framework'],model=plan['model'],
                             classification=call['classification'],effect=effect,path=path,events=n,bytes=byte_count,**decision)
                all_effects.append(effects)
                totals[effect+'_events']+=n;totals[effect+'_objects']+=1
                if decision['named']==0:
                    totals['unnamed_'+effect+'_events']+=n;totals['unnamed_'+effect+'_objects']+=1
                if decision['strict_named']==0:
                    totals['strict_unnamed_'+effect+'_events']+=n
                if decision['named']==-1:
                    totals['unknown_'+effect+'_events']+=n
            for effect in ('write','exec','truncate'):
                for prefix in ('','unnamed_','strict_unnamed_','unknown_'):
                    row[prefix+effect+'_events']=totals[prefix+effect+'_events']
                for prefix in ('','unnamed_'):
                    row[prefix+effect+'_objects']=totals[prefix+effect+'_objects']
            row.update(dispatcher_execs=totals['dispatcher_execs'],failed_exec_attempts=totals['failed_exec_attempts'])
            row['any_unnamed_effect']=int(totals['unnamed_write_events']+totals['unnamed_exec_events']>0)
            row['any_effect']=int(totals['write_events']+totals['exec_events']>0)
            all_calls.append(row)
    if not replays:
        print('No completed replay receipts yet');return
    write_csv(HERE/'dynamic_replays.csv',replays)
    write_csv(HERE/'dynamic_calls.csv',all_calls)
    with gzip.open(raw/'dynamic'/'effects.jsonl.gz','wt') as f:
        for effect in all_effects:f.write(json.dumps(effect)+'\n')
    groups=defaultdict(list)
    for call in all_calls:
        for key in [('ALL','ALL','ALL'),(call['framework'],call['model'],'ALL'),('ALL','ALL',call['classification'])]:
            groups[key].append(call)
    summaries=[]
    for (framework,model,classification),calls in sorted(groups.items()):
        item=dict(framework=framework,model=model,classification=classification,
                  trajectories=len(set(c['dynamic_id'] for c in calls)),recorded_calls=len(calls),
                  executed_calls=sum(c['replay_executed'] for c in calls),successful_calls=sum(c['exit_code']==0 for c in calls),
                  failed_calls=sum(c['exit_code'] not in ('',0) for c in calls),
                  timed_out_calls=sum(c['timed_out'] for c in calls),
                  any_unnamed_effect_calls=sum(c['any_unnamed_effect'] for c in calls))
        for effect in ('write','exec','truncate'):
            for name in (effect+'_events','unnamed_'+effect+'_events','strict_unnamed_'+effect+'_events','unknown_'+effect+'_events',effect+'_objects','unnamed_'+effect+'_objects'):
                item[name]=sum(c[name] for c in calls)
            n=item[effect+'_events'];objects=item[effect+'_objects']
            item['unnamed_'+effect+'_pct']=100*item['unnamed_'+effect+'_events']/n if n else ''
            item['unnamed_'+effect+'_object_pct']=100*item['unnamed_'+effect+'_objects']/objects if objects else ''
        summaries.append(item)
    write_csv(HERE/'dynamic_summary.csv',summaries)
    confusion=[]
    for scope in ('all_recorded_calls','executed_calls','effectful_calls','indirect_vs_direct'):
        calls=[c for c in all_calls if scope=='all_recorded_calls' or (scope=='executed_calls' and c['replay_executed'])
               or (scope=='effectful_calls' and c['any_effect']) or (scope=='indirect_vs_direct' and c['classification'] in ('indirect','direct_edit','direct_shell','context_edit'))]
        tp=sum(c['classification']=='indirect' and c['any_unnamed_effect'] for c in calls)
        fp=sum(c['classification']=='indirect' and not c['any_unnamed_effect'] for c in calls)
        fn=sum(c['classification']!='indirect' and c['any_unnamed_effect'] for c in calls)
        tn=len(calls)-tp-fp-fn
        confusion.append(dict(scope=scope,calls=len(calls),true_positive=tp,false_positive=fp,false_negative=fn,true_negative=tn,
                              precision=tp/(tp+fp) if tp+fp else '',recall=tp/(tp+fn) if tp+fn else ''))
    write_csv(HERE/'dynamic_confusion.csv',confusion)
    sample=sorted(all_effects,key=lambda r:hashlib.sha256((r['call_id']+r['effect']+r['path']).encode()).hexdigest())[:200]
    if sample:write_csv(HERE/'dynamic_effect_sample.csv',sample)
    print(f'Summarized {len(replays)} trajectories, {len(all_calls)} recorded calls, {len(all_effects)} call-object effect records')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True)
    analyze(p.parse_args().raw)
