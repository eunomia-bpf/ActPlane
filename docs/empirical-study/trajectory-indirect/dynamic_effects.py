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
import subprocess

import bashlex

from analyze import HERE,write_csv,walk

SHELL_WORD_CACHE={}
PROFILE_HELPER_BASENAMES={'id','run-parts'}


def strings(value):
    if isinstance(value,str):yield value
    elif isinstance(value,dict):
        for item in value.values():yield from strings(item)
    elif isinstance(value,list):
        for item in value:yield from strings(item)


def visibility(path,args,cwd,effect,string_bytes=256):
    if not path or path.endswith('..') or len(path.encode())>=string_bytes-1:
        return dict(named=-1,strict_named=-1,match='unresolved_or_truncated_path')
    path=path.removesuffix(' (deleted)')
    values=list(strings(args))
    name=posixpath.basename(path)
    boundary=r'[A-Za-z0-9_.-]'
    expression=r'(?<!'+boundary+')'+re.escape(name)+r'(?!'+boundary+')'
    literal=any(name in s and re.search(expression,s) for s in values) if name else False
    absolute=path if path.startswith('/') else posixpath.normpath(posixpath.join(cwd,path))
    relative=posixpath.relpath(absolute,cwd) if cwd else absolute
    candidates=(absolute,relative,'./'+relative) if not relative.startswith('../') else (absolute,relative)
    path_boundary=r'[A-Za-z0-9_./-]'
    strict=any(p in value and re.search(r'(?<!'+path_boundary+')'+re.escape(p)+r'(?!'+path_boundary+')',value)
               for value in values for p in candidates if p not in ('.','..'))
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
        if command not in SHELL_WORD_CACHE:
            SHELL_WORD_CACHE[command]=[posixpath.basename(token) for token in shell_words(command)
                if re.fullmatch(r'[A-Za-z0-9_./~*?\[\]@+:-]+',token) and any(c in token for c in '*?[')]
        for pattern in SHELL_WORD_CACHE[command]:
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
    tracked_cache={}
    for plan in plans:
        run=raw/'dynamic'/'runs'/plan['dynamic_id']
        if not (run/'done.json').exists():continue
        done=json.loads((run/'done.json').read_text())
        tracked_key=(plan['repository'],plan['base_commit'])
        if tracked_key not in tracked_cache:
            git_dir=raw/'dynamic/git-cache'/plan['repository'].replace('/','__')
            tree=subprocess.check_output(['git','--git-dir',str(git_dir),'ls-tree','-r','-z','--name-only',plan['base_commit']])
            tracked_cache[tracked_key]={p.decode('utf-8',errors='replace') for p in tree.split(b'\0') if p}
        observer_metadata=json.loads((run/'observer_metadata.json').read_text()) if (run/'observer_metadata.json').exists() else {}
        string_bytes=observer_metadata.get('config',{}).get('observer_string_bytes',256)
        records={r['call_id']:r for r in map(json.loads,(run/'calls.jsonl').read_text().splitlines())} if (run/'calls.jsonl').exists() else {}
        counts,bytes_,errors=parse_observer(run/'observer.jsonl')
        effects_by_tag=defaultdict(list)
        for (tag,kind,path),events in counts.items():
            effects_by_tag[tag].append((kind,path,events,bytes_.get((tag,kind,path),0)))
        replay=dict(**plan,executed_calls=done['executed_calls'],fatal=done['fatal'],setup_steps=done['setup_steps'],
                    setup_failed_steps=done['setup_failed_steps'],observer_exit=done['observer_exit'],observer_errors=len(errors),
                    observer_error_detail='; '.join(errors[:10]),elapsed_s=done['elapsed_s'],finished_utc=done['finished_utc'])
        replay['observer_string_bytes']=string_bytes
        replay['observer_sha256']=observer_metadata.get('observer_sha256','')
        for key in ('per_call_timeout_s','per_trajectory_timeout_s','environment_setup_timeout_s'):
            replay[key]=observer_metadata.get('config',{}).get(key,'')
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
                     process_launched=int(bool(receipt) and not receipt.get('worker_error')),worker_error=receipt.get('worker_error',''),
                     original_status=call['status'],trace_valid=int(not errors),elapsed_s=receipt.get('elapsed_s',0))
            row['original_timeout_argument']=call['args'].get('timeout','')
            totals=Counter()
            tagged_effects=effects_by_tag.get(tag,[])
            shim_execs=sum(n for kind,path,n,b in tagged_effects if kind==2 and path=='/replay/bin/apply_patch')
            for kind,path,n,byte_count in tagged_effects:
                if kind in (8,9):
                    totals['failed_exec_attempts' if kind==8 else 'dispatcher_execs']+=n
                    continue
                # The supplied apply_patch shim has one injected Python exec per
                # invocation. Remove it conservatively, while retaining the
                # named shim exec and any additional project Python execs.
                if kind==2 and path=='/usr/bin/python3' and shim_execs:
                    excluded=min(n,shim_execs)
                    totals['shim_helper_execs']+=excluded
                    n-=excluded;shim_execs-=excluded
                    if not n:continue
                effect={1:'write',2:'exec',3:'truncate'}.get(kind,'unknown')
                decision=visibility(path,call['args'],receipt.get('cwd_before',plan['sandbox_workdir']),effect,string_bytes)
                effects=dict(dynamic_id=plan['dynamic_id'],call_id=call['call_id'],framework=plan['framework'],model=plan['model'],
                             classification=call['classification'],effect=effect,path=path,events=n,bytes=byte_count,**decision)
                effects['profile_helper_name_proxy']=int(effect=='exec' and posixpath.basename(path) in PROFILE_HELPER_BASENAMES)
                if effects['profile_helper_name_proxy']:
                    totals['profile_helper_exec_events']+=n;totals['profile_helper_exec_objects']+=1
                    if decision['named']==0:
                        totals['unnamed_profile_helper_exec_events']+=n;totals['unnamed_profile_helper_exec_objects']+=1
                project=plan['sandbox_workdir'].rstrip('/')+'/'
                effects['project_base_tracked']=-1
                if path.startswith(project):
                    relative=path[len(project):].removesuffix(' (deleted)')
                    effects['project_base_tracked']=int(relative in tracked_cache[tracked_key])
                    dependency=any(part in relative.split('/') for part in ('_submodules','node_modules','.pnpm-store','.yarn','.npm'))
                    generated=any(part in relative.split('/') for part in ('.git','__pycache__','.pytest_cache','node_modules','target','build','dist','.mypy_cache','.ruff_cache','.tox','.venv','venv'))
                    effects['path_scope']='project_dependency' if dependency else 'project_generated' if generated else 'project_other'
                elif path.startswith('/cache/'):effects['path_scope']='package_cache'
                elif path.startswith('/venv/'):effects['path_scope']='environment'
                elif path.startswith('/tmp/'):effects['path_scope']='temporary'
                elif path.startswith('/root/'):effects['path_scope']='home'
                else:effects['path_scope']='system_or_other'
                all_effects.append(effects)
                totals[effect+'_events']+=n;totals[effect+'_objects']+=1
                if decision['named']==0:
                    totals['unnamed_'+effect+'_events']+=n;totals['unnamed_'+effect+'_objects']+=1
                if decision['strict_named']==0:
                    totals['strict_unnamed_'+effect+'_events']+=n
                if decision['named']==-1:
                    totals['unknown_'+effect+'_events']+=n
                    totals['unknown_'+effect+'_objects']+=1
            for effect in ('write','exec','truncate'):
                for prefix in ('','unnamed_','strict_unnamed_','unknown_'):
                    row[prefix+effect+'_events']=totals[prefix+effect+'_events']
                for prefix in ('','unnamed_','unknown_'):
                    row[prefix+effect+'_objects']=totals[prefix+effect+'_objects']
            row.update(dispatcher_execs=totals['dispatcher_execs'],shim_helper_execs=totals['shim_helper_execs'],failed_exec_attempts=totals['failed_exec_attempts'])
            for name in ('profile_helper_exec_events','profile_helper_exec_objects','unnamed_profile_helper_exec_events','unnamed_profile_helper_exec_objects'):
                row[name]=totals[name]
            row['any_unnamed_effect']=int(totals['unnamed_write_events']+totals['unnamed_exec_events']>0)
            row['any_unnamed_effect_no_profile_helpers']=int(totals['unnamed_write_events']+totals['unnamed_exec_events']-totals['unnamed_profile_helper_exec_events']>0)
            row['any_effect']=int(totals['write_events']+totals['exec_events']>0)
            row['truth_unresolved']=int(not row['any_unnamed_effect'] and (not row['replay_executed'] or not row['trace_valid'] or totals['unknown_write_events']+totals['unknown_exec_events']>0))
            all_calls.append(row)
    if not replays:
        print('No completed replay receipts yet');return
    write_csv(HERE/'dynamic_replays.csv',replays)
    write_csv(HERE/'dynamic_calls.csv',all_calls)
    fidelity=Counter()
    for call in all_calls:
        outcome=('unexecuted' if not call['replay_executed'] else 'timeout' if call['timed_out']
                 else 'exit_zero' if call['exit_code']==0 else 'exit_nonzero')
        fidelity[('ALL','ALL',call['original_status'],outcome)]+=1
        fidelity[(call['framework'],call['model'],call['original_status'],outcome)]+=1
    write_csv(HERE/'dynamic_fidelity.csv',[dict(framework=k[0],model=k[1],original_status=k[2],replay_outcome=k[3],calls=n)
                                           for k,n in sorted(fidelity.items())])
    with gzip.open(raw/'dynamic'/'effects.jsonl.gz','wt') as f:
        for effect in all_effects:f.write(json.dumps(effect)+'\n')
    groups=defaultdict(list)
    for call in all_calls:
        for key in [('ALL','ALL','ALL'),(call['framework'],call['model'],'ALL'),('ALL','ALL',call['classification']),
                    (call['framework'],call['model'],call['classification'])]:
            groups[key].append(call)
    summaries=[]
    for (framework,model,classification),calls in sorted(groups.items()):
        item=dict(framework=framework,model=model,classification=classification,
                  trajectories=len(set(c['dynamic_id'] for c in calls)),recorded_calls=len(calls),
                  executed_calls=sum(c['replay_executed'] for c in calls),successful_calls=sum(c['exit_code']==0 for c in calls),
                  failed_calls=sum(c['exit_code'] not in ('',0) for c in calls),
                  timed_out_calls=sum(c['timed_out'] for c in calls),
                  invalid_trace_calls=sum(not c['trace_valid'] for c in calls),
                  any_unnamed_effect_calls=sum(c['any_unnamed_effect'] for c in calls),
                  any_observed_effect_calls=sum(c['any_effect'] for c in calls),
                  any_unnamed_effect_trajectories=len({c['dynamic_id'] for c in calls if c['any_unnamed_effect']}),
                  any_unnamed_effect_calls_pct=100*sum(c['any_unnamed_effect'] for c in calls)/len(calls))
        for effect in ('write','exec','truncate'):
            for name in (effect+'_events','unnamed_'+effect+'_events','strict_unnamed_'+effect+'_events','unknown_'+effect+'_events',effect+'_objects','unnamed_'+effect+'_objects','unknown_'+effect+'_objects'):
                item[name]=sum(c[name] for c in calls)
            n=item[effect+'_events'];objects=item[effect+'_objects']
            item['unnamed_'+effect+'_pct']=100*item['unnamed_'+effect+'_events']/n if n else ''
            item['unnamed_'+effect+'_object_pct']=100*item['unnamed_'+effect+'_objects']/objects if objects else ''
        summaries.append(item)
    write_csv(HERE/'dynamic_summary.csv',summaries)
    sensitivity=[]
    for (framework,model,classification),calls in sorted(groups.items()):
        row=dict(scenario='exclude_exec_basenames_id_and_run-parts',framework=framework,model=model,
                 classification=classification,recorded_calls=len(calls))
        for unit in ('events','objects'):
            removed=sum(c['profile_helper_exec_'+unit] for c in calls)
            total=sum(c['exec_'+unit] for c in calls)-removed
            unnamed=sum(c['unnamed_exec_'+unit]-c['unnamed_profile_helper_exec_'+unit] for c in calls)
            row['excluded_exec_'+unit]=removed;row['exec_'+unit]=total;row['unnamed_exec_'+unit]=unnamed
            row['unnamed_exec_'+unit+'_pct']=100*unnamed/total if total else ''
        tp=sum(c['classification']=='indirect' and c['any_unnamed_effect_no_profile_helpers'] for c in calls)
        fp=sum(c['classification']=='indirect' and not c['any_unnamed_effect_no_profile_helpers'] for c in calls)
        fn=sum(c['classification']!='indirect' and c['any_unnamed_effect_no_profile_helpers'] for c in calls)
        row.update(any_unnamed_effect_calls=sum(c['any_unnamed_effect_no_profile_helpers'] for c in calls),
                   true_positive=tp,false_positive=fp,false_negative=fn,true_negative=len(calls)-tp-fp-fn,
                   precision=tp/(tp+fp) if tp+fp else '',recall=tp/(tp+fn) if tp+fn else '')
        sensitivity.append(row)
    write_csv(HERE/'dynamic_sensitivity.csv',sensitivity)
    trajectory_summaries=[]
    for replay in replays:
        calls=[c for c in all_calls if c['dynamic_id']==replay['dynamic_id']]
        item={key:replay[key] for key in ('dynamic_id','framework','model','instance_id')}
        item['recorded_calls']=len(calls)
        item['executed_calls']=sum(c['replay_executed'] for c in calls)
        item['any_unnamed_effect_calls']=sum(c['any_unnamed_effect'] for c in calls)
        for effect in ('write','exec'):
            for suffix in ('events','objects'):
                total=sum(c[effect+'_'+suffix] for c in calls)
                unnamed=sum(c['unnamed_'+effect+'_'+suffix] for c in calls)
                item[effect+'_'+suffix]=total
                item['unnamed_'+effect+'_'+suffix]=unnamed
                item['unnamed_'+effect+'_'+suffix+'_pct']=100*unnamed/total if total else ''
        trajectory_summaries.append(item)
    write_csv(HERE/'dynamic_trajectory_summary.csv',trajectory_summaries)
    scope_groups=defaultdict(list)
    for effect in all_effects:
        if effect['effect'] not in ('write','exec'):continue
        for key in [('ALL','ALL',effect['path_scope'],effect['effect']),
                    (effect['framework'],effect['model'],effect['path_scope'],effect['effect'])]:
            scope_groups[key].append(effect)
    scope_rows=[]
    for key,effects in sorted(scope_groups.items()):
        total=sum(e['events'] for e in effects)
        unnamed=sum(e['events'] for e in effects if e['named']==0)
        scope_rows.append(dict(framework=key[0],model=key[1],path_scope=key[2],effect=key[3],events=total,
                               unnamed_events=unnamed,unknown_events=sum(e['events'] for e in effects if e['named']==-1),
                               unnamed_pct=100*unnamed/total,call_object_pairs=len(effects),
                               unnamed_call_object_pairs=sum(e['named']==0 for e in effects),
                               unnamed_call_object_pct=100*sum(e['named']==0 for e in effects)/len(effects)))
    write_csv(HERE/'dynamic_scope_summary.csv',scope_rows)
    tracked_groups=defaultdict(list)
    for effect in all_effects:
        if effect['effect']!='write':continue
        scope={1:'base_tracked_project',0:'other_project',-1:'outside_project'}[effect['project_base_tracked']]
        for key in [('ALL','ALL',scope),(effect['framework'],effect['model'],scope)]:tracked_groups[key].append(effect)
    tracked_rows=[]
    for key,effects in sorted(tracked_groups.items()):
        total=sum(e['events'] for e in effects);unnamed=sum(e['events'] for e in effects if e['named']==0)
        tracked_rows.append(dict(framework=key[0],model=key[1],path_scope=key[2],events=total,unnamed_events=unnamed,
            unnamed_pct=100*unnamed/total,call_file_pairs=len(effects),unnamed_call_file_pairs=sum(e['named']==0 for e in effects),
            unnamed_call_file_pct=100*sum(e['named']==0 for e in effects)/len(effects)))
    write_csv(HERE/'dynamic_tracked_scope_summary.csv',tracked_rows)
    confusion=[]
    for scope in ('all_recorded_calls','executed_calls','successful_calls','effectful_calls','indirect_vs_direct'):
        calls=[c for c in all_calls if scope=='all_recorded_calls' or (scope=='executed_calls' and c['replay_executed'])
               or (scope=='successful_calls' and c['exit_code']==0) or (scope=='effectful_calls' and c['any_effect']) or (scope=='indirect_vs_direct' and c['classification'] in ('indirect','direct_edit','direct_shell','context_edit'))]
        tp=sum(c['classification']=='indirect' and c['any_unnamed_effect'] for c in calls)
        fp=sum(c['classification']=='indirect' and not c['any_unnamed_effect'] for c in calls)
        fn=sum(c['classification']!='indirect' and c['any_unnamed_effect'] for c in calls)
        tn=len(calls)-tp-fp-fn
        unknown_p=sum(c['classification']=='indirect' and c['truth_unresolved'] for c in calls)
        unknown_n=sum(c['classification']!='indirect' and c['truth_unresolved'] for c in calls)
        confusion.append(dict(scope=scope,calls=len(calls),true_positive=tp,false_positive=fp,false_negative=fn,true_negative=tn,
                              precision=tp/(tp+fp) if tp+fp else '',recall=tp/(tp+fn) if tp+fn else '',
                              unresolved_predicted=unknown_p,unresolved_other=unknown_n,
                              precision_upper=(tp+unknown_p)/(tp+fp) if tp+fp else '',
                              recall_lower=tp/(tp+fn+unknown_n) if tp+fn+unknown_n else '',
                              recall_upper=(tp+unknown_p)/(tp+unknown_p+fn) if tp+unknown_p+fn else ''))
    write_csv(HERE/'dynamic_confusion.csv',confusion)
    model_confusion=[]
    for framework,model in sorted({(c['framework'],c['model']) for c in all_calls}):
        calls=[c for c in all_calls if (c['framework'],c['model'])==(framework,model)]
        tp=sum(c['classification']=='indirect' and c['any_unnamed_effect'] for c in calls)
        fp=sum(c['classification']=='indirect' and not c['any_unnamed_effect'] for c in calls)
        fn=sum(c['classification']!='indirect' and c['any_unnamed_effect'] for c in calls)
        model_confusion.append(dict(framework=framework,model=model,calls=len(calls),true_positive=tp,false_positive=fp,
                                    false_negative=fn,true_negative=len(calls)-tp-fp-fn,
                                    precision=tp/(tp+fp) if tp+fp else '',recall=tp/(tp+fn) if tp+fn else '',
                                    unresolved_calls=sum(c['truth_unresolved'] for c in calls)))
    write_csv(HERE/'dynamic_model_confusion.csv',model_confusion)
    # Show varied examples instead of allowing one dependency install to fill
    # the committed excerpt. The complete effect census remains in raw storage.
    sample_strata=defaultdict(list)
    for effect in all_effects:
        sample_strata[(effect['classification'],effect['effect'],effect['path_scope'])].append(effect)
    for effects in sample_strata.values():
        effects.sort(key=lambda r:hashlib.sha256((r['call_id']+r['effect']+r['path']).encode()).hexdigest())
    sample=[];rank=0
    while len(sample)<200:
        added=False
        for key in sorted(sample_strata):
            if rank<len(sample_strata[key]):
                sample.append(sample_strata[key][rank]);added=True
                if len(sample)==200:break
        if not added:break
        rank+=1
    if sample:write_csv(HERE/'dynamic_effect_sample.csv',sample)
    print(f'Summarized {len(replays)} trajectories, {len(all_calls)} recorded calls, {len(all_effects)} call-object effect records')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True)
    analyze(p.parse_args().raw)
