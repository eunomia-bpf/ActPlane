"""Aggregate the frozen official-task matrix without dropping failed cells."""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
from pathlib import Path


def write_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as f:
        w=csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader(); w.writerows(rows)


def cell_key(r):
    return (r['task_id'],r['model'],r.get('system',r.get('defense')),
            str(r.get('no_attack')).lower(),r.get('carrier',r.get('attack_carrier')))


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--manifest',type=Path,nargs='+',required=True)
    p.add_argument('--runs',type=Path,nargs='+',required=True)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    planned=[r for path in args.manifest for r in csv.DictReader(path.open())]
    if len({cell_key(r) for r in planned})!=len(planned):
        raise ValueError('duplicate cell in combined manifests')
    records={}
    for run in args.runs:
        for path in sorted((run/'cases').glob('*/scored.json')):
            r=json.loads(path.read_text()); key=cell_key(r)
            if key in records:
                raise ValueError(f'duplicate cell in report inputs: {key}')
            records[key]=r
    cells=[]
    for row in planned:
        r=records.get(cell_key(row))
        status='pending' if r is None else r.get('run_status','unknown')
        known=False if r is None else r.get('attack_outcome_known',False)
        cells.append(dict(row,run_status=status,error='' if r is None else r.get('error',''),
            attack_outcome_known=known,
            attack_completed='' if not known else bool(r.get('attack_completed')),
            utility_pass=False if r is None else bool(r.get('utility_pass')),
            proposed_attempt=False if r is None else bool(r.get('proposed_attempt')),
            unsafe_action_landed=False if r is None else bool(r.get('unsafe_action_landed')),
            parser_failures=0 if r is None else r.get('parser_failures',0),
            wall_clock_s='' if r is None else r.get('wall_clock_s','')))
    write_csv(args.out/'cells.csv',cells,list(cells[0]) if cells else [])
    write_csv(args.out/'combined-planned.csv',planned,list(planned[0]) if planned else [])
    identities=defaultdict(int)
    for run in args.runs:
        for path in (run/'cases').glob('*/calls/*/*.response.json'):
            try:
                r=json.loads(path.read_text())
                scored=path.parents[2]/'scored.json'
                requested=json.loads(scored.read_text()).get('model') if scored.exists() else 'pending'
                served=r.get('cli_model_identities') or ([r['model']] if r.get('model') else [])
                for model in served:identities[(requested,model)]+=1
            except (ValueError,OSError):continue
    write_csv(args.out/'model-identities.csv',[
        dict(requested_model=k[0],observed_model=k[1],response_count=v)
        for k,v in sorted(identities.items())],['requested_model','observed_model','response_count'])
    grouped=defaultdict(list)
    for c in cells:grouped[(c['model'],c['system'])].append(c)
    summary=[]
    for (model,system),rows in sorted(grouped.items()):
        clean=[r for r in rows if r['no_attack'].lower()=='true']
        attacked=[r for r in rows if r['no_attack'].lower()=='false']
        successes=sum(r['attack_completed'] is True for r in attacked)
        unknown=sum(not r['attack_outcome_known'] for r in attacked)
        done=sum(r['run_status']!='pending' for r in rows)
        summary.append(dict(model=model,system=system,planned=len(rows),finished=done,
            pending=len(rows)-done,failed=sum(r['run_status']=='failed' for r in rows),
            clean_n=len(clean),attack_n=len(attacked),attack_successes=successes,
            attack_unknown=unknown,asr_lower=successes/len(attacked),
            asr_upper=(successes+unknown)/len(attacked),
            clean_successes=sum(r['utility_pass'] for r in clean),
            clean_utility=sum(r['utility_pass'] for r in clean)/len(clean),
            attacked_successes=sum(r['utility_pass'] for r in attacked),
            attacked_utility=sum(r['utility_pass'] for r in attacked)/len(attacked),
            proposed_attempts=sum(r['proposed_attempt'] for r in attacked),
            unsafe_landed=sum(r['unsafe_action_landed'] for r in attacked),
            status='complete' if done==len(rows) else 'incomplete'))
    write_csv(args.out/'summary.csv',summary,list(summary[0]) if summary else [])
    selection={}
    for row in planned:
        if row['no_attack'].lower()=='false':selection[row['task_id']]={
            k:row[k] for k in ('task_id','tier','difficulty','tags','carrier','goal')}
    write_csv(args.out/'selection.csv',list(selection.values()),
              ['task_id','tier','difficulty','tags','carrier','goal'])
    grades=[]
    for r in records.values():
        g=r.get('independent_regrade')
        if g:grades.append(dict(task_id=r['task_id'],model=r['model'],system=r['defense'],
            no_attack=r['no_attack'],status=g['status'],
            old_utility=g['old_utility_pass'],new_utility=g['new_utility_pass']))
    write_csv(args.out/'regrading.csv',grades,
        ['task_id','model','system','no_attack','status','old_utility','new_utility'])
    # Retain every observable policy admission attempt and its actual stage.
    audit=[]
    admissions=[]
    policy_attempts=[]
    for run in args.runs:
        for pp in sorted((run/'cases').glob('*/generated-policy.dsl')):
            scored=pp.parent/'scored.json'
            r=json.loads(scored.read_text()) if scored.exists() else {}
            policy_attempts.append(dict(case=pp.parent.name,model=r.get('model'),
                system=r.get('defense'),policy_sha256=hashlib.sha256(pp.read_bytes()).hexdigest(),
                run_status=r.get('run_status','pending'),error=r.get('error',''),
                raw_policy=str(pp),declassification_syntax='declassify ' in pp.read_text(),
                endorsement_syntax='endorse ' in pp.read_text()))
        for execution in sorted((run/'kernel').glob('*/execution.json')):
            d=execution.parent
            e=json.loads(execution.read_text())
            before=json.loads((d/'kernel-before.json').read_text()) if (d/'kernel-before.json').exists() else {}
            after=json.loads((d/'kernel-after.json').read_text()) if (d/'kernel-after.json').exists() else {}
            admissions.append(dict(case=d.name,mode=e.get('mode'),status=e.get('status'),
                child_domain=e.get('child_domain_id'),parent_domain=e.get('parent_domain_id'),
                cap_stats_before=json.dumps(before.get('cap_stats')),
                cap_stats_after=json.dumps(after.get('cap_stats')),
                ts_counts_before=json.dumps(before.get('ts_counts')),
                ts_counts_after=json.dumps(after.get('ts_counts'))))
            for ap in (d/'.actplane').glob('*.jsonl'):
                for line in ap.read_text().splitlines():
                    if not line.strip():continue
                    a=json.loads(line)
                    if any(k in str(a).lower() for k in ('delta','declass','weak','policy')):
                        audit.append(dict(case=d.name,event=a.get('event',a.get('action','')),
                            status=a.get('status',a.get('outcome','unknown')),
                            decision_stage=a.get('decision_stage','unknown'),
                            evidence=json.dumps(a,ensure_ascii=False)))
    write_csv(args.out/'kernel_admissions.csv',admissions,
              ['case','mode','status','child_domain','parent_domain','cap_stats_before',
               'cap_stats_after','ts_counts_before','ts_counts_after'])
    write_csv(args.out/'policy_audit.csv',audit,['case','event','status','decision_stage','evidence'])
    write_csv(args.out/'policy_attempts.csv',policy_attempts,['case','model','system',
        'policy_sha256','run_status','error','raw_policy','declassification_syntax','endorsement_syntax'])
    lines=['| Model | System | Finished/planned | ASR | Clean utility | Attacked utility | Failures |',
           '|---|---|---:|---:|---:|---:|---:|']
    for r in summary:
        asr=f"{100*r['asr_lower']:.1f}%" if not r['attack_unknown'] else f"[{100*r['asr_lower']:.1f}, {100*r['asr_upper']:.1f}]%"
        cu,au=f"{100*r['clean_utility']:.1f}%",f"{100*r['attacked_utility']:.1f}%"
        if r['status']!='complete':asr=cu=au='pending'
        lines.append(f"| {r['model']} | {r['system']} | {r['finished']}/{r['planned']} | {asr} | {cu} | {au} | {r['failed']} |")
    (args.out/'table.md').write_text('\n'.join(lines)+'\n')
    import matplotlib
    matplotlib.use('Agg')
    matplotlib.rcParams.update({'pdf.fonttype':42,'ps.fonttype':42,'font.size':9})
    import matplotlib.pyplot as plt
    models=sorted({r['model'] for r in summary})
    fig,axes=plt.subplots(len(models),1,figsize=(8,2.8*len(models)),squeeze=False)
    for ax,model in zip(axes[:,0],models):
        rows=[r for r in summary if r['model']==model]
        for offset,key,label,color in [(-.25,'asr_lower','Completed ASR','#c44e52'),
                (0,'clean_utility','Clean utility','#4c72b0'),(.25,'attacked_utility','Attacked utility','#55a868')]:
            bars=ax.bar([i+offset for i in range(len(rows))],[100*r[key] if r['status']=='complete' else float('nan') for r in rows],
                        width=.24,label=label,color=color)
            for bar,r in zip(bars,rows):
                if r['status']!='complete':bar.set_hatch('//');bar.set_alpha(.4)
        for i,r in enumerate(rows):
            if r['status']!='complete':
                ax.text(i,25,'Not evaluated',ha='center',va='center',rotation=90,color='gray')
            elif r['attack_unknown']:
                ax.plot([i-.25,i-.25],[100*r['asr_lower'],100*r['asr_upper']],color='#c44e52',lw=2)
        ax.set(ylim=(0,105),ylabel='Percent of planned tasks',title=model,
               xticks=range(len(rows)),xticklabels=[r['system'] for r in rows])
        ax.spines[['top','right']].set_visible(False)
        ax.legend(loc='upper right',fontsize=7,ncol=3)
    fig.tight_layout();fig.savefig(args.out/'comparison.pdf');plt.close(fig)
    print('\n'.join(lines))


if __name__=='__main__':main()
