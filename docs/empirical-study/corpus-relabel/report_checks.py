"""Workspace-only agreement statistics and final review decision; never edits labels."""
import csv, hashlib, itertools, json, math
from collections import Counter
from pathlib import Path
HERE=Path(__file__).resolve().parent
AXES=['type','topic','enforceability','context_required']

def read(p):
    with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))

def write(p,rows):
    with p.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)

def scores(a,b):
    n=len(a); observed=sum(x==y for x,y in zip(a,b))/n
    ca,cb=Counter(a),Counter(b);expected=sum(ca[k]*cb[k] for k in ca)/(n*n)
    return observed, (observed-expected)/(1-expected) if expected<1 else float('nan')

def applicable(r,k):
    return k in ('type','topic') or r['type']=='directive' and (k=='enforceability' or r['enforceability']!='semantic_only')

def table(rows,keys):
    return '\n'.join(['| '+' | '.join(keys)+' |','|'+'|'.join('---' for _ in keys)+'|']+['| '+' | '.join(f'{r[k]:.4f}' if isinstance(r[k],float) else str(r[k]) for k in keys)+' |' for r in rows])

def main():
    baseline={r['metric']:r for r in read(HERE/'baseline_numbers.csv') if r['cohort']=='primary'}
    for r in read(HERE/'numbers.csv'):
        assert float(r['current_merged_value'])==float(baseline[r['metric']]['value']),r['metric']
    original=(HERE/'.inputs'/'plot_empirical.original.py').read_text()
    expected=original.replace("    'figure.dpi': 300,","    'figure.dpi': 300,\n    'pdf.fonttype': 42,\n    'ps.fonttype': 42,").replace("os.path.dirname(__file__), '..', 'figures'","os.path.dirname(__file__), 'figures'")
    assert (HERE/'plot_empirical.py').read_text()==expected
    for r in read(HERE/'validation_hashes.csv'):
        assert hashlib.sha256((HERE/r['path']).read_bytes()).hexdigest()==r['sha256'],r['path']
    statistics=[];differences=[];exacts=[]
    def compare(kind,left_name,right_name,left,right):
        assert len(left)==len(right) and len({r['statement_id'] for r in left})==len(left)
        li={r['statement_id']:r for r in left};ri={r['statement_id']:r for r in right};assert set(li)==set(ri)
        ids=sorted(li)
        for scope in ('all_with_inapplicable','reference_applicable'):
            for k in AXES:
                use=[sid for sid in ids if scope=='all_with_inapplicable' or applicable(li[sid],k)]
                a=[li[sid][k] for sid in use];b=[ri[sid][k] for sid in use];agree,kappa=scores(a,b)
                statistics.append(dict(check=kind,left=left_name,right=right_name,label=k,scope=scope,n=len(use),agreement=agree,kappa=kappa,change_rate=1-agree))
        exact=sum(all(li[s][k]==ri[s][k] for k in AXES) for s in ids)/len(ids)
        exacts.append(dict(check=kind,left=left_name,right=right_name,n=len(ids),exact_match_rate=exact))
        for sid in ids:
            for k in AXES:
                if li[sid][k]!=ri[sid][k]:differences.append(dict(check=kind,left=left_name,right=right_name,statement_id=sid,label=k,reference=li[sid][k],prediction=ri[sid][k],text=li[sid].get('text',''),reason=ri[sid].get('reason','')))
    for cohort in ('added','original'):
        base=read(HERE/f'common_{cohort}_300.csv');proc={i:read(HERE/'checks'/f'procedure{i}'/cohort/'labels.csv') for i in (1,2,3)}
        for i,j in itertools.combinations(proc,2):compare(f'pairwise_{cohort}',f'procedure{i}',f'procedure{j}',proc[i],proc[j])
        if cohort=='original':
            for i in proc:compare('original_reference','original',f'procedure{i}',base,proc[i])
    obj=json.loads((HERE/'checks'/'claude'/'response.json').read_text(encoding='utf-8-sig'))
    text=obj.get('result','');structured=obj.get('structured_output')
    if not structured:
        if text.strip().startswith('```'):text=text.strip().split('\n',1)[1].rsplit('```',1)[0]
        structured=json.loads(text)
    labels=structured['rows'];base=read(HERE/'claude_sample.csv')
    provenance=dict(original_reference='63db86945c9b8618a46aa68c8de214bc4b8343d9',codex_model='gpt-5.6-sol',claude_model_usage=obj.get('modelUsage',obj.get('model_usage',{})),claude_stop_reason=obj.get('stop_reason'),claude_cli_duration_ms=obj.get('duration_ms'),hashes={})
    paths=[HERE/'common_added_300.csv',HERE/'common_original_300.csv',HERE/'claude_sample.csv']
    for i,name in [(1,'shared_codebook.txt'),(2,'shared_codebook.txt'),(3,'common-instructions.txt')]:
        paths.extend([HERE/f'shard{i}'/'run_review.py',HERE/f'shard{i}'/name])
    for p in paths:provenance['hashes'][str(p.relative_to(HERE))]=hashlib.sha256(p.read_bytes()).hexdigest()
    (HERE/'check_provenance.json').write_text(json.dumps(provenance,indent=2),encoding='utf-8')
    topics={r['topic'] for r in read(HERE/'reviewed_all.csv')}
    for r in labels:
        assert set(['statement_id',*AXES])<=set(r)
        t,p,e,c=[r[k] for k in AXES]
        assert p in topics
        assert (t=='description' and e==c=='') or (t=='directive' and e in ('semantic_only','content','per_event','cross_event') and ((e=='semantic_only' and c=='') or (e!='semantic_only' and c in ('none','project','task'))))
    write(HERE/'checks'/'claude'/'labels.csv',labels)
    compare('claude_crosscheck','reviewed','claude',base,labels)
    write(HERE/'agreement.csv',statistics);write(HERE/'exact_match.csv',exacts)
    if differences:write(HERE/'disagreements.csv',differences)
    relevant=[r for r in statistics if r['check'] in ('pairwise_added','original_reference') and r['scope']=='reference_applicable']
    failures=[r for r in statistics if r['check'] in ('pairwise_added','original_reference') and (not math.isfinite(r['kappa']) or r['kappa']<.8)]
    rank=[]
    for i in (1,2,3):
        rs=[r for r in relevant if r['check']=='original_reference' and r['right']==f'procedure{i}']
        pair=[r for r in relevant if r['check']=='pairwise_added' and f'procedure{i}' in (r['left'],r['right'])]
        rank.append(dict(procedure=f'procedure{i}',minimum_original_kappa=min(r['kappa'] for r in rs),mean_original_kappa=sum(r['kappa'] for r in rs)/4,mean_pairwise_kappa=sum(r['kappa'] for r in pair)/len(pair)))
    rank.sort(key=lambda r:(r['mean_original_kappa'],r['mean_pairwise_kappa']),reverse=True)
    best=rank[0]['procedure']
    if failures:
        failedprocs=sorted({r['right'] for r in failures if r['check']=='original_reference'})
        decision=f'DO NOT ACCEPT the merged reviewed labels as method-consistent. Original-reference failures: {", ".join(failedprocs) or "none"}. Best relative agreement: {best}. '
        if len(failedprocs)==3:decision+=f'All three procedures deviate from the original reference. Recommend re-running all affected shards with {best} only after its remaining original-reference failures are resolved and independently revalidated. Its relative ranking is not a pass. No shard was re-run.'
        else:decision+=f'Recommend re-running affected shards with {best}, subject to the per-label results below. No shard was re-run.'
    else:decision='KEEP the merged reviewed labels: all required applicable-label kappas meet 0.80 against each other and the original labels.'
    methodology='The original study reports an estimated 5–8% post-correction error rate but explicitly says no formal inter-rater agreement. No original per-label kappa or reusable double-annotation table was recovered. The operational bar is therefore the requested kappa >= 0.80 on every label, using all rows for type/topic, original directives for enforcement, and original system-observable directives for context. Predicted inapplicability counts as disagreement. Pairwise applicability is conditioned on the left procedure; the all-row scores additionally count empty labels as a category and are fully symmetric. Exact match requires all four labels. The decision uses pairwise added-sample and original-reference checks; pairwise original-sample checks are also reported.'
    procedure='Each original runner file and stored instruction text was imported/read unchanged. Only the output-directory global was redirected. Original 150-row batch sizes, schemas, model, CLI flags, validation and retry functions were retained (two simultaneous batches per procedure per cohort). There were no post-return semantic adjudications in this check. Shards 1 and 2 had such adjudications in their original completed labels, so this checks the automated procedures, not those additional interventions. Procedure 3 retains access to all 64 reference YAMLs. Worked examples embedded in any of the three prompts were excluded by exact text from the original sample; the complete original reference remained available to procedure 3 by its unchanged design, so this is not a blinded holdout.'
    mismatch='Method identity cannot be certified. Historical sections name Claude Opus 4.6, temperature 0 and a fixed seed; the three review runners use Codex gpt-5.6-sol with their configured reasoning/default sampling and different examples/output instructions. The added corpus also has broader discovery, eligibility, eight file families, automated segmentation, and different first-pass annotators (documented in corpus-merge/README.md). These differences predate this task. Counts below describe the requested frozen merge and must not be presented as a validated same-method replication if the consistency gate fails.'
    report='# Procedure consistency and original-reference checks\n\n'+decision+'\n\n'+methodology+'\n\n'+procedure+'\n\n'+mismatch+'\n\n## Applicable-label agreement\n\n'+table([r for r in statistics if r['scope']=='reference_applicable'],['check','left','right','label','n','agreement','kappa','change_rate'])+'\n\n## Exact four-label agreement\n\n'+table(exacts,['check','left','right','n','exact_match_rate'])+'\n\n## Procedure ranking (selection uses this diagnostic sample)\n\n'+table(rank,['procedure','minimum_original_kappa','mean_original_kappa','mean_pairwise_kappa'])+'\n\nAll full-denominator and applicable-denominator results are in agreement.csv. Every changed label and returned rationale is in disagreements.csv. Claude cross-check is independent of Codex and did not change any label. Original labels are a reference convention, not human ground truth. Stratified agreement is sample-conditional, not an estimate of corpus prevalence. Both all-row and applicable-label scores must meet the decision bar. Claude CLI response metadata (including model usage) is retained in checks/claude/response.json.\n'
    interpretation='The main failures affect all three procedures: added-sample context kappas are 0.610–0.710 between procedures. Against original labels, enforcement kappas are 0.556–0.571 and context kappas 0.349–0.478. Procedure 2 also misses the type threshold (0.7875). The historical estimated 5–8% error band implies roughly 92–95% raw agreement; original-reference enforcement agreement here is only 67.3–68.2%, so the decision also fails that historical bar. These diagnostics do not isolate a single faulty shard. The independent Claude check used first-party claude-opus-5-5 and has 79% exact four-label agreement, without changing labels.'
    report=report.replace(decision+'\n\n',decision+'\n\n'+interpretation+'\n\n',1)
    (HERE/'CHECK.md').write_text(report,encoding='utf-8')
    nums=read(HERE/'numbers.csv')
    def fmt(v,unit):
        if v in ('','unavailable'):return v
        x=float(v);return f'{100*x:.1f}%' if unit.startswith('fraction') else f'{x:,.1f}' if not x.is_integer() else f'{int(x):,}'
    comparison=[dict(Measure=r['label'],Paper=r['paper_value'],Current=fmt(r['current_merged_value'],r['unit']),Reviewed=fmt(r['reviewed_value'],r['unit'])) for r in nums]
    changes=read(HERE/'change_counts.csv')
    if not any(r['shard']=='all' for r in changes):
        for k in AXES+['any','boundary']:
            n=sum(int(r['changed']) for r in changes if r['label']==k and r['shard']!='all')
            changes.append(dict(shard='all',label=k,changed=n,total=27601,rate=n/27601))
        write(HERE/'change_counts.csv',changes)
    claude_stats=[r for r in statistics if r['check']=='claude_crosscheck' and r['scope']=='reference_applicable']
    summary='# Reviewed merged study\n\n'+decision+'\n\nValidated 27,601 added statements exactly once across 298 repositories. The requested merge has 29,717 statements in 362 repositories, retaining all 2,116 original labels from 64 repositories (including the 27 overlaps). Original reference: origin/artifact-ready = 63db86945c9b8618a46aa68c8de214bc4b8343d9.\n\n'+mismatch+'\n\n## Recomputed numbers\n\nThese are the requested reviewed-label results even when the consistency gate rejects their adoption. Numerators, denominators, unrounded values and 95% intervals are in numbers.csv. Calculations call corpus-merge/analyze_merge.py metrics unchanged, including its 10,000 whole-repository bootstrap draws and seed 20261029. Original plot script is copied byte-for-byte from corpus-merge; four PDFs and PNG previews are under figures/, with Type 42 settings and pdffonts evidence.\n\n'+table(comparison,['Measure','Paper','Current','Reviewed'])+'\n\n## First-pass changes\n\n'+table(changes,['shard','label','changed','total','rate'])+'\n\n## Independent Claude cross-check\n\n'+table(claude_stats,['label','n','agreement','kappa','change_rate'])+'\n\nSee CHECK.md, agreement.csv, exact_match.csv and disagreements.csv for the complete procedure results and individual Claude disagreements. Claude labels never replace the reviewed labels. review_sample.csv contains a separate 100-statement author sample with empty verdicts.\n\n## Reproduction and evidence\n\nRun prepare_study.py and report_checks.py through ws.sh run corpus-relabel with the existing corpus-merge virtualenv. Run run_checks.py locally for model calls. The model adapter retains every original runner and prompt, changes only output paths, and uses 150 statements per batch. Sampling seeds, allocation and example exclusions are retained in sampling.json and excluded_worked_examples.csv. All samplings use equal allocation across populated type/tier/topic strata with repository round robin within strata, without replacement. This deliberately emphasizes uncommon categories. Original sample excludes all embedded worked-example text. The two 100-statement samples use reviewed-label strata.\n\nInputs for offline reproduction are the unchanged corpus-merge/.inputs staged snapshot (copy to .inputs here), verified against source_hashes.csv, plus the retained shard inputs/outputs. Source input payloads are already versioned in corpus-scale and original YAML snapshots are retained in the shard directories. Large raw CLI logs are excluded; structured batch inputs, outputs, runners, schemas and instructions remain versioned. No paper repository edits, full-shard reruns, pull, rebase or PR.\n'
    summary=summary.replace(decision+'\n\n',decision+'\n\n'+interpretation+'\n\n',1)
    summary+='\nFinal checks: all 45 current-merge values match baseline_numbers.csv exactly; original runner and reviewed.csv hashes are unchanged; the plot script differs from the original only in the documented output directory and Type 42 settings. Source text comparisons across the first-pass export normalize CRLF/LF only, while each shard input versus reviewed output requires exact field equality. Figure previews were visually inspected: original legend overlays and the long-label clipping in figure 3 are retained. Workspace timestamps are approximately 10 minutes ahead of the local host, so cross-host file times are not used as elapsed-time evidence.\n'
    (HERE/'SUMMARY.md').write_text(summary,encoding='utf-8')
    print(decision,flush=True);print(table(rank,['procedure','minimum_original_kappa','mean_original_kappa','mean_pairwise_kappa']),flush=True)

if __name__=='__main__':main()
