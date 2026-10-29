"""Offline validation, sampling and unchanged merged-study calculations (Workspace)."""
import ast, csv, hashlib, importlib.util, json, random, shutil, sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
MERGE = Path('/workspaces/exp/corpus-merge/src')
AXES = ['type', 'topic', 'enforceability', 'context_required']
SEED = 20261029

def read(p):
    with p.open(encoding='utf-8-sig', newline='') as f: return list(csv.DictReader(f))

def write(p, rows):
    with p.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n'); w.writeheader(); w.writerows(rows)

def sample(rows, n, seed):
    """Equal allocation to populated type/tier/topic strata, round-robin repositories."""
    rng = random.Random(seed); strata = defaultdict(lambda: defaultdict(list))
    for r in rows: strata[(r['type'], r['enforceability'], r['topic'])][r['repo']].append(r)
    pools = []
    for key in sorted(strata):
        repos = list(strata[key].values()); rng.shuffle(repos)
        for rs in repos: rng.shuffle(rs)
        pool = []
        while any(repos):
            for rs in repos:
                if rs: pool.append(rs.pop())
        pools.append(pool)
    selected = []
    while len(selected) < n:
        for pool in pools:
            if pool and len(selected) < n: selected.append(pool.pop(0))
    rng.shuffle(selected)
    return selected

def main():
    spec = importlib.util.spec_from_file_location('merge', MERGE/'analyze_merge.py'); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    m.INPUT=HERE/'.inputs'; m.SCALE=m.INPUT/'scale'
    tree=ast.parse((MERGE/'plot_empirical.py').read_text())
    cfg={n.targets[0].id:ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('COLLAPSE','TOPIC_ORDER','ENF_LEVELS','CTX_LEVELS')}
    old, om, new, nm, shared = m.load_inputs(cfg['COLLAPSE'])
    source_index={r['statement_id']:r for r in read(m.SCALE/'statements.csv')}
    for r in new:
        for k,v in source_index[r['statement_id']].items():
            if k not in r:r[k]=v
    for r in old+new: r['topic'] = cfg['COLLAPSE'].get(r['topic'], r['topic'])
    first = {r['statement_id']:r for r in new if r['key'] not in om}
    allrows = []; counts = []; manifests = []
    for i in (1,2,3):
        source = read(HERE/'shards'/f'shard{i}.csv'); reviewed = read(HERE/f'shard{i}'/'reviewed.csv')
        assert len(source)==len(reviewed) and len({r['statement_id'] for r in reviewed})==len(source)
        assert [r['statement_id'] for r in source]==[r['statement_id'] for r in reviewed]
        for a,b in zip(source,reviewed):
            assert all(a[k]==b[k] for k in a)
            ref=first[a['statement_id']]
            assert all(a[k]==ref[k] for k in a if k!='text'), a['statement_id']
            assert a['text'].replace('\r\n','\n')==ref['text'].replace('\r\n','\n'), a['statement_id']
            ref['text']=a['text']  # Preserve shard text exactly; source CSV has mixed CRLF/LF.
            t,p,e,c = [b[k+'_r'] for k in AXES]
            assert t in ('description','directive') and p in cfg['TOPIC_ORDER']
            assert (t=='description' and e==c=='') or (t=='directive' and e in cfg['ENF_LEVELS'] and ((e=='semantic_only' and c=='') or (e!='semantic_only' and c in cfg['CTX_LEVELS'])))
            changed = any(b[k]!=b[k+'_r'] for k in AXES)
            assert b['changed'].lower()==str(changed).lower()
            assert not changed or b['reason'].strip()
        allrows.extend(reviewed)
        for axis in AXES+['any','boundary']:
            num = sum(any(r[k]!=r[k+'_r'] for k in AXES) if axis=='any' else 'boundary' in r['reason'].lower() if axis=='boundary' else r[axis]!=r[axis+'_r'] for r in reviewed)
            counts.append(dict(shard=i,label=axis,changed=num,total=len(reviewed),rate=num/len(reviewed)))
        for name in ('reviewed.csv','run_review.py'):
            p=HERE/f'shard{i}'/name; manifests.append(dict(path=str(p.relative_to(HERE)),sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
    assert len(allrows)==27601 and len({r['statement_id'] for r in allrows})==27601 and {r['statement_id'] for r in allrows}==set(first)
    for axis in AXES+['any','boundary']:
        num=sum(r['changed'] for r in counts if r['label']==axis)
        counts.append(dict(shard='all',label=axis,changed=num,total=len(allrows),rate=num/len(allrows)))
    write(HERE/'reviewed_all.csv',allrows); write(HERE/'change_counts.csv',counts); write(HERE/'validation_hashes.csv',manifests)
    examples=set(); example_rows=[]
    markers=['ORIGINAL WORKED EXAMPLES, selected across all 64 original files (verbatim statement text and labels)\n','ORIGINAL WORKED EXAMPLES (one from every original repository, plus axis combinations):\n','=== ACTUAL WORKED EXAMPLE FROM EACH OF 64 ORIGINAL REPOSITORIES ===\n']
    for i,name in [(1,'shared_codebook.txt'),(2,'shared_codebook.txt'),(3,'common-instructions.txt')]:
        text=(HERE/f'shard{i}'/name).read_text(encoding='utf-8')
        data=json.JSONDecoder().raw_decode(text.split(markers[i-1],1)[1].lstrip())[0]
        for ex in data:
            examples.add(ex['text']); example_rows.append(dict(procedure=i,source=ex['source'],text=ex['text']))
    write(HERE/'excluded_worked_examples.csv',example_rows)
    original=[{k:v for k,v in r.items() if k!='key'} for r in old if r['text'] not in examples]
    assert len(original)>=300
    write(HERE/'common_added_300.csv',sample(list(first.values()),300,SEED))
    write(HERE/'common_original_300.csv',sample(original,300,SEED+1))
    reviewed=[]
    for r in allrows:
        v=dict(first[r['statement_id']]); v.update({k:r[k+'_r'] for k in AXES}); reviewed.append(v)
    human=sample(reviewed,100,SEED+2)
    write(HERE/'review_sample.csv',[{**{k:r[k] for k in ['statement_id','repo','file_path','start_line','end_line','text']+AXES},'verdict':''} for r in human])
    write(HERE/'claude_sample.csv',sample(reviewed,100,SEED+3))
    (HERE/'sampling.json').write_text(json.dumps(dict(seed=SEED,allocation='equal populated type/enforceability/topic strata; repository round robin within strata; without replacement',original_eligible=len(original),excluded_original_texts=len(examples),added_repositories=298,original_repositories=64),indent=2))
    metadata={**nm,**om}; merged=old+reviewed
    current=m.metrics(old+list(first.values()),metadata,cfg['TOPIC_ORDER'])
    result=m.metrics(merged,metadata,cfg['TOPIC_ORDER'])
    oldresult=m.metrics(old,om,cfg['TOPIC_ORDER'])
    rows=[]
    for a,b,c in zip(current,result,oldresult):
        assert a['metric']==b['metric']==c['metric']
        rows.append(dict(metric=b['metric'],label=b['label'],unit=b['unit'],paper_value=b['paper_value'],current_merged_value=a['value'],reviewed_value=b['value'],numerator=b['numerator'],denominator=b['denominator'],ci_low=b['ci_low'],ci_high=b['ci_high'],original_64_value=c['value']))
    write(HERE/'numbers.csv',rows)
    write(HERE/'plot_numbers.csv',[dict(cohort='primary',**r) for r in result])
    layout=HERE/'layout'; layout.mkdir(exist_ok=True); grouped=defaultdict(list)
    for r in merged: grouped[r['key']].append({k:r[k] for k in AXES})
    import yaml
    for key,rs in grouped.items():
        p=layout/key.replace('/','__'); p.mkdir(exist_ok=True); (p/'statements.yaml').write_text(yaml.safe_dump(dict(statements=rs),sort_keys=False))
    shutil.copyfile(MERGE/'plot_empirical.py',HERE/'plot_empirical.py')
    text=(MERGE/'verify_figures.py').read_text().replace("root / 'numbers.csv'","root / 'plot_numbers.csv'")
    (HERE/'verify_figures.py').write_text(text)
    (HERE/'environment.txt').write_text((MERGE/'environment.txt').read_text()+'\nRecomputed in actplane-dev /workspaces/exp/corpus-relabel/src\n')
    print(json.dumps(dict(validated=len(allrows),merged=len(merged),repositories=len(metadata),original_eligible=len(original),metrics=len(rows))),flush=True)

if __name__=='__main__': main()
