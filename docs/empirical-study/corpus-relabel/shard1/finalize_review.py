import csv, datetime, hashlib, json, pathlib, re, time
from run_review import LABELS, TOPICS, validate

HERE = pathlib.Path(__file__).resolve().parent
source = HERE.parent/'shards/shard1.csv'
original = list(csv.DictReader(source.open(encoding='utf-8-sig',newline='')))
reviewed = list(csv.DictReader((HERE/'reviewed.csv').open(encoding='utf-8',newline='')))
assert len(original) == len(reviewed) == 9201
assert [r['statement_id'] for r in original] == [r['statement_id'] for r in reviewed]
assert len({r['statement_id'] for r in reviewed}) == len(reviewed)
byid = {r['statement_id']:r for r in reviewed}
manual = json.loads((HERE/'manual_adjudications.json').read_text(encoding='utf-8'))
for sid,(enf,ctx,reason) in manual.items():
    row=byid[sid]
    assert row['type_r']=='directive'
    previous=row['reason']
    row['enforceability_r']=enf
    row['context_required_r']=ctx
    row['reason']=reason+(' '+previous if 'boundary:' in previous.lower() else '')

counts={k:0 for k in LABELS}
changed=0
for old,new in zip(original,reviewed):
    assert all(old[k]==new[k] for k in old), old['statement_id']
    this_changed=False
    for k in LABELS:
        if old[k]!=new[k+'_r']:
            counts[k]+=1
            this_changed=True
    new['changed']='true' if this_changed else 'false'
    changed+=this_changed
    if not this_changed and 'boundary:' not in new['reason'].lower(): new['reason']=''
validate(original,{'rows':[[r['statement_id'],*[r[k+'_r'] for k in LABELS],r['reason']] for r in reviewed]})

fields=list(original[0])+[k+'_r' for k in LABELS]+['changed','reason']
temp=HERE/'reviewed.validated.tmp'
with temp.open('w',encoding='utf-8',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(reviewed)
temp.replace(HERE/'reviewed.csv')
reread=list(csv.DictReader((HERE/'reviewed.csv').open(encoding='utf-8',newline='')))
assert reread==reviewed

status=(HERE/'STATUS.md').read_text(encoding='utf-8')
for k,n in counts.items(): status=re.sub(r'(- Rows changed, '+re.escape(k)+r': )\d+\.',lambda m:m[1]+str(n)+'.',status)
status=re.sub(r'(- Rows changed \(any label\): )\d+\.',lambda m:m[1]+str(changed)+'.',status)
boundaries=sum('boundary:' in r['reason'].lower() for r in reviewed)
status=re.sub(r'(- Boundary flags: )\d+',lambda m:m[1]+str(boundaries),status)
retry_batches=[]
for f in (HERE/'batches').glob('*.attempt2.json'):
    if (HERE/'batches'/(f.name[:3]+'.review.json')).exists(): retry_batches.append(f.name[:3])
now=time.time()
setup_started=(HERE/'run_review.py').stat().st_birthtime
status+=f'''\nFinal output audit:\n\n- Codex model: `gpt-5.6-sol`, high reasoning effort, identical for all 62 accepted batches. The configured default `gpt-6.1-sol` was rejected by the account during preflight, before any review result was accepted.\n- Retried batches with returned second-attempt output: {', '.join(sorted(retry_batches)) or 'none'}. Only failed batches were retried.\n- Individually read and adjudicated after return: {len(manual)} specific statements, recorded in `manual_adjudications.json`; explicit reference-file access and a run-command directive were corrected using the codebook's observable-operation rule.\n- Final CSV round-trip and full original-column equality: passed for all {len(reviewed)} rows, including text, repository, path, line spans, and original labels.\n- Final exact statement-ID coverage and uniqueness: passed; missing 0, extra 0, duplicate 0.\n- Final label vocabulary, applicability, changed flags, and reason consistency: passed.\n- Wall-clock from orchestration script creation through final audit: {(now-setup_started):.1f} seconds ({(now-setup_started)/60:.2f} minutes), including local model troubleshooting.\n- Final audit time: {datetime.datetime.now().astimezone().isoformat()}.\n- Reviewed CSV SHA-256: `{hashlib.sha256((HERE/'reviewed.csv').read_bytes()).hexdigest()}`.\n'''
(HERE/'STATUS.md').write_text(status,encoding='utf-8')
print(json.dumps({'reviewed':len(reviewed),'changed_rows':changed,'changed_per_label':counts,'boundary_flags':boundaries,'missing':0,'duplicates':0,'manual_adjudications':len(manual),'wall_seconds_since_setup':round(now-setup_started,1)},indent=2))
