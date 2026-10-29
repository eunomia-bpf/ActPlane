import concurrent.futures as cf
import csv
import datetime as dt
import json
from pathlib import Path
import time
import run_review as r

TASK_START = dt.datetime(2026,10,29,22,55,35,tzinfo=dt.timezone.utc).timestamp()
r.START = TASK_START
OUT = r.OUT
common = (OUT/'common-instructions.txt').read_text(encoding='utf-8')
with r.INPUT.open(encoding='utf-8-sig',newline='') as f:
    reader=csv.DictReader(f)
    columns=reader.fieldnames
    rows=list(reader)
batches=[rows[i:i+150] for i in range(0,len(rows),150)]
started={int(f.name.split('-')[1].split('.')[0]) for f in OUT.glob('batch-*.input.json')}
done={int(f.name.split('-')[1].split('.')[0]) for f in OUT.glob('batch-*.validated.json')}
active=started-done
pending=set(range(1,len(batches)+1))-started
print(json.dumps({'preserved_validated':sorted(done),'preserved_active':sorted(active),'launch_pending':sorted(pending)}),flush=True)

def harvest(number):
    batch=batches[number-1]
    stem=f'batch-{number:03d}'
    last_error=None
    while True:
        targets=sorted(OUT.glob(f'{stem}.attempt-*.json'),key=lambda p:p.stat().st_mtime,reverse=True)
        for target in targets:
            # Only outputs of the supported-model run; earlier run never returned labels.
            if target.stat().st_mtime < dt.datetime(2026,10,29,23,0,5,tzinfo=dt.timezone.utc).timestamp():
                continue
            try:
                data=json.loads(target.read_text(encoding='utf-8-sig'))
                reviewed=r.validate(batch,data)
                (OUT/f'{stem}.validated.json').write_text(json.dumps(list(reviewed.values()),ensure_ascii=False),encoding='utf-8')
                print(json.dumps({'batch':number,'harvested':len(reviewed),'seconds':round(time.time()-TASK_START)}),flush=True)
                return number,reviewed,[]
            except Exception as exc:
                last_error=str(exc)
        # A retry already running must be allowed to finish rather than duplicated.
        logs=[p for p in OUT.glob(f'{stem}.attempt-*.log') if p.stat().st_mtime >= dt.datetime(2026,10,29,23,0,5,tzinfo=dt.timezone.utc).timestamp()]
        if logs:
            latest=max(logs,key=lambda p:p.stat().st_mtime)
            text=latest.read_text(encoding='utf-8',errors='replace')
            # Codex prints a final token count after finishing; invalid finished batches are retried only.
            if 'tokens used' in text and time.time()-latest.stat().st_mtime>4:
                if last_error:
                    print(json.dumps({'batch':number,'retry_invalid':last_error}),flush=True)
                    return r.review_batch(number,batch,common)
        time.sleep(2)

reviewed={}
for number in sorted(done):
    vals=json.loads((OUT/f'batch-{number:03d}.validated.json').read_text(encoding='utf-8'))
    decisions={'rows':[[x['statement_id'],*[x[k+'_r'] for k in r.LABELS],x['reason']] for x in vals]}
    reviewed.update(r.validate(batches[number-1],decisions))
errors={}
failed=[]
with cf.ThreadPoolExecutor(max_workers=64) as pool:
    jobs=[pool.submit(harvest,n) for n in sorted(active)]
    jobs += [pool.submit(r.review_batch,n,batches[n-1],common) for n in sorted(pending)]
    for future in cf.as_completed(jobs):
        n,data,err=future.result()
        if err: errors[n]=err
        if data is None: failed.append(n)
        else:
            assert not set(reviewed).intersection(data)
            reviewed.update(data)
        (OUT/'progress.json').write_text(json.dumps({'reviewed':len(reviewed),'total':len(rows),'completed_batches':len(list(OUT.glob('batch-*.validated.json'))),'failed_batches':failed,'elapsed_seconds':round(time.time()-TASK_START),'retry_errors':errors},indent=2),encoding='utf-8')
missing=[x['statement_id'] for x in rows if x['statement_id'] not in reviewed]
assert not missing,(len(missing),failed)
fields=columns+[k+'_r' for k in r.LABELS]+['changed','reason']
with (OUT/'reviewed.csv').open('w',encoding='utf-8',newline='') as f:
    writer=csv.DictWriter(f,fieldnames=fields)
    writer.writeheader()
    writer.writerows(reviewed[x['statement_id']] for x in rows)
with (OUT/'reviewed.csv').open(encoding='utf-8',newline='') as f:
    final=list(csv.DictReader(f))
assert len(final)==len(rows)
assert len({x['statement_id'] for x in final})==len(rows)
assert all(all(a[k]==b[k] for k in columns) for a,b in zip(rows,final))
changes={k:sum(x[k]!=x[k+'_r'] for x in final) for k in r.LABELS}
boundary=sum(x['reason'].lower().startswith('boundary:') for x in final)
elapsed=time.time()-TASK_START
status=f'''# Shard 3 second-pass review

- Statements reviewed: {len(final)} / {len(rows)}
- Rows changed (any label): {sum(x['changed']=='true' for x in final)}
- Type changes: {changes['type']}
- Topic changes: {changes['topic']}
- Enforceability changes: {changes['enforceability']}
- Context-required changes: {changes['context_required']}
- Boundary flags (spans unchanged): {boundary}
- Failed or missing rows: {len(missing)}
- Failed batches remaining: {failed}
- Wall-clock time, including setup and startup recovery: {elapsed:.1f} seconds ({elapsed/60:.2f} minutes)
- Task start UTC: {dt.datetime.fromtimestamp(TASK_START,dt.timezone.utc).isoformat()}
- Finished UTC: {dt.datetime.now(dt.timezone.utc).isoformat()}
- Model: Codex CLI gpt-5.6-sol, configured high reasoning. Default gpt-6.1-sol was unsupported by the authenticated account; its startup attempts returned no annotations.
- Parallel execution: initially 16 Codex child processes; remaining unstarted batches launched concurrently to meet the deadline, preserving active calls and validated outputs. {len(batches)} batches, normally 150 statements each.
- Definitions: identical taxonomy.txt, original empirical.md sections 4.2-4.5, and actual worked examples from all 64 original repositories. Full original YAML snapshots retained in original-examples/.
- Review: individual semantic decisions on all four labels; no keyword/pattern label assignment or re-segmentation. Only failed or invalid batches retried.
- Validation: every statement_id exactly once; exact legal values and applicability; changed flags/reasons checked; all original columns/text/spans preserved in original order; final CSV round trip verified.
- Git: read-only show/ls-tree solely for requested definitions/examples; no Git state mutation, commit, push, pull, or paper edits.
'''
(OUT/'STATUS.md').write_text(status,encoding='utf-8')
print(status,flush=True)
