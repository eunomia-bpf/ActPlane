"""Recover complete model final messages while CLI shutdown is still pending."""
import json
from pathlib import Path
import run_review as r

out=r.OUT
for log in out.glob('batch-*.attempt-*.log'):
    stem=log.name.split('.attempt-')[0]
    target=out/(stem+'.validated.json')
    if target.exists():
        continue
    text=log.read_text(encoding='utf-8',errors='replace')
    marker='\ncodex\n'
    if marker not in text:
        continue
    final=text.rsplit(marker,1)[1].lstrip()
    try:
        data,end=json.JSONDecoder().raw_decode(final)
        batch=json.loads((out/(stem+'.input.json')).read_text(encoding='utf-8'))
        reviewed=r.validate(batch,data)
    except (ValueError,KeyError,AssertionError,TypeError) as exc:
        print(stem,'not valid:',str(exc)[:160],flush=True)
        continue
    raw=out/log.name.replace('.log','.json')
    if not raw.exists():
        raw.write_text(json.dumps(data,ensure_ascii=False),encoding='utf-8')
    target.write_text(json.dumps(list(reviewed.values()),ensure_ascii=False),encoding='utf-8')
    print(stem,'recovered and validated',len(reviewed),flush=True)
