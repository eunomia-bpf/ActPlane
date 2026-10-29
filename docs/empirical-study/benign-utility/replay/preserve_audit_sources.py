"""Retain forensic source bytes before deleting rebuildable runtime payloads."""
import csv
import hashlib
import json
import os
from pathlib import Path
import tarfile
import sys
from open_audit import match

ROOT = Path(os.environ['WS_RAW']) / 'replay'
OUT = ROOT.parent.parent / 'replay/results'


def preserve(run, relative, data, records):
    digest = hashlib.sha256(data).hexdigest()
    target = run / 'retained-audit-source-bytes' / digest
    target.parent.mkdir(exist_ok=True)
    if target.exists() and target.read_bytes() != data:
        raise RuntimeError('Retained byte mismatch')
    target.write_bytes(data)
    records[relative] = dict(sha256=digest, bytes=len(data), retained=str(target.relative_to(run)))


def main():
    candidates = list(csv.DictReader((OUT / 'open-audit-candidates.csv').open()))
    plans = {r['dynamic_id']:r for r in csv.DictReader((OUT/'cohort.csv').open())}
    retained_rows=[]
    for run in sorted(ROOT.glob('open-audit-*/dynamic/runs/t*')):
        if not (run/'done.json').exists():
            continue
        manifest = run/'retained-audit-source-manifest.json'
        records = json.loads(manifest.read_text()) if manifest.exists() else {}
        workdir = plans[run.name]['sandbox_workdir']
        wanted = set()
        for row in candidates:
            if row['audit_condition'] != run.parents[2].name or row['dynamic_id'] != run.name:
                continue
            for path in (row['resolved_path'], row['raw_path']):
                for prefix, directory in ((workdir,'repo'),('/venv','venv'),('/root','home'),('/tmp','tmp'),('/cache','cache')):
                    if path == prefix or path.startswith(prefix+'/'):
                        wanted.add(directory+path[len(prefix):])
                        break
        rules = [r for r in json.loads((run/'compiled-sources.json').read_text()) if r['label']=='SECRET']
        for archive_name in (() if '--verify-only' in sys.argv else ('runtime.tar.gz','runtime-cache.tar.gz')):
            archive = run/archive_name
            if not archive.exists():
                continue
            # One sequential pass avoids repeated seeks through multi-GB gzip files.
            with tarfile.open(archive,'r|gz') as stream:
                for member in stream:
                    name = member.name.removeprefix('./')
                    if not member.isfile():
                        continue
                    prefix, _, tail = name.partition('/')
                    sandbox = {'repo':workdir,'venv':'/venv','home':'/root','tmp':'/tmp','cache':'/cache'}.get(prefix)
                    path = (sandbox+'/'+tail) if sandbox else ''
                    if name in wanted or (path and any(match(path.encode()[:126],r) for r in rules)):
                        preserve(run,name,stream.extractfile(member).read(),records)
        for relative in wanted:
            file = run/relative
            if file.is_file():
                preserve(run,relative,file.read_bytes(),records)
        for row in candidates:
            if (row['audit_condition'],row['dynamic_id'])!=(run.parents[2].name,run.name) or not row['retained_sha256']:
                continue
            path=row['resolved_path'] or row['raw_path']
            for prefix,directory in ((workdir,'repo'),('/venv','venv'),('/root','home'),('/tmp','tmp'),('/cache','cache')):
                if path==prefix or path.startswith(prefix+'/'):
                    entry=records.get(directory+path[len(prefix):])
                    if not entry or entry['sha256']!=row['retained_sha256']:
                        raise RuntimeError('Candidate byte preservation failed: '+str(run)+' '+path)
                    break
        manifest.write_text(json.dumps(records,indent=2,sort_keys=True)+'\n')
        for relative, record in sorted(records.items()):
            if hashlib.sha256((run/record['retained']).read_bytes()).hexdigest()!=record['sha256']:
                raise RuntimeError('Retained source hash mismatch')
            retained_rows.append(dict(audit_condition=run.parents[2].name,dynamic_id=run.name,
                original_runtime_relative_path=relative,**record))
        print(run.name,len(records),'retained sources',flush=True)
    with (OUT/'retained-audit-sources.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=['audit_condition','dynamic_id','original_runtime_relative_path','sha256','bytes','retained'])
        writer.writeheader();writer.writerows(retained_rows)


if __name__ == '__main__':
    main()
