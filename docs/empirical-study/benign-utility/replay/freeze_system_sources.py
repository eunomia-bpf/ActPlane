"""Retain original system-source observations across Workspace restarts.

Input is the exact Git blob from:
git show 884c1f33:docs/empirical-study/benign-utility/replay/results/adjudication_evidence.csv
Save those bytes as $WS_RAW/replay/pre-restart-adjudication-evidence.csv.
This preserves observed provenance metadata and never assigns event judgments.
"""
import csv
import hashlib
import os
from pathlib import Path

ROOT=Path(os.environ['WS_RAW'])/'replay'
OUT=ROOT.parent.parent/'replay/results'
FIELDS=['condition','raw_condition','dynamic_id','engine_sha256','source_path','retained_system_source_path','retained_system_source_sha256',
        'retained_system_source_ctime_ns','retained_system_source_mapping']

def main():
    source=ROOT/'pre-restart-adjudication-evidence.csv'
    data=source.read_bytes()
    expected='e23fd47bfe22f255b93be190642cb99174223055'
    if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=expected:
        raise RuntimeError('Original committed system-source receipt input differs')
    rows={}
    cases={(r['raw_condition'],r['dynamic_id']):r for r in csv.DictReader(Path(__file__).with_name('reviewed_cases.csv').open())}
    for row in csv.DictReader(source.open()):
        if row.get('retained_system_source_sha256'):
            raw_condition={'broad':'block-broad','scoped':'block-scoped','none':'none'}[row['condition']]
            case=cases[(raw_condition,row['dynamic_id'])]
            log=ROOT/raw_condition/'dynamic/runs'/row['dynamic_id']/'engine.jsonl'
            if hashlib.sha256(log.read_bytes()).hexdigest()!=case['engine_sha256']:
                raise RuntimeError('Original engine log changed')
            values={key:row[key] for key in FIELDS if key not in ('raw_condition','engine_sha256')}
            values.update(raw_condition=raw_condition,engine_sha256=case['engine_sha256'])
            values.update(source_commit='884c1f33',source_git_blob='e23fd47bfe22f255b93be190642cb99174223055')
            rows[(raw_condition,row['dynamic_id'],row['source_path'])]=values
    with (OUT/'readonly-system-source-receipts.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=FIELDS+['source_commit','source_git_blob'])
        writer.writeheader();writer.writerows(rows.values())
    print('Frozen original system-source receipts:',len(rows))

if __name__=='__main__':main()
