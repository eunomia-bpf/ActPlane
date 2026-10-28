#!/usr/bin/env python3
"""Freeze a paired, stratified dynamic sample and recover exact task base commits.

Only task metadata is used: oracle patches and verifier patches are never applied.
"""
import argparse
import concurrent.futures
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import time

import pyarrow.parquet as pq
import requests

from analyze import HERE, normalize, write_csv

CFG=json.loads((HERE/'dynamic_config.json').read_text())
VERIFIED_REPO='SWE-bench/SWE-bench_Verified'
VERIFIED_REV='78f471bf655a3137b2e8a75af1501690ec009ec3'
HARBOR_HASH='e2e357045bf03e4900d2506c36562f6eaff7acd37f63780600967ea3aecdcd79'


def fetch(url,path,headers=None,params=None):
    if path.exists():
        return path
    path.parent.mkdir(parents=True,exist_ok=True)
    errors=[]
    for attempt in range(3):
        try:
            response=requests.get(url,headers=headers,params=params,timeout=90)
            response.raise_for_status()
            path.write_bytes(response.content)
            return path
        except Exception as exc:
            errors.append(str(exc))
            time.sleep(attempt+1)
    raise RuntimeError('; '.join(errors))


def prepare(raw):
    root=raw/'dynamic'
    root.mkdir(exist_ok=True)
    groups={tuple(k):[] for k in CFG['groups']}
    with gzip.open(raw/'sampled_trajectories.jsonl.gz','rt') as f:
        for line in f:
            row=json.loads(line)
            key=(row['framework'],row['model'])
            if key in groups:
                groups[key].append(row)
    selected=[]
    for key,rows in groups.items():
        chosen=sorted(rows,key=lambda r:hashlib.sha256((CFG['seed']+r['instance_id']).encode()).hexdigest())[:CFG['per_group']]
        selected.extend(chosen)
    selected=sorted(selected,key=lambda r:(r['framework'],r['model'],r['instance_id']))
    (root/'selected_trajectories.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in selected))

    verified_file=fetch(f'https://huggingface.co/datasets/{VERIFIED_REPO}/resolve/{VERIFIED_REV}/data/test-00000-of-00001.parquet',root/'swebench_verified.parquet')
    verified={r['instance_id']:r for r in pq.read_table(verified_file).to_pylist()}
    # Public registry configuration is fetched at runtime. No private API key is used.
    constants=fetch('https://raw.githubusercontent.com/harbor-framework/harbor/main/src/harbor/auth/constants.py',root/'harbor_public_config.py').read_text()
    base=re.search(r'"(https://[^\"]+supabase.co)"',constants)[1]
    publishable=re.search(r'"(sb_publishable_[^\"]+)"',constants)[1]
    headers={'apikey':publishable}
    version_file=fetch(base+'/rest/v1/dataset_version',root/'harbor_pinned_version.json',headers,
                       {'select':'id,content_hash,version,revision','content_hash':'eq.'+HARBOR_HASH})
    version=json.loads(version_file.read_text())[0]
    assert version['content_hash']==HARBOR_HASH
    edges_file=fetch(base+'/rest/v1/dataset_version_task',root/'harbor_pinned_tasks.json',headers,
                     {'select':'task_version_id,task_version:task_version_id(content_hash,archive_path,package:package_id(name,org:org_id(name)))',
                      'dataset_version_id':'eq.'+version['id'],'limit':'1000'})
    edges={r['task_version']['package']['name']:r['task_version'] for r in json.loads(edges_file.read_text())}
    plans=[]
    metadata=[]
    for index,row in enumerate(selected):
        iid=row['instance_id']
        error=''
        task={}
        source=''
        digest=''
        try:
            if row['source']=='mini':
                task=verified[iid]
                source=f'https://huggingface.co/datasets/{VERIFIED_REPO}/tree/{VERIFIED_REV}'
                digest=hashlib.sha256(verified_file.read_bytes()).hexdigest()
            else:
                edge=edges[iid]
                url=base+'/storage/v1/object/packages/'+edge['archive_path']
                archive=fetch(url,root/'task_archives'/f'{iid}.tar.gz',headers)
                digest=hashlib.sha256(archive.read_bytes()).hexdigest()
                source='harbor:'+HARBOR_HASH+':'+edge['content_hash']
                with tarfile.open(archive) as tf:
                    task=json.load(tf.extractfile('tests/config.json'))
            assert re.fullmatch(r'[0-9a-f]{40}',task['base_commit'])
            assert task['instance_id'].lower()==iid.lower()
        except Exception as exc:
            error=str(exc)
        repo=task.get('repo',row.get('repository',''))
        workdir='/testbed' if row['source']=='mini' else '/'+repo.split('/')[-1]
        plan=dict(dynamic_id=f't{index:02d}',trajectory_id=row['trajectory_id'],source=row['source'],framework=row['framework'],model=row['model'],
                  instance_id=iid,repository=repo,base_commit=task.get('base_commit',''),language=task.get('language','python'),
                  sandbox_workdir=workdir,recorded_calls=len(list(normalize(row))),metadata_source=source,
                  metadata_file_sha256=digest,preparation_error=error)
        plans.append(plan)
        metadata.append(dict(dynamic_id=plan['dynamic_id'],instance_id=iid,repository=repo,base_commit=plan['base_commit'],
                             language=plan['language'],original_version=task.get('version',''),image_name=task.get('image_name',''),
                             install_config=task.get('install_config',{})))
    write_csv(HERE/'dynamic_plan.csv',plans)
    (root/'task_metadata.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in metadata))
    print(f'Frozen {len(plans)} trajectories, {len(set(p["instance_id"] for p in plans))} distinct tasks')
    print('Metadata errors:',sum(bool(p['preparation_error']) for p in plans))


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--raw',type=Path,required=True)
    prepare(p.parse_args().raw)
