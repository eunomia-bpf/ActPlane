#!/usr/bin/env python3
"""Record replay feasibility, access probes, disk usage, and considered exclusions."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import requests

from analyze import HERE, write_csv


def main(raw):
    rows=[]
    def record(probe,status,detail):
        rows.append(dict(probe=probe,status=str(status),detail=str(detail),utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())))
    try:
        r=subprocess.run(['docker','info','--format','{{.ServerVersion}}'],capture_output=True,text=True,timeout=15)
        record('docker_daemon',r.returncode,(r.stdout+r.stderr).strip())
    except (OSError,subprocess.TimeoutExpired) as e:
        record('docker_daemon','unavailable',type(e).__name__)
    record('bpftrace_binary','available' if shutil.which('bpftrace') else 'unavailable','binary lookup only')
    endpoints=[('qwen38','http://qwen38-vllm.models.svc.cluster.local:8000/v1'),
               ('glm53-flash','http://glm53-flash.models.svc.cluster.local:8000/v1'),
               ('qwen38-flash-next','http://qwen38-flash-next.models.svc.cluster.local:8000/v1'),
               ('gateway',os.environ.get('LITELLM_BASE_URL','').rstrip('/'))]
    for label,base in endpoints:
        for authenticated in ([False,True] if label!='gateway' else [True]):
            if not base:
                continue
            headers={'Authorization':'Bearer '+os.environ.get('LITELLM_API_KEY','')} if authenticated else {}
            try:
                r=requests.get(base+'/models',headers=headers,timeout=15)
                ids=[x.get('id') for x in r.json().get('data',[])] if r.status_code==200 else []
                record(label+('_with_gateway_key' if authenticated else '_without_key'),r.status_code,json.dumps(ids))
            except Exception as e:
                record(label,'probe_failed',type(e).__name__)
    # The registry metadata, not a downloaded tensor/model, establishes these identities.
    for repo,reason in [('SWE-bench/SWE-smith-trajectories','Not sampled: SWE-agent already represented; constructed bug tasks differ from real issue trajectories.'),
                        ('SWE-Gym/MoatlessTools-Sampled-Trajectories','Not sampled: no root license/card declaration found during availability check.'),
                        ('SWE-Gym/OpenHands-Sampled-Trajectories','Not sampled: raw archive card has no declared license; used MIT-declared SFT release with documented success selection.')]:
        try:
            r=requests.get('https://huggingface.co/api/datasets/'+repo,timeout=30)
            j=r.json()
            record(repo,r.status_code,json.dumps(dict(revision=j.get('sha'),declared_license=j.get('cardData',{}).get('license'),decision=reason)))
        except Exception as e:
            record(repo,'probe_failed',type(e).__name__)
    record('required_oss_change_workflow_skill','unavailable','Not listed in available skills and filesystem search found no oss-change-workflow/SKILL.md. Followed scope, validation, docs synchronization, and branch handoff guidance from AGENTS.md and the operator update.')
    receipts=list((raw/'dynamic/runs').glob('*/done.json'))
    record('dynamic_replay','receipts_available' if receipts else 'not_run',
           f'{len(receipts)} replay receipts. See dynamic_replays.csv and dynamic_preflight.csv. '
           'Local bpftrace and isolated checkouts replace the initial Docker feasibility limitation. '
           'The independent two-LLM annotation remains a static-label check.')
    write_csv(HERE/'availability.csv',rows)
    usage=shutil.disk_usage(raw)
    size=sum(p.stat().st_size for p in raw.rglob('*') if p.is_file())
    write_csv(HERE/'resources.csv',[dict(raw_bytes=size,workspace_total_bytes=usage.total,workspace_used_bytes=usage.used,
                                       workspace_used_pct=round(100*usage.used/usage.total,3),raw_limit_bytes=25_000_000_000,
                                       workspace_limit_pct=85,utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))])


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--raw',type=Path,required=True)
    main(p.parse_args().raw)
