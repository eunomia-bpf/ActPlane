"""Read-only upstream/disk/model inventory; run only in the Workspace."""
import json
import os
from pathlib import Path
import shutil
import urllib.request

raw = Path(os.environ['WS_RAW'])
u = raw / 'upstream'
out = raw / 'feasibility.json'
r = {'disk': dict(zip(('total','used','free'), shutil.disk_usage('/workspaces')))}
for label, url, key in [
    ('osworld_image','https://huggingface.co/datasets/xlangai/ubuntu_osworld/resolve/main/Ubuntu.qcow2.zip',None),
    ('gateway_models',os.environ.get('LITELLM_BASE_URL','').rstrip('/') + '/models',os.environ.get('LITELLM_API_KEY')),
    ('qwen_models','http://qwen38-vllm.models.svc.cluster.local:8000/v1/models',None),
]:
    try:
        req = urllib.request.Request(url, method='HEAD' if label=='osworld_image' else 'GET')
        if key: req.add_header('Authorization','Bearer '+key)
        with urllib.request.urlopen(req, timeout=30) as resp:
            r[label] = {'status':resp.status}
            if label=='osworld_image':
                r[label].update({k:resp.headers.get(k) for k in ('Content-Length','Content-Type','X-Linked-Size')})
            else:
                r[label]['models'] = [v['id'] for v in json.load(resp).get('data',[])]
    except Exception as e:
        r[label] = {'error':type(e).__name__, 'detail':str(e).split('?')[0]}
spec=json.loads((u/'OS-Harm/evaluation_examples/test_injection.json').read_text())
tasks=[]
for suite,ids in spec.items():
    for tid in ids:
        d=json.loads((u/f'OS-Harm/evaluation_examples/examples/{suite}/{tid}.json').read_text())
        tasks.append({'suite':suite,'task_id':tid,'cases':sum(len(i['goals']) for i in d.get('injections',[]))})
r['osharm_injection_tasks']=tasks
out.write_text(json.dumps(r,indent=2))
print(json.dumps(r,indent=2))
