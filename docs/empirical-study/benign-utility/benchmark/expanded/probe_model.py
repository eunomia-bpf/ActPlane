"""Unscored inert controller transport probe; benchmark defaults are untouched."""
import json,os,time,urllib.request
from pathlib import Path
started=time.time()
body=json.dumps(dict(model='zai/glm-5.3',messages=[dict(role='user',content='Reply with OK.')])).encode()
request=urllib.request.Request(os.environ['LITELLM_BASE_URL'].rstrip('/')+'/chat/completions',data=body,headers={'Authorization':'Bearer '+os.environ['LITELLM_API_KEY'],'Content-Type':'application/json'})
with urllib.request.urlopen(request,timeout=120) as response:
    status=response.status;data=json.load(response)
receipt=dict(purpose='unscored inert model transport probe; no official task or action',http_status=status,requested_model='zai/glm-5.3',response_model=data.get('model'),choices=len(data.get('choices',[])),elapsed_s=time.time()-started,utc=time.strftime('%FT%TZ',time.gmtime()))
assert status==200 and receipt['choices']>0
target=Path('/workspaces/exp/benign-utility/raw/benchmark/expanded-recovery/model-transport-probe.json');target.write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
