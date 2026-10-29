"""Inspect actual compiler output and record engine/model provenance."""
import csv,hashlib,json,re,struct,subprocess,urllib.request
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark');HERE=Path(__file__).parent;OUT=RAW.parent.parent/'benchmark/results'
OUT.mkdir(exist_ok=True);rows=[]
act='/workspaces/lanes/translation-models/target/release/actplane'
for condition in ['b','c']:
 policy=(HERE/'policies'/f'{condition}.dsl').read_text();blob=RAW/f'policy-{condition}.bin'
 subprocess.run([act,'--rule',policy,'compile','--out',str(blob),'--force'],check=True,capture_output=True)
 data=blob.read_bytes();count,rules=struct.unpack_from('<II',data)
 source_patterns=re.findall(r'^source (\w+) = (exec|file) "([^"]*)"',policy,re.M)
 assert count==len(source_patterns)
 for i,(label,kind,pattern) in enumerate(source_patterns):
  op,mode,literal,arg,add,delete,gates,invals,ip,mask,exit_code,domain=struct.unpack_from('<BB64s24s6xQQQQIIiI',data,8+i*144)
  literal=literal.split(b'\0')[0].decode()
  if pattern.startswith('**/*'):assert mode==2 and literal==pattern[4:]
  if kind=='file' and pattern.startswith('/') and '*' not in pattern:assert mode==0 and literal==pattern
  rows.append(dict(condition=condition,label=label,source_kind=kind,pattern=pattern,compiled_op=op,compiled_match_mode=mode,compiled_literal=literal,add_mask=add))
with (OUT/'compiled-sources.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
provenance=[]
for kind,path in [('engine',RAW/'engine/process'),('compiler',Path(act)),('observer',HERE.parent/'replay/source_observer.bt')]:
 if path.exists():provenance.append(dict(component=kind,path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
with (OUT/'binaries.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=['component','path','sha256']);w.writeheader();w.writerows(provenance)
try:
 model=json.load(urllib.request.urlopen('http://qwen38-vllm.models.svc.cluster.local:8000/v1/models',timeout=20))
 (OUT/'qwen-candidate-model-metadata.json').write_text(json.dumps(model,indent=2)+'\n')
except Exception as e:print('Model metadata unavailable',repr(e))
print('Audited',len(rows),'sources')
