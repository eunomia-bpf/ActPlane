"""Post-agent verification collector: public bytes only, no credential hashes."""
import base64,csv,hashlib,json,subprocess,time
from pathlib import Path

SCRIPT='''import base64,hashlib,importlib.metadata,json,os,re,sys
from pathlib import Path
rows=[]
for name in json.loads(sys.argv[1]):
 p=Path(name)
 try:
  if not p.is_file():continue
  with p.open('rb') as f:data=f.read(10*1024*1024+1)
  public=(b'-----BEGIN CERTIFICATE-----' in data or b'-----BEGIN PUBLIC KEY-----' in data or b'PGP PUBLIC KEY BLOCK' in data) and not re.search(rb'-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----',data)
  row=dict(path=name,realpath=os.path.realpath(p),bytes=p.stat().st_size,public_header=bool(public))
  if public and len(data)<=10*1024*1024:row.update(sha256=hashlib.sha256(data).hexdigest(),base64=base64.b64encode(data).decode())
  rows.append(row)
 except OSError as e:rows.append(dict(path=name,error=type(e).__name__))
print(json.dumps(dict(files=rows,packages=sorted({(d.metadata.get('Name',''),d.version) for d in importlib.metadata.distributions()}))))
'''

def collect(logs):
    started=time.monotonic();scope_path=logs/'scope.json'
    if not scope_path.exists():return
    paths=set()
    if (logs/'observer.jsonl').exists():
        for line in (logs/'observer.jsonl').open(errors='replace'):
            try:record=json.loads(line)
            except ValueError:continue
            for data in str(record.get('data','')).splitlines():
                items=data.split('|',4)
                if len(items)==5 and items[0]=='READ' and items[4].startswith('/'):paths.add(items[4])
    scope=json.loads(scope_path.read_text())
    result=subprocess.run(['docker','exec',scope['container_id'],'python3','-c',SCRIPT,json.dumps(sorted(paths))],capture_output=True,text=True,timeout=45)
    receipt=dict(purpose='post-agent evidence collection outside model-dispatched actions',started_monotonic=started,elapsed_s=time.monotonic()-started,returncode=result.returncode,observed_candidate_paths=len(paths),private_contents_or_hashes_retained=False)
    if result.returncode==0:
        content=json.loads(result.stdout)
        for row in content['files']:
            payload=row.pop('base64',None)
            if payload is not None:
                data=base64.b64decode(payload);assert hashlib.sha256(data).hexdigest()==row['sha256']
                target=logs/'public-source-bytes'/row['sha256'];target.parent.mkdir(exist_ok=True);target.write_bytes(data);row['retained_public_path']=str(target)
        (logs/'post-agent-source-evidence.json').write_text(json.dumps(content,indent=2)+'\n')
    else:receipt['error']=result.stderr[:1000]
    (logs/'post-agent-source-collection.json').write_text(json.dumps(receipt,indent=2)+'\n')
