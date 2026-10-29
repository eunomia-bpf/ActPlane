"""Verifier-only transport for three obsolete, exact official Debian artifacts."""
import argparse,csv,fcntl,hashlib,json,subprocess,sys,time,urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote,unquote,urlparse

ROOT=Path('/workspaces/exp/benign-utility')
RAW=ROOT/'raw/benchmark/expanded-recovery/apt-transport'
OUT=ROOT/'benchmark/expanded/results'
HOST='172.29.77.1';PORT=38766
PACKAGES=(('curl','7.74.0-1.3+deb11u16','curl'),('libcurl4','7.74.0-1.3+deb11u16','curl'),('libnghttp2-14','1.43.0-1+deb11u3','nghttp2'))
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))

def prepare():
 RAW.mkdir(parents=True,exist_ok=True);rows=[]
 for name,version,source in PACKAGES:
  api=f'https://snapshot.debian.org/mr/binary/{name}/{quote(version,safe="")}/binfiles'
  meta=RAW/(name+'-snapshot-api.json')
  if not meta.exists():
   with opener.open(api,timeout=60) as response:meta.write_bytes(response.read())
  artifact=next(r['hash'] for r in json.loads(meta.read_text())['result'] if r['architecture']=='amd64')
  url='https://snapshot.debian.org/file/'+artifact
  file=RAW/(name+'_'+version+'_amd64.deb')
  if not file.exists():
   with opener.open(url,timeout=60) as response:file.write_bytes(response.read())
  assert hashlib.sha1(file.read_bytes()).hexdigest()==artifact,'Official snapshot content address mismatch'
  rows.append(dict(package=name,version=version,architecture='amd64',snapshot_api=api,artifact_url=url,snapshot_sha1=artifact,sha256=hashlib.sha256(file.read_bytes()).hexdigest(),bytes=file.stat().st_size,retained_path=str(file),original_path=f'/debian-security/pool/updates/main/{source[0]}/{source}/{file.name}'))
 with (OUT/'.export.lock').open('a+') as guard:
  fcntl.flock(guard,fcntl.LOCK_EX)
  with (OUT/'verifier-apt-artifacts.csv').open('w',newline='') as stream:
   writer=csv.DictWriter(stream,fieldnames=list(rows[0]),lineterminator='\n');writer.writeheader();writer.writerows(rows)
 return rows

class Proxy(BaseHTTPRequestHandler):
 def do_GET(self):
  url=self.path
  if url=='/health':
   self.send_response(200);self.end_headers();self.wfile.write(b'benign-utility-verifier-apt-transport');return
  parsed=urlparse(url);matches=[r for r in self.server.artifacts if parsed.hostname=='deb.debian.org' and unquote(parsed.path)==r['original_path']]
  try:
   if matches:
    row=matches[0];file=Path(row['retained_path']);data=file.read_bytes();assert hashlib.sha256(data).hexdigest()==row['sha256'];status=200;kind='exact_official_snapshot_bytes'
   else:
    request=urllib.request.Request(url,headers={k:v for k,v in self.headers.items() if k.lower() not in ('host','connection','proxy-connection')})
    with opener.open(request,timeout=90) as response:data=response.read();status=response.status
    kind='unchanged_upstream_transport'
   self.send_response(status);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
   with (RAW/'requests.jsonl').open('a') as stream:stream.write(json.dumps(dict(utc=time.strftime('%FT%TZ',time.gmtime()),url=url,status=status,kind=kind,bytes=len(data)))+'\n')
  except Exception as error:self.send_error(502,str(error))
 def log_message(self,*args):pass

def verifier_env():
 url=f'http://{HOST}:{PORT}'
 try:
  with opener.open(url+'/health',timeout=3) as response:assert response.read()==b'benign-utility-verifier-apt-transport'
 except OSError:
  with (RAW/'server.log').open('a') as stream:
   process=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--serve'],stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
  for _ in range(100):
   assert process.poll() is None,'Verifier artifact proxy exited'
   try:
    with opener.open(url+'/health',timeout=1) as response:
     if response.read()==b'benign-utility-verifier-apt-transport':break
   except OSError:time.sleep(.1)
  else:raise RuntimeError('Verifier artifact proxy not ready')
 return {'http_proxy':url}

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--serve',action='store_true');args=parser.parse_args()
 if args.serve:
  rows=list(csv.DictReader((OUT/'verifier-apt-artifacts.csv').open()))
  server=ThreadingHTTPServer((HOST,PORT),Proxy);server.artifacts=rows;server.serve_forever()
 else:print(json.dumps(prepare(),indent=2))
