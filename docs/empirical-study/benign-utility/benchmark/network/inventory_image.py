"""Read-only metadata inside an unmodified official task image; no key bytes output."""
import hashlib,json,os,re,stat
from pathlib import Path
rows=[]
for root,dirs,files in os.walk('/',followlinks=False):
 if root=='/':dirs[:]=[x for x in dirs if x not in ('proc','sys','dev','run','inventory')]
 for name in files:
  instruction=name in ('AGENTS.md','CLAUDE.md','.cursorrules')
  candidate=(instruction or name.endswith(('.pem','.key')) or name in ('id_rsa','id_ed25519','credentials','credentials.json','oauth_creds.json') or name.startswith('.env') or name.startswith('ssh_host_') and name.endswith('_key'))
  if not candidate:continue
  path=Path(root)/name
  try:
   info=path.stat()
   if not stat.S_ISREG(info.st_mode):continue
   with path.open('rb') as handle:prefix=handle.read(1024*1024)
   if instruction:kind='project_instruction'
   elif re.search(rb'-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----',prefix):kind='private_key_header'
   elif b'-----BEGIN CERTIFICATE-----' in prefix:kind='public_certificate_header'
   elif b'-----BEGIN PUBLIC KEY-----' in prefix or b'PGP PUBLIC KEY BLOCK' in prefix:kind='public_key_header'
   elif name.startswith('.env') or name in ('credentials','credentials.json','oauth_creds.json'):kind='credential_path_candidate'
   else:kind='unclassified_key_candidate'
   row=dict(path=str(path),realpath=os.path.realpath(path),symlink=path.is_symlink(),mode=oct(stat.S_IMODE(info.st_mode)),classification=kind,empty=info.st_size==0)
   if kind in ('public_certificate_header','public_key_header'):
    if len(prefix)==info.st_size:row['public_file_sha256']=hashlib.sha256(prefix).hexdigest()
    else:row['classification']='public_header_content_scan_truncated'
   if instruction:row['instruction_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
   rows.append(row)
  except OSError as error:rows.append(dict(path=str(path),classification='inaccessible',error=type(error).__name__))
print(json.dumps(rows,sort_keys=True))
