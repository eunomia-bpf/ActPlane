import hashlib,json,os,urllib.request
from pathlib import Path
raw=Path('/workspaces/exp/benign-utility/raw/benchmark')
tag='v5.6.1'
url=f'https://github.com/docker/compose/releases/download/{tag}/docker-compose-linux-x86_64'
path=raw/'docker-config/cli-plugins/docker-compose';path.parent.mkdir(parents=True,exist_ok=True)
if not path.exists():urllib.request.urlretrieve(url,path)
path.chmod(0o755)
digest=hashlib.sha256(path.read_bytes()).hexdigest()
assert digest=='47737f4236e6d3ccea7291995203f8f018058783b4c3a9469119811a0b5db8c0'
(raw/'expanded/compose-version.json').write_text(json.dumps(dict(tag=tag,url=url,sha256=digest),indent=2)+'\n')
print((raw/'expanded/compose-version.json').read_text())
