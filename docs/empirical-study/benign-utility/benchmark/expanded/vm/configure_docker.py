"""Configure only the empty guest daemon, never the host's live daemon/socket."""
import json
from pathlib import Path
import subprocess

remote = r'''
import json,subprocess
from pathlib import Path
def run(args,**kwargs):return subprocess.run(args,check=True,**kwargs)
assert not subprocess.check_output(['docker','ps','-aq'],text=True).strip(), 'Guest has containers; do not interrupt it'
run(['systemctl','stop','docker.socket','docker.service'])
configuration={'data-root':'/var/lib/benign-utility-expanded-docker','storage-driver':'overlay2','bip':'172.29.77.1/24'}
Path('/etc/docker/daemon.json').write_text(json.dumps(configuration,indent=2)+'\n')
run(['systemctl','start','docker.service'])
info=json.loads(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True))
assert info['DockerRootDir']==configuration['data-root'] and info['Driver']=='overlay2'
network=json.loads(subprocess.check_output(['docker','network','inspect','bridge'],text=True))[0]
assert network['IPAM']['Config'][0]['Gateway']=='172.29.77.1'
filesystem=json.loads(subprocess.check_output(['findmnt','--json','-T',configuration['data-root']],text=True))['filesystems'][0]
assert filesystem['fstype']=='ext4',filesystem
print(json.dumps(dict(configuration=configuration,info=info,bridge=network,filesystem=filesystem)))
'''
args=['ssh','-i','/tmp/benign-utility-vm/id_ed25519','-p','2247','-o','StrictHostKeyChecking=no',
      '-o','UserKnownHostsFile=/dev/null','root@127.0.0.1','python3','-']
result=subprocess.run(args,input=remote,text=True,check=True,capture_output=True)
data=json.loads(result.stdout)
out=Path('/workspaces/exp/benign-utility/raw/benchmark/expanded/vm/guest-docker.json')
out.write_text(json.dumps(data,indent=2)+'\n')
print(json.dumps(dict(data_root=data['info']['DockerRootDir'],driver=data['info']['Driver'],
                     gateway=data['bridge']['IPAM']['Config'][0]['Gateway'],filesystem=data['filesystem'])))
