"""Guest-only exact-hostname resolution repair, followed by real model liveness."""
import ipaddress,json,os,shlex,socket,subprocess,urllib.parse
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark/expanded-recovery');RAW.mkdir(parents=True,exist_ok=True)
hostname=urllib.parse.urlsplit(os.environ['LITELLM_BASE_URL']).hostname
address=next(r[4][0] for r in socket.getaddrinfo(hostname,4000,socket.AF_INET,socket.SOCK_STREAM));ipaddress.IPv4Address(address)
script="from pathlib import Path; import sys; p=Path('/etc/hosts'); old=p.read_text(); Path(sys.argv[3]).write_text(old); p.write_text('\\n'.join(x for x in old.splitlines() if not x.endswith('# benign-utility-gateway'))+'\\n'+sys.argv[1]+' '+sys.argv[2]+' # benign-utility-gateway\\n')"
def ssh(command,**kwargs):return subprocess.run(['ssh','-i','/tmp/benign-utility-vm/id_ed25519','-p','2247','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','root@127.0.0.1',command],**kwargs)
ssh(shlex.join(['python3','-c',script,address,hostname,str(RAW/'guest-hosts-before.txt')]),check=True)
prefix='cd /workspaces/exp/benign-utility/src; source /workspaces/exp/benign-utility/raw/benchmark/expanded-recovery/model.env; '
result=ssh(prefix+'python3 -m benchmark.expanded.diagnose_gateway',check=True,capture_output=True,text=True)
data=json.loads(result.stdout);assert data.get('models_status')==200,data
(RAW/'gateway-dns-validation.json').write_text(json.dumps(dict(hostname=hostname,address=address,guest=data),indent=2)+'\n')
ssh(prefix+'python3 -m benchmark.expanded.probe_model',check=True)
