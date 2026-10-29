"""Repair controller-only cluster DNS, retaining every failed native attempt."""
import argparse,csv,ipaddress,json,os,shlex,signal,socket,subprocess,time,urllib.parse
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark/expanded-recovery')
ROOT=RAW.parents[2]/'benchmark/expanded'

def identity(pid):
    p=Path('/proc')/str(pid);data=(p/'stat').read_text().rsplit(')',1)[1].split()
    return dict(pid=pid,state=data[0],starttime=data[19],cmdline=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode())
def children(pid):
    found=[]
    for p in Path('/proc').glob('[0-9]*'):
        try:
            data=(p/'stat').read_text().rsplit(')',1)[1].split()
            if int(data[1])==pid:found.append(identity(int(p.name)))
        except OSError:pass
    return found
def ssh(port,command,**kwargs):
    return subprocess.run(['ssh','-i','/tmp/benign-utility-vm/id_ed25519','-p',str(port),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','root@127.0.0.1',command],**kwargs)
def main(action,pid):
    target=RAW/'gateway-dns-repair.json'
    if action=='pause':
        before=identity(pid);assert '-m benchmark.expanded.matrix' in before['cmdline']
        receipt=dict(coordinator_before=before,children_before=children(pid),paused_utc=time.strftime('%FT%TZ',time.gmtime()),reason='guest cluster hostname resolution failed while identical host /models returned200; no utility score assigned')
        target.write_text(json.dumps(receipt,indent=2)+'\n');os.kill(pid,signal.SIGSTOP);return
    receipt=json.loads(target.read_text());assert identity(pid)['starttime']==receipt['coordinator_before']['starttime']
    active=[c for c in children(pid) if c['state']!='Z'];assert not active,'Wait for existing native SSH cells/exporters to finish naturally: '+str(active)
    for calls in (RAW/'jobs').glob('*/*/agent/calls.jsonl'):assert not calls.read_text().strip(),'A pre-repair trial dispatched tools; inspect individually before an environment-wide exclusion'
    hostname=urllib.parse.urlsplit(os.environ['LITELLM_BASE_URL']).hostname
    address=next(r[4][0] for r in socket.getaddrinfo(hostname,4000,socket.AF_INET,socket.SOCK_STREAM));ipaddress.IPv4Address(address)
    host_script="from pathlib import Path; import sys; p=Path('/etc/hosts'); old=p.read_text().splitlines(); p.write_text('\\n'.join(x for x in old if not x.endswith('# benign-utility-gateway'))+'\\n'+sys.argv[1]+' '+sys.argv[2]+' # benign-utility-gateway\\n')"
    diagnostics=[]
    for i in range(1,4):
        port=2246+i
        ssh(port,shlex.join(['python3','-c',host_script,address,hostname]),check=True)
        command='cd /workspaces/exp/benign-utility/src; source /workspaces/exp/benign-utility/raw/benchmark/expanded-recovery/model.env; python3 -m benchmark.expanded.diagnose_gateway'
        result=ssh(port,command,check=True,capture_output=True,text=True);data=json.loads(result.stdout);assert data.get('models_status')==200,data;diagnostics.append(dict(worker=f'worker{i}',**data))
    audits=[]
    for result in (RAW/'jobs').glob('*/*/result.json'):
        data=json.loads(result.read_text());exception=data.get('exception_info') or {}
        assert exception.get('exception_type')=='InternalServerError' and 'Connection error' in exception.get('exception_message',''),str(result)
        job=result.parent.parent.name;task=data['task_name'];condition,attempt=job[len(task)+1:].split('-',1)
        audits.append(dict(trial_id=result.parent.name,task=task,condition=condition,attempt=attempt,reason='verified_guest_model_gateway_DNS_failure_before_tools_and_verifier',retry_allowed=1,evidence=str(target)))
    with (ROOT/'results/infrastructure-audits.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(audits[0]),lineterminator='\n');writer.writeheader();writer.writerows(audits)
    receipt.update(repaired_utc=time.strftime('%FT%TZ',time.gmtime()),hostname=hostname,address=address,worker_diagnostics=diagnostics,excluded_trial_ids=[r['trial_id'] for r in audits],children_at_repair=children(pid),coordinator_closed_signal='SIGKILL to metadata coordinator only after all child native SSH cells finished')
    target.write_text(json.dumps(receipt,indent=2)+'\n')
    os.kill(pid,signal.SIGKILL)
    print(json.dumps(dict(hostname=hostname,address=address,worker_statuses=[d['models_status'] for d in diagnostics],infrastructure_attempts=len(audits))))
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['pause','apply']);parser.add_argument('pid',type=int);args=parser.parse_args();main(args.action,args.pid)
