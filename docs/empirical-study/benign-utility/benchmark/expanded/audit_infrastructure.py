"""Identify the observed pre-test Debian package transport failure; no reward inference."""
import argparse,csv,fcntl,json,shlex,subprocess,time
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark/expanded-recovery')
OUT=RAW.parent.parent.parent/'benchmark/expanded/results'
guard=(OUT/'.export.lock').open('a+')
fcntl.flock(guard,fcntl.LOCK_EX)
parser=argparse.ArgumentParser();parser.add_argument('--inspect-original-state',action='store_true');args=parser.parse_args()
file=OUT/'infrastructure-audits.csv'
old=list(csv.DictReader(file.open())) if file.exists() else []
previous={r['trial_id']:r for r in old}
rows=[]
for result in sorted((RAW/'jobs').glob('qemu-alpine-ssh-*/*/result.json')):
 verifier=result.parent/'verifier';stdout=verifier/'test-stdout.txt'
 if not stdout.exists():continue
 text=stdout.read_text(errors='replace')
 if not all(s in text for s in ('404  Not Found','curl: command not found','uvx: command not found')):continue
 assert not (verifier/'ctrf.json').exists(),'Executed tests must not be excluded by this transport audit'
 data=json.loads(result.read_text());exception=data.get('exception_info') or {}
 timed_out=exception.get('exception_type')=='AgentTimeoutError'
 row=dict(trial_id=result.parent.name,task='qemu-alpine-ssh',reason='official_verifier_dependency_http404_before_pytest',confirmed_infrastructure_failure=1,retry_allowed=int(not timed_out),verifier_status='not_executed_official_apt_dependency_http404',agent_exception=exception.get('exception_type',''),disposition='retain_genuine_agent_timeout_no_model_resample; utility_unknown_without_executed_oracle' if timed_out else 'confirmed_infrastructure_failure_requires_audit_before_model_retry',evidence=str(stdout)+'; no ctrf.json; official tests/test.sh lines4-19 install curl and uv before pytest; Harbor0.25.0 SingleStepStrategy continues verification after AgentTimeoutError')
 prior=previous.get(row['trial_id'],{})
 for key in ('original_post_agent_state_available','original_state_evidence'):
  row[key]=prior.get(key,'unknown')
 if args.inspect_original_state:
  scope=json.loads((result.parent/'agent/scope.json').read_text());container=scope['container_id']
  command=shlex.join(['docker','inspect','--format','{{.Id}}',container])
  probe=subprocess.run(['ssh','-i','/tmp/benign-utility-vm/id_ed25519','-p','2247','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=10','root@127.0.0.1',command],capture_output=True,text=True,timeout=20)
  receipt=RAW/'original-state-inspection'/f'{row["trial_id"]}.json';receipt.parent.mkdir(exist_ok=True)
  receipt.write_text(json.dumps(dict(utc=time.strftime('%FT%TZ',time.gmtime()),container_id=container,command='docker inspect --format {{.Id}} <original immutable container ID>',returncode=probe.returncode,stdout=probe.stdout,stderr=probe.stderr),indent=2)+'\n')
  row['original_post_agent_state_available']='1' if probe.returncode==0 and probe.stdout.strip()==container else ('0' if probe.returncode==1 and 'No such object:' in probe.stderr else 'unknown')
  row['original_state_evidence']=str(receipt)
 rows.append(row)
merged={r['trial_id']:r for r in old}
merged.update({r['trial_id']:r for r in rows})
if merged:
 fields=list(dict.fromkeys(k for row in merged.values() for k in row))
 with file.open('w',newline='') as stream:
  writer=csv.DictWriter(stream,fieldnames=fields,lineterminator='\n');writer.writeheader();writer.writerows(merged.values())
print('Confirmed pre-test dependency failures:',len(rows))
