"""Archive the failed transport epoch, without assigning its attempts utility zero."""
import csv,json,os,shutil,subprocess,sys
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark');ROOT=BASE.parent.parent/'benchmark/expanded'
archive=ROOT/'transport-results'
if not archive.exists():shutil.copytree(ROOT/'results',archive,ignore=shutil.ignore_patterns('.export.lock'))
old=BASE/'expanded-vm';audits=[];status=[]
tasks=[r['task'] for r in csv.DictReader((ROOT/'results/tasks.csv').open())]
for job in sorted((old/'jobs').glob('*')):
    task=next(t for t in tasks if job.name.startswith(t+'-'));condition,attempt=job.name[len(task)+1:].split('-',1)
    results=list(job.glob('*/result.json'))
    if not results:status.append(dict(task=task,condition=condition,attempt=attempt,state='interrupted_by_confirmed_workspace_group_OOM',native_result=''));continue
    for path in results:
        data=json.loads(path.read_text());error=data.get('exception_info') or {};calls=path.parent/'agent/calls.jsonl'
        if error.get('exception_type')=='InternalServerError' and 'Connection error' in error.get('exception_message','') and (not calls.exists() or not calls.read_text().strip()):
            audits.append(dict(trial_id=path.parent.name,task=task,condition=condition,attempt=attempt,reason='model_transport_connection_failure_before_tools_and_verifier',retry_allowed=1,evidence=str(path)))
            state='verified_model_transport_infrastructure_failure'
        else:state='requires_individual_native_outcome_audit'
        status.append(dict(task=task,condition=condition,attempt=attempt,state=state,native_result=str(path)))
for name,rows in [('infrastructure-audits.csv',audits),('attempt-status.csv',status)]:
    with (archive/name).open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]),lineterminator='\n');writer.writeheader();writer.writerows(rows)
env={**os.environ,'BU_EXPANDED_RAW':str(old),'BU_EXPANDED_OUT':str(archive)}
subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('export.py'))],env=env,check=True)
env.update(BU_EXPANDED_RAW=str(BASE/'expanded-recovery'),BU_EXPANDED_OUT=str(ROOT/'results'))
subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('export.py'))],env=env,check=True)
print('Retained transport attempts:',len(status),'confirmed model-connection infrastructure errors:',len(audits))
