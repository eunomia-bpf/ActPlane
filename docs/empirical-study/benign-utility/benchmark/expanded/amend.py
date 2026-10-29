"""Retain host attempts and freeze the same-protocol guest environment."""
import argparse,csv,hashlib,importlib.metadata,json,os,shutil,subprocess,sys,time
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark')
ROOT=BASE.parent.parent/'benchmark/expanded'
HERE=Path(__file__).parent
ENVIRONMENT='workspace_kvm_guest_20261029'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return list(csv.DictReader(p.open())) if p.exists() else []
def stage():
    host_seals=ROOT/'host-task-seals'
    if not host_seals.exists():shutil.copytree(ROOT/'task-seals',host_seals)
    for file in host_seals.glob('*.json'):
        seal=json.loads(file.read_text())
        for relative,expected in seal['runtime_code'].items():assert digest(HERE/'host-runtime'/relative)==expected,relative
    archive=ROOT/'host-results'
    if not archive.exists():shutil.copytree(ROOT/'results',archive,ignore=shutil.ignore_patterns('.export.lock'))
    rows=read(archive/'trials.csv')
    assert not any(r['selected_for_comparison']=='1' and r['condition']!='a' for r in rows),'Amendment must precede valid defended primary outcomes'
    env={**os.environ,'BU_EXPANDED_RAW':str(BASE/'expanded'),'BU_EXPANDED_OUT':str(archive)}
    subprocess.run([sys.executable,'-B',str(HERE/'export.py')],env=env,check=True)
    (ROOT/'amendment.json').write_text(json.dumps(dict(environment_id=ENVIRONMENT,utc=time.strftime('%FT%TZ',time.gmtime()),rule='ALL guest conditions only; ALL host attempts supporting regardless reward',old_host_raw=str(BASE/'expanded'),primary_raw=str(BASE/'expanded-vm'),tasks_sha256=digest(ROOT/'results/tasks.csv'),original_host_task_seal_hashes={p.name:digest(p) for p in host_seals.glob('*.json')}),indent=2)+'\n')
    env.update(BU_EXPANDED_RAW=str(BASE/'expanded-vm'),BU_EXPANDED_OUT=str(ROOT/'results'))
    subprocess.run([sys.executable,'-B',str(HERE/'export.py')],env=env,check=True)
def capture(worker,port):
    chain=Path('/sys/kernel/security/lsm').read_text().strip();assert 'bpf' in chain.split(',')
    directory=ROOT/'worker-results'/worker;control=directory/'enforcement-block-control.csv'
    controls=read(control);assert len(controls)==3 and all(r['passed']=='1' for r in controls)
    daemon=json.loads(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True))
    environment=dict(environment_id=ENVIRONMENT,worker_id=worker,ssh_port=port,kernel_release=os.uname().release,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),lsm_chain=chain,docker_data_root=daemon['DockerRootDir'],docker_driver=daemon['Driver'],engine_sha256=digest(BASE/'engine/process'),harbor_version=importlib.metadata.version('harbor'),native_block_control_sha256=digest(control),frozen_before_models_utc=time.strftime('%FT%TZ',time.gmtime()))
    assert environment['harbor_version']=='0.25.0'
    (directory/'environment.json').write_text(json.dumps(environment,indent=2)+'\n')
    print(json.dumps(environment,indent=2))
def freeze():
    workers={f'worker{i}':json.loads((ROOT/'worker-results'/f'worker{i}'/'environment.json').read_text()) for i in range(1,4)}
    assert len({w['boot_id'] for w in workers.values()})==3
    assert len({w['kernel_release'] for w in workers.values()})==1
    assert all(w['harbor_version']=='0.25.0' and 'bpf' in w['lsm_chain'].split(',') and w['engine_sha256']==digest(BASE/'engine/process') for w in workers.values())
    environment=dict(environment_id=ENVIRONMENT,arrangement='three kernel-isolated identical workers; task rank modulo three; one native cell per worker',workers=workers,frozen_before_models_utc=time.strftime('%FT%TZ',time.gmtime()))
    assignments=[dict(task=t['task'],selection_rank=i,worker_id='worker'+str(i%3+1),ssh_port=workers['worker'+str(i%3+1)]['ssh_port'],condition_order=t['condition_order']) for i,t in enumerate(read(ROOT/'results/tasks.csv'))]
    with (ROOT/'results/worker-assignment.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(assignments[0]),lineterminator='\n');writer.writeheader();writer.writerows(assignments)
    assignment={a['task']:a['worker_id'] for a in assignments}
    target=ROOT/'environment-freeze.json';target.write_text(json.dumps(environment,indent=2)+'\n')
    for file in (ROOT/'task-seals').glob('*.json'):
        seal=json.loads((ROOT/'host-task-seals'/file.name).read_text())
        seal.update(environment_id=ENVIRONMENT,worker_id=assignment[file.stem],original_host_seal_sha256=digest(ROOT/'host-task-seals'/file.name),frozen_before_model_utc=time.strftime('%FT%TZ',time.gmtime()))
        seal['files']['environment-freeze.json']=digest(target)
        seal['files']['results/worker-assignment.csv']=digest(ROOT/'results/worker-assignment.csv')
        code_root=HERE.parent
        seal['runtime_code']={str(p.relative_to(code_root)):digest(p) for p in [code_root/'adapter.py',HERE/'adapter.py',HERE/'run.py',HERE/'collect_public.py',HERE/'dependencies.py',code_root/'dependencies.py']}
        file.write_text(json.dumps(seal,indent=2)+'\n')
    print(json.dumps(environment,indent=2))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['stage','capture-worker','freeze']);p.add_argument('--worker');p.add_argument('--ssh-port',type=int);a=p.parse_args()
    stage() if a.action=='stage' else capture(a.worker,a.ssh_port) if a.action=='capture-worker' else freeze()
