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
def freeze():
    chain=Path('/sys/kernel/security/lsm').read_text().strip();assert 'bpf' in chain.split(',')
    controls=read(ROOT/'results/enforcement-block-control.csv');assert len(controls)==3 and all(r['passed']=='1' for r in controls)
    daemon=json.loads(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True))
    environment=dict(environment_id=ENVIRONMENT,kernel_release=os.uname().release,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),lsm_chain=chain,docker_data_root=daemon['DockerRootDir'],docker_driver=daemon['Driver'],engine_sha256=digest(BASE/'engine/process'),harbor_version=importlib.metadata.version('harbor'),native_block_control_sha256=digest(ROOT/'results/enforcement-block-control.csv'),frozen_before_models_utc=time.strftime('%FT%TZ',time.gmtime()))
    assert environment['harbor_version']=='0.25.0'
    target=ROOT/'environment-freeze.json';target.write_text(json.dumps(environment,indent=2)+'\n')
    for file in (ROOT/'task-seals').glob('*.json'):
        seal=json.loads((ROOT/'host-task-seals'/file.name).read_text())
        seal.update(environment_id=ENVIRONMENT,original_host_seal_sha256=digest(ROOT/'host-task-seals'/file.name),frozen_before_model_utc=time.strftime('%FT%TZ',time.gmtime()))
        seal['files']['environment-freeze.json']=digest(target)
        code_root=HERE.parent
        seal['runtime_code']={str(p.relative_to(code_root)):digest(p) for p in [code_root/'adapter.py',HERE/'adapter.py',HERE/'run.py',HERE/'collect_public.py',HERE/'dependencies.py',code_root/'dependencies.py']}
        file.write_text(json.dumps(seal,indent=2)+'\n')
    print(json.dumps(environment,indent=2))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['stage','freeze']);a=p.parse_args();stage() if a.action=='stage' else freeze()
