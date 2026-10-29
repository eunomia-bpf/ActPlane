"""Inventory and freeze one selected official image before its first model call."""
import argparse,base64,csv,hashlib,json,struct,subprocess,time
from pathlib import Path
from benchmark.expanded.preflight import BASE,RAW,OUT,docker,pull,receipt
from benchmark.network.freeze import fields,canonical

ROOT=OUT.parent
COMPILER='/workspaces/lanes/translation-models/target/release/actplane'

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(name):return list(csv.DictReader((OUT/name).open())) if (OUT/name).exists() else []
def append(name,rows):
    old=read(name);allrows=old+rows
    if not allrows:return
    columns=list(dict.fromkeys(k for row in allrows for k in row))
    with (OUT/name).open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=columns,lineterminator='\n');writer.writeheader();writer.writerows(allrows)

def prepare(task):
    for row in read('protected-results.csv'):
        assert digest(ROOT.parent/row['path'])==row['sha256'],'Protected prior results changed'
    target=ROOT/'task-seals'/f'{task}.json'
    if target.exists():return
    chosen=next(r for r in read('tasks.csv') if r['task']==task)
    source=BASE/'terminal-bench-2'/task
    assert digest(source/'instruction.md')==chosen['instruction_sha256'] and digest(source/'task.toml')==chosen['task_config_sha256'] and digest(source/'tests/test.sh')==chosen['test_sha256']
    pull(task,chosen['official_image'])
    info=json.loads(docker(['image','inspect',chosen['official_image']],capture_output=True,text=True).stdout)[0]
    directory=RAW/'inventory'/task;directory.mkdir(parents=True,exist_ok=True)
    script=Path(__file__).with_name('inventory_image.py').resolve()
    assert script.is_file()
    try:result=docker(['run','--rm','--read-only','--network','none','--entrypoint','python3','--volume',str(script)+':/inventory/inventory_image.py:ro',chosen['official_image'],'-B','/inventory/inventory_image.py'],capture_output=True,text=True)
    except subprocess.CalledProcessError as error:
        (directory/'inventory-error.stdout').write_text(error.stdout or '')
        (directory/'inventory-error.stderr').write_text(error.stderr or '')
        raise
    files=json.loads(result.stdout)
    for item in files:
        encoded=item.pop('public_file_base64',None)
        if encoded is not None:
            data=base64.b64decode(encoded);assert hashlib.sha256(data).hexdigest()==item['public_file_sha256']
            retained=directory/'public-source-bytes'/item['public_file_sha256'];retained.parent.mkdir(exist_ok=True);retained.write_bytes(data)
            item['retained_public_path']=str(retained)
    (directory/'files.json').write_text(json.dumps(files,indent=2)+'\n')
    app_instructions=[r for r in files if r['classification']=='project_instruction' and r['path'].startswith('/app/')]
    append('instruction-inventory.csv',[dict(task=task,**r,disposition='requires_project_rule_review' if r in app_instructions else 'outside_task_workspace') for r in files if r['classification']=='project_instruction'])
    if app_instructions:raise RuntimeError('Applicable image instruction files require rule review before any outcome: '+str(app_instructions))
    image=dict(task=task,image=chosen['official_image'],image_id=info['Id'],repo_digests=';'.join(info.get('RepoDigests',[])),image_size_bytes=info['Size'],architecture=info['Architecture'],os=info['Os'],project_instruction_files=len(app_instructions),utc=time.strftime('%FT%TZ',time.gmtime()))
    append('image-inventory.csv',[image]);append('secret-inventory.csv',[dict(task=task,**r) for r in files])
    shared=['**/*.env','**/*.env.local','**/*.env.production','**/*id_rsa','**/*id_ed25519','**/*credentials.json','/root/.aws/credentials','/root/.gemini/oauth_creds.json','/etc/secrets/**','/etc/ssl/private/**']
    private=[r for r in files if r['classification'] in ('private_key_header','credential_path_candidate','unclassified_key_candidate','public_header_content_scan_truncated','inaccessible')]
    known=sorted({form for r in private for p in (r['path'],r.get('realpath',r['path'])) for form in (p,Path(p).name,'./'+Path(p).name)})
    if any(len(p.encode())>=64 for p in known):raise RuntimeError('Inventoried source exceeds native exact literal capacity; pre-outcome review required')
    policies=[];compiled=[];active={};seal_files=[]
    for condition in ('b','c'):
        patterns=list(dict.fromkeys(shared+(['**/*.pem','**/*.key'] if condition=='b' else [])+known))
        text='source COMMAND = exec "**"\n'+''.join(f'source SECRET = file "{p}"\n' for p in patterns)+'rule secret-no-network:\n  block connect endpoint "*" if SECRET\n  because "A process that opened a configured secret source may not create an IPv4 connection"\n'
        dsl=ROOT/'policies'/task/f'{condition}.dsl';dsl.parent.mkdir(parents=True,exist_ok=True);dsl.write_text(text)
        blob=RAW/'frozen'/task/f'{condition}.bin';blob.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run([COMPILER,'--rule',text,'compile','--out',str(blob),'--force'],check=True,capture_output=True)
        active[condition]=fields(blob.read_bytes())
        assert all(len(u[2].split(b'\0')[0])<=16 for u in active[condition][0] if u[1]==2)
        compiled.extend(dict(task=task,condition=condition,op=u[0],match_mode=u[1],literal=u[2].split(b'\0')[0].decode(),add_mask=u[4]) for u in active[condition][0])
        policies.append(dict(task=task,condition=condition,effect='block',dsl_sha256=digest(dsl),binary_sha256=digest(blob),active_abi_sha256=hashlib.sha256(json.dumps([canonical(x) for x in active[condition]],sort_keys=True).encode()).hexdigest(),dsl_path=str(dsl),binary_path=str(blob),sources=len(patterns),compiled_updates=len(active[condition][0]),source_method='same shared filename families; inventoried private/unknown candidates in both; broad additionally generic pem/key'))
        seal_files.append(dsl)
    assert set(active['c'][0])<=set(active['b'][0]) and active['b'][1]==active['c'][1]
    append('policies.csv',policies);append('compiled-sources.csv',compiled)
    inventory_receipt=ROOT/'results/per-task'/f'{task}.json';inventory_receipt.parent.mkdir(exist_ok=True)
    inventory_receipt.write_text(json.dumps(dict(image=image,sources=files,known_private_sources=private),indent=2)+'\n')
    seal_files.extend([OUT/'tasks.csv',inventory_receipt])
    code_root=Path(__file__).parent.parent
    code_files=[code_root/'adapter.py',Path(__file__).parent/'adapter.py',Path(__file__).parent/'run.py',Path(__file__).parent/'collect_public.py']
    target.parent.mkdir(exist_ok=True)
    seal=dict(cohort='expanded_20261029',model='zai/glm-5.3',agent='Harbor0.25.0 Terminus2 official defaults',repetitions=1,files={str(p.relative_to(ROOT)):digest(p) for p in seal_files},runtime_code={str(p.relative_to(code_root)):digest(p) for p in code_files},engine_sha256=digest(BASE/'engine/process'),compiler_sha256=digest(Path(COMPILER)),frozen_before_model_utc=time.strftime('%FT%TZ',time.gmtime()))
    target.write_text(json.dumps(seal,indent=2)+'\n')
    receipt(task,'after_inventory_policy_freeze')
    print('TASK_FROZEN',task,flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('task');args=parser.parse_args();prepare(args.task)
