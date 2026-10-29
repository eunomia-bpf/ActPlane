"""Read-only, outcome-independent inspection of published network task goals.

Does not pull an image, run a task, or change the primary manifest.
"""
import csv,hashlib,re,subprocess,tomllib
from pathlib import Path

RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
DATA=RAW/'terminal-bench-2';OUT=RAW.parent.parent/'benchmark/results'
pattern=re.compile(r'https?://|download|pip install|npm install|apt-get|wget|curl|git clone',re.I)
decisions={
 'pypi-server':('propose','local_package_http','Goal requires installing the newly hosted package from a local HTTP package index; background server plus foreground pip transaction.'),
 'git-multibranch':('propose','local_ssh_and_https','Goal requires SSH pushes and verification at local HTTPS endpoints; inventory the official nginx private key and SSH host keys before freezing new task-specific sources.'),
 'build-cython-ext':('propose','external_https_checkout_and_build','Goal explicitly requires a pinned remote HTTPS checkout and compiling/installing a Python extension; foreground network/build actions.'),
 'hf-model-inference':('defer','external_model_download_and_service','Natural outbound model download, but Torch image and model increase disk pressure; service adds background attribution complexity.'),
 'sam-cell-seg':('defer','external_model_and_segmentation','Referenced model repository and segmentation workload add model/image/resource requirements beyond the lighter proposed stratum.'),
 'extract-moves-from-video':('defer','external_video_download','Required YouTube dependency and OCR/video workload add external-service availability and modality confounds.'),
 'build-pov-ray':('defer','external_legacy_source_download','Natural required source download, but legacy archive discovery/availability adds an avoidable external dependency.'),
 'build-pmars':('defer','external_debian_source_download','Natural required Debian-source download; selected foreground checkout/build task already represents the external-source category.'),
 'configure-git-webserver':('defer','local_ssh_and_http','Required local deployment and HTTP verification; git-multibranch additionally mandates TLS and has an explicit private-key artifact.'),
 'gpt2-codegolf':('exclude','already_downloaded_data','Download keyword describes weights already provided, not a required new network action.'),
}
head=subprocess.check_output(['git','-C',str(DATA),'rev-parse','HEAD'],text=True).strip()
rows=[]
for instruction in sorted(DATA.glob('*/instruction.md')):
 text=instruction.read_text()
 if not pattern.search(text):continue
 task=instruction.parent.name
 decision,role,reason=decisions.get(task,('requires_static_review','unclassified','Keyword match requires task-goal review before admission'))
 config=tomllib.loads((instruction.parent/'task.toml').read_text())
 env=config.get('environment',{})
 dockerfile=instruction.parent/'environment/Dockerfile'
 test=instruction.parent/'tests/test.sh'
 test_text=test.read_text() if test.exists() else ''
 rows.append(dict(task=task,decision=decision,role=role,reason=reason,
  instruction_match_lines=','.join(str(i) for i,line in enumerate(text.splitlines(),1) if pattern.search(line)),
  dataset_commit=head,instruction_sha256=hashlib.sha256(instruction.read_bytes()).hexdigest(),
  dockerfile_sha256=hashlib.sha256(dockerfile.read_bytes()).hexdigest() if dockerfile.exists() else '',
  test_sha256=hashlib.sha256(test.read_bytes()).hexdigest() if test.exists() else '',
  official_image=env.get('docker_image',''),official_agent_timeout_s=config.get('agent',{}).get('timeout_sec',''),
  official_verifier_timeout_s=config.get('verifier',{}).get('timeout_sec',''),
  official_cpus=env.get('cpus',''),official_memory=env.get('memory',''),official_storage=env.get('storage',''),
  verifier_transport='uv0.9.5' if 'uv/0.9.5/install.sh' in test_text else ('pip' if re.search(r'\bpip install\b',test_text) else 'other'),
  image_size_status='not_measured_no_image_pull',experiment_status='not_run',instruction_path=str(instruction)))
 rows[-1].update(static_known_private_key='/etc/ssl/private/nginx-selfsigned.key' if task=='git-multibranch' else ('none_declared_in_reviewed_dockerfile_not_full_inventory' if task in ('pypi-server','build-cython-ext') else 'not_inventoried'),
  full_image_secret_inventory='pending_before_any_followup_outcome' if decision=='propose' else 'not_proposed',
  followup_policy_status='new_task_specific_narrowing_not_frozen' if decision=='propose' else 'not_proposed')
with (OUT/'network-task-candidates.csv').open('w',newline='') as handle:
 writer=csv.DictWriter(handle,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
print('Static candidates',len(rows),'proposed',[r['task'] for r in rows if r['decision']=='propose'])
