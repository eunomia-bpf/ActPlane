"""Preserve direct evidence for an agent-caused official-harness error.

This audit does not manufacture a verifier reward or rerun a negative outcome.
"""
import csv,hashlib,json
from pathlib import Path

RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
OUT=RAW.parent.parent/'benchmark/results'
trial='git-leak-recovery__N6UvkVs'
job=RAW/'jobs/git-leak-recovery-c-block-1'
directory=job/trial
pane=(directory/'agent/terminus_2.pane').read_text()
native=json.loads((directory/'result.json').read_text())
summary=json.loads((job/'result.json').read_text())
base=next((RAW/'venv/lib').glob('python*/site-packages/harbor/metrics/base.py'))
metric_source=base.read_text()
assert '0 if reward is None' in metric_source
assert "actual=$(git prune -n | sort)" in pane
assert 'ERROR: unexpected prune set; aborting cleanup\n' in pane
assert 'exit\n' in pane and 'logout' in pane
assert native['exception_info']['exception_type']=='RuntimeError'
assert 'no server' in native['exception_info']['exception_message']
assert not native.get('verifier_result')
assert 'TAINT_VIOLATION' not in (directory/'agent/engine.log').read_text()
stats=summary['stats']
evals=list(stats['evals'].values())
assert len(evals)==1 and evals[0]['n_errors']==1
mean=evals[0]['metrics'][0]['mean']
assert mean==0
row=dict(task='git-leak-recovery',condition='c',attempt='block-1',trial_id=trial,
 audit='agent_induced_shell_exit',retry_allowed=0,native_reward_available=0,
 official_job_mean=mean,official_job_errors=evals[0]['n_errors'],
 verifier_tests_executed=0,policy_interventions=0,
 evidence='Agent compared bare object hashes with git-prune hash-plus-type output, executed exit1, then exited outer shell; subsequent send_keys failed because tmux server exited.',
 pane_path=str(directory/'agent/terminus_2.pane'),
 pane_sha256=hashlib.sha256((directory/'agent/terminus_2.pane').read_bytes()).hexdigest(),
 native_result_path=str(directory/'result.json'),job_result_path=str(job/'result.json'),
 metric_source=str(base),metric_sha256=hashlib.sha256(base.read_bytes()).hexdigest())
with (OUT/'error-audit.csv').open('w',newline='') as handle:
 writer=csv.DictWriter(handle,fieldnames=list(row));writer.writeheader();writer.writerow(row)
print(row)
