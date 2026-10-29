"""One separately declared official task trial, with unchanged native defaults."""
import argparse,asyncio,fcntl,json,os,time
from pathlib import Path
from harbor.job import Job
from harbor.models.job.config import JobConfig
from benchmark.expanded.dependencies import verifier_env
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark');RAW=Path(os.environ.get('BU_EXPANDED_RAW',str(BASE/'expanded-recovery')))
ROOT=BASE.parent.parent/'benchmark/expanded'

async def main():
 parser=argparse.ArgumentParser();parser.add_argument('task');parser.add_argument('condition',choices=['a','b','c']);parser.add_argument('--attempt',default='1');parser.add_argument('--preflight-only',action='store_true');args=parser.parse_args()
 assert (ROOT/'task-seals'/f'{args.task}.json').exists(),'Freeze cohort and calibration before first model outcome'
 assert (ROOT/'environment-freeze.json').exists(),'Freeze verified guest environment before any main outcome'
 environment=json.loads((ROOT/'environment-freeze.json').read_text());worker=environment['workers'][os.environ['BU_EXPANDED_WORKER']]
 assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==worker['boot_id'] and os.uname().release==worker['kernel_release'],'Wrong worker kernel: refuse before creating Docker resources'
 assert 'bpf' in Path('/sys/kernel/security/lsm').read_text().strip().split(',')
 slot=Path('/run/benign-utility-native-cell.lock').open('a+')
 fcntl.flock(slot,fcntl.LOCK_EX)
 for process in Path('/proc').glob('[0-9]*'):
  try:
   command=(process/'cmdline').read_bytes().split(b'\0')[0].decode()
   assert command!=str(BASE/'engine/process'),'An earlier native enforcer remains alive: refuse stacking before model generation'
  except (OSError,UnicodeDecodeError):pass
 os.environ.update(DOCKER_HOST=os.environ.get('BU_DOCKER_HOST','unix:///var/run/docker.sock'),DOCKER_CONFIG=str(BASE/'docker-config'),BU_TASK=args.task,BU_CONDITION=args.condition,BU_NETWORK_EFFECT='block')
 os.environ['BU_NETWORK_PREFLIGHT_ONLY']='1' if args.preflight_only else '0'
 config=JobConfig.model_validate(dict(job_name=f'{args.task}-{args.condition}-{args.attempt}',jobs_dir=str(RAW/('instrumentation-preflights' if args.preflight_only else 'jobs')),n_concurrent_trials=1,n_attempts=1,
  agents=[dict(import_path='benchmark.expanded.adapter:ExpandedTerminus',model_name='openai/zai/glm-5.3',base_url=os.environ['LITELLM_BASE_URL'],model_api_key_name='LITELLM_API_KEY')],
  tasks=[dict(path=str(BASE/'terminal-bench-2'/args.task),source='terminal-bench@2.0')],verifier=dict(env=verifier_env())))
 job=await Job.create(config);result=await job.run();print(result.model_dump_json(indent=2))

if __name__=='__main__':asyncio.run(main())
