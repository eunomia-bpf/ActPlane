"""One separately declared official task trial, with unchanged native defaults."""
import argparse,asyncio,json,os
from pathlib import Path
from harbor.job import Job
from harbor.models.job.config import JobConfig
from benchmark.dependencies import verifier_env
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark');RAW=BASE/'expanded'
ROOT=BASE.parent.parent/'benchmark/expanded'

async def main():
 parser=argparse.ArgumentParser();parser.add_argument('task');parser.add_argument('condition',choices=['a','b','c']);parser.add_argument('--attempt',default='1');parser.add_argument('--preflight-only',action='store_true');args=parser.parse_args()
 assert (ROOT/'task-seals'/f'{args.task}.json').exists(),'Freeze cohort and calibration before first model outcome'
 os.environ.update(DOCKER_HOST='unix://'+str(BASE/'docker.sock'),DOCKER_CONFIG=str(BASE/'docker-config'),BU_TASK=args.task,BU_CONDITION=args.condition,BU_NETWORK_EFFECT='block')
 os.environ['BU_NETWORK_PREFLIGHT_ONLY']='1' if args.preflight_only else '0'
 config=JobConfig.model_validate(dict(job_name=f'{args.task}-{args.condition}-{args.attempt}',jobs_dir=str(RAW/('instrumentation-preflights' if args.preflight_only else 'jobs')),n_concurrent_trials=1,n_attempts=1,
  agents=[dict(import_path='benchmark.expanded.adapter:ExpandedTerminus',model_name='openai/zai/glm-5.3',base_url=os.environ['LITELLM_BASE_URL'],model_api_key_name='LITELLM_API_KEY')],
  tasks=[dict(path=str(BASE/'terminal-bench-2'/args.task),source='terminal-bench@2.0')],verifier=dict(env=verifier_env())))
 job=await Job.create(config);result=await job.run();print(result.model_dump_json(indent=2))

if __name__=='__main__':asyncio.run(main())
