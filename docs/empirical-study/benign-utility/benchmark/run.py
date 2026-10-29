"""Run one official Harbor trial; condition is instrumentation in Terminus only."""
import argparse,asyncio,json,os,sys
from pathlib import Path
from harbor.job import Job
from harbor.models.job.config import JobConfig

RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
async def main():
 p=argparse.ArgumentParser();p.add_argument('task');p.add_argument('condition',choices=['a','b','c']);p.add_argument('--attempt',default='1');args=p.parse_args()
 os.environ['DOCKER_HOST']='unix://'+str(RAW/'docker.sock')
 os.environ['DOCKER_CONFIG']=str(RAW/'docker-config')
 os.environ['OPENAI_API_KEY']='local-no-key'
 os.environ['BU_CONDITION']=args.condition
 os.environ['BU_TASK']=args.task
 config=JobConfig.model_validate(dict(job_name=f'{args.task}-{args.condition}-{args.attempt}',jobs_dir=str(RAW/'jobs'),n_concurrent_trials=1,n_attempts=1,
   agents=[dict(import_path='benchmark.adapter:InstrumentedTerminus',model_name='openai/qwen3.8-27b-nvfp4',base_url='http://qwen38-vllm.models.svc.cluster.local:8000/v1',model_api_key_name='OPENAI_API_KEY')],
   tasks=[dict(path=str(RAW/'terminal-bench-2'/args.task),source='terminal-bench@2.0')]))
 job=await Job.create(config)
 result=await job.run()
 print(result.model_dump_json(indent=2))
if __name__=='__main__':asyncio.run(main())
