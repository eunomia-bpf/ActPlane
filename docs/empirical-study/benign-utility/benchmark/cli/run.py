"""One official Harbor installed-Codex preflight, separate from Terminus trials."""
import argparse
import asyncio
import hashlib
import importlib.metadata
import inspect
import json
import os
import subprocess
import harbor.agents.installed.codex
from pathlib import Path

from harbor.job import Job
from harbor.models.job.config import JobConfig
from benchmark.dependencies import verifier_env

BASE = Path('/workspaces/exp/benign-utility/raw/benchmark')
RAW = BASE.parent / 'benchmark-cli'

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('task')
    parser.add_argument('condition', choices=['a', 'c', 'c-block'])
    parser.add_argument('--attempt', default='preflight-1')
    args = parser.parse_args()
    stat = os.statvfs('/workspaces')
    if 1 - stat.f_bavail / stat.f_blocks >= .85:
        raise RuntimeError('Shared disk at or above 85%; official CLI preflight deferred')
    os.environ['DOCKER_HOST'] = 'unix://' + str(BASE / 'docker.sock')
    os.environ['DOCKER_CONFIG'] = str(BASE / 'docker-config')
    auth_home = Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex')))
    auth_path = (auth_home / 'auth.json').resolve(strict=True)
    if not auth_path.is_file():
        raise RuntimeError('Existing Workspace Codex auth.json is unavailable')
    os.environ['CODEX_AUTH_JSON_PATH'] = str(auth_path)
    # Harbor resolves the existing Workspace auth file without credential contents
    # entering the job configuration or reproducibility receipts.
    for name in ('OPENAI_API_KEY', 'CODEX_API_KEY', 'OPENAI_BASE_URL'):
        os.environ.pop(name, None)
    agent = dict(model_name='openai/gpt-6-astra', env={'METHOD': 'script'})
    if args.condition == 'a':
        agent['name'] = 'codex'
    else:
        agent['import_path'] = ('benchmark.cli.adapter:ControllerBlockCodex'
            if args.condition == 'c-block' else 'benchmark.cli.adapter:ControllerCodex')
    config = JobConfig.model_validate(dict(
        job_name=f'{args.task}-{args.condition}-{args.attempt}',
        jobs_dir=str(RAW / 'jobs'), n_concurrent_trials=1, n_attempts=1,
        verifier=dict(env=verifier_env()),
        agents=[agent],
        tasks=[dict(path=str(BASE / 'terminal-bench-2' / args.task),
                    source='terminal-bench@2.0')],
    ))
    RAW.mkdir(parents=True, exist_ok=True)
    evidence = RAW.parent.parent / 'benchmark/cli/results'
    evidence.mkdir(parents=True, exist_ok=True)
    native_source = Path(inspect.getfile(harbor.agents.installed.codex))
    provenance = dict(harbor_version=importlib.metadata.version('harbor'),
        codex_agent_source_sha256=hashlib.sha256(native_source.read_bytes()).hexdigest(),
        dataset_commit=subprocess.check_output(['git', '-C', str(BASE / 'terminal-bench-2'), 'rev-parse', 'HEAD'], text=True).strip(),
        disk_used_fraction=1 - stat.f_bavail / stat.f_blocks,
        auth_mode='native CODEX_AUTH_JSON_PATH from existing Workspace CODEX_HOME',
        cli_behavior_defaults=True, official_verifier_bytes=True, config=config.model_dump(mode='json'))
    (evidence / f'{config.job_name}-provenance.json').write_text(json.dumps(provenance, indent=2))
    job = await Job.create(config)
    result = await job.run()
    print(result.model_dump_json(indent=2))

if __name__ == '__main__':
    asyncio.run(main())