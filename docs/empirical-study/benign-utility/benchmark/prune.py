"""Reclaim only this lane's unused Docker images/cache, preserving active tasks."""
import json,os,shutil,subprocess
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
env={**os.environ,'DOCKER_HOST':'unix://'+str(RAW/'docker.sock'),'DOCKER_CONFIG':str(RAW/'docker-config')}
print('BEFORE',json.dumps(shutil.disk_usage('/workspaces')._asdict()),flush=True)
for command in (['docker','image','prune','-af'],['docker','builder','prune','-af']):
 subprocess.run(command,env=env,check=True)
print('AFTER',json.dumps(shutil.disk_usage('/workspaces')._asdict()),flush=True)
