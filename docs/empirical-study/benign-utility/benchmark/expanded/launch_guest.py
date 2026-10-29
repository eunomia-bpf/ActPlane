"""Launch the native guest matrix without exposing the existing model key."""
import os,shlex,subprocess
from pathlib import Path
ROOT=Path('/workspaces/exp/benign-utility')
RAW=ROOT/'raw/benchmark/expanded-vm';RAW.mkdir(parents=True,exist_ok=True)
target=RAW/'model.env'
fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'w') as stream:
    for name in ('LITELLM_BASE_URL','LITELLM_API_KEY'):
        value=os.environ[name];assert value
        stream.write('export '+name+'='+shlex.quote(value)+'\n')
os.chmod(target,0o600)
command=['python3','-B','-m','benchmark.expanded.matrix']
raise SystemExit(subprocess.run(command).returncode)
