"""Run the existing native mechanism control separately in each guest kernel."""
from concurrent.futures import ThreadPoolExecutor
import subprocess
from pathlib import Path
ROOT=Path('/workspaces/exp/benign-utility/benchmark/expanded')
initial=ROOT/'initial-guest-environment-freeze.json'
if not initial.exists():initial.write_bytes((ROOT/'environment-freeze.json').read_bytes())
def capture(i):
    worker=f'worker{i}';port=2246+i
    command=['ssh','-i','/tmp/benign-utility-vm/id_ed25519','-p',str(port),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','root@127.0.0.1',f'bash /workspaces/exp/benign-utility/src/benchmark/expanded/guest_control.sh {worker} {port}']
    subprocess.run(command,check=True)
with ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(capture,(1,2,3)))
subprocess.run(['python3','-B','-m','benchmark.expanded.amend','freeze'],check=True)
