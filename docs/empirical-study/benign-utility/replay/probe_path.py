"""Isolated observer buffer/load diagnostic; no official trajectory is modified."""
import ctypes
import csv
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT=Path(os.environ['WS_RAW'])/'replay/observer-probe'
if len(sys.argv)>1 and sys.argv[1]=='--read':
    ctypes.CDLL(None).prctl(15,b'apti6eprobe',0,0,0)
    os.execv(sys.executable,[sys.executable,'-c','from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()',sys.argv[2]])
    raise SystemExit
ROOT.mkdir(exist_ok=True)
target=ROOT
for i in range(8):target=target/('x'*60+str(i))
target.mkdir(parents=True,exist_ok=True)
target=target/'.env';target.write_text('instrumentation fixture only\n')
source=(Path(__file__).parent/'source_observer.bt').read_text()
rows=[]
for size in (512,1024,4096):
    text=re.sub(r'path\(args.file->f_path, \d+\)',f'path(args.file->f_path, {size})',source)
    program=ROOT/f'path-{size}.bt';program.write_text(text)
    output=ROOT/f'path-{size}.jsonl';error=ROOT/f'path-{size}.stderr'
    with output.open('w') as stdout,error.open('w') as stderr:
        process=subprocess.Popen(['bpftrace','-f','json',str(program),'0'],stdout=stdout,stderr=stderr,
            env={**os.environ,'BPFTRACE_MAX_STRLEN':str(size)})
        end=time.monotonic()+30
        while time.monotonic()<end and process.poll() is None and 'SOURCE_OBSERVER_READY' not in output.read_text():time.sleep(.1)
        ready='SOURCE_OBSERVER_READY' in output.read_text()
        if ready:
            subprocess.run([sys.executable,str(Path(__file__).resolve()),'--read',str(target)],check=True)
            time.sleep(.5)
        if process.poll() is None:process.send_signal(signal.SIGINT)
        process.wait(timeout=20)
    data=output.read_text();errors=error.read_text()
    seen=ready and any(r.get('type')=='printf' and ('|apti6eprobe|' in str(r.get('data',''))) and str(target) in str(r.get('data',''))
        for r in (json.loads(line) for line in data.splitlines() if line.strip()))
    row=dict(path_bytes=size,ready=ready,complete_long_source_path_seen=seen,stderr=errors[-500:],helper_errors=data.count('helper_error'))
    rows.append(row);print(row,flush=True)
    if ready and seen and not row['helper_errors']:break
(ROOT/'path-probe.json').write_text(json.dumps(rows,indent=2))
output=ROOT.parent.parent.parent/'replay/results/observer-probe.csv'
with output.open('w',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
