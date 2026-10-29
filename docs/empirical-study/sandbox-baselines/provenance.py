#!/usr/bin/env python3
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import shutil

from study import HERE, LANE, RAW, VENDOR
OUT = LANE/'results'
OUT.mkdir(exist_ok=True)
def run(args):
    p=subprocess.run(args,text=True,capture_output=True)
    return p.stdout.strip() or p.stderr.strip()
def write(name, rows):
    with (OUT/name).open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
rows=[]
for label, cmd in [('codex',[str(RAW/'codex-real'),'--version']),
                   ('srt',[str(RAW/'tools/node_modules/.bin/srt'),'--version']),
                   ('docker',['docker','--version']),('kernel',['uname','-r']),
                   ('bubblewrap',['bwrap','--version']),('strace',['strace','--version']),
                   ('python',['python3','--version']),('node',['node','--version']),
                   ('pytest',['pytest','--version']),
                   ('pytest-module',['python3','-m','pytest','--version']),
                   ('docker-pytest',['docker','run','--rm','actplane-sandbox-baselines:trixie','pytest','--version']),
                   ('docker-pytest-module',['docker','run','--rm','actplane-sandbox-baselines:trixie','python3','-m','pytest','--version']),
                   ('docker-image',['docker','image','inspect','actplane-sandbox-baselines:trixie','--format','{{.Id}}']),
                   ('disk',['df','-h','/workspaces'])]:
    rows.append(dict(component=label,version=run(cmd).splitlines()[0],utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())))
write('versions.csv',rows)
write('host-packages.csv',[dict(package=p,version=run(['dpkg-query','-W','-f=${Version}',p])) for p in ('python3','python3-pytest','bubblewrap','socat','ripgrep','strace','python3-matplotlib')])
files=[]
for p in sorted(VENDOR.glob('*.py')):
    upstream=Path('/workspaces/lanes/translation-models/docs/empirical-study/translation-models')/p.name
    h=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
    files.append(dict(file=p.name,sha256=h(p),upstream_sha256=h(upstream),identical=int(p.read_bytes()==upstream.read_bytes())))
write('replayer-hashes.csv',files)
package=RAW/'tools/node_modules/@anthropic-ai/sandbox-runtime'
(OUT/'srt-cli-default-source.txt').write_text('\n'.join(
    x for x in (package/'dist/cli.js').read_text().splitlines()
    if any(k in x for k in ('getDefaultConfig','allowedDomains:','deniedDomains:','denyRead:','allowWrite:','denyWrite:'))))
(OUT/'codex-sandbox-help.txt').write_text(run([str(RAW/'codex-real'),'sandbox','--help'])+'\n')
(OUT/'docker-info.txt').write_text(run(['docker','info'])+'\n')
(OUT/'docker-image.json').write_text(run(['docker','image','inspect','actplane-sandbox-baselines:trixie'])+'\n')
(OUT/'docker-package-versions.txt').write_text(run(['docker','run','--rm','actplane-sandbox-baselines:trixie','dpkg-query','-W'])+'\n')
(OUT/'docker-security-status.txt').write_text(run(['docker','run','--rm','actplane-sandbox-baselines:trixie','cat','/proc/self/status'])+'\n')
shutil.copy(RAW/'tools/package-lock.json',OUT/'srt-package-lock.json')
write('optional-lanes.csv',[dict(item='gVisor',available=int(bool(run(['sh','-c','command -v runsc']))),reason='not installed; optional installation omitted'),
    dict(item='injection-bench',available=int(Path('/workspaces/exp/injection-bench').exists()),reason='inspect folder only; never block')])
write('configurations.csv',[
 dict(system='control',config='no sandbox',network='Workspace network',scope='matched replay control'),
 dict(system='codex',config='empty CODEX_HOME; sandbox_mode=workspace-write; default network off',network='default denied',scope='official requested preset'),
 dict(system='srt',config='no ~/.srt-settings.json; built-in default',network='empty allowlist',scope='standalone SRT defaults'),
 dict(system='srt-cwd',config=(HERE/'srt-cwd.json').read_text().strip(),network='empty allowlist',scope='documented enabled-harness cwd-write analogue; not standalone default'),
 dict(system='docker',config='default runtime security; workload/input/output bind mounts only',network='default bridge; nested DNS failure recorded',scope='default Docker security boundary'),
])
print('provenance exported',flush=True)
