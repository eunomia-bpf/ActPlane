"""Dependency-only cache backing check with actual bwrap and unchanged uv defaults."""
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import run as adapter

ROOT=adapter.ROOT
PROBE=r'''
import errno,fcntl,glob,hashlib,json,os,subprocess
from pathlib import Path
source=Path('/cache/link-source');source.write_bytes(b'cache-backing-probe\n')
destination=Path('/harbor/link-target')
result={}
try:os.link(source,destination);result['hardlink_errno']=0
except OSError as error:result['hardlink_errno']=error.errno
with source.open('rb') as src,Path('/harbor/clone-target').open('wb') as dst:
    try:fcntl.ioctl(dst.fileno(),0x40049409,src.fileno());result['reflink_errno']=0
    except OSError as error:result['reflink_errno']=error.errno
uv='/replay/bin/uv'
log=open('/replay/uv-copy.log','w')
for command in ([uv,'venv','--python','/usr/bin/python3','/harbor/.venv'],
                [uv,'-v','pip','install','--no-index','--python','/harbor/.venv/bin/python','/replay/certifi-2026.10.23-py3-none-any.whl']):
    subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
log.close()
cached=list(Path('/cache/uv').rglob('certifi/cacert.pem'))
installed=list(Path('/harbor/.venv').glob('lib/python*/site-packages/certifi/cacert.pem'))
assert len(cached)==1 and len(installed)==1,(cached,installed)
a,b=cached[0],installed[0]
result.update(uv_version=subprocess.check_output([uv,'--version'],text=True).strip(),
    source_device=a.stat().st_dev,destination_device=b.stat().st_dev,
    source_inode=a.stat().st_ino,destination_inode=b.stat().st_ino,
    uv_used_same_inode=a.stat().st_dev==b.stat().st_dev and a.stat().st_ino==b.stat().st_ino,
    cache_filesystem=subprocess.check_output(['stat','-f','-c','%T','/cache'],text=True).strip(),
    source_sha256=hashlib.sha256(a.read_bytes()).hexdigest(),destination_sha256=hashlib.sha256(b.read_bytes()).hexdigest(),
    uv_copy_log=Path('/replay/uv-copy.log').read_text())
print(json.dumps(result))
'''


def main():
    if os.readlink('/proc/self/ns/mnt')==os.readlink('/proc/1/ns/mnt'):raise RuntimeError('run preflight through unshare --mount --propagation private')
    root=ROOT/'cache-preflight'/str(time.time_ns());dynamic=root/'dynamic';dynamic.mkdir(parents=True)
    for name in ('toolchains','git-cache'):(dynamic/name).symlink_to(ROOT/'input/dynamic'/name,target_is_directory=True)
    shutil.copy2(ROOT/'input/dynamic/launch',dynamic/'launch')
    plan=next(r for r in csv.DictReader((ROOT/'harness/dynamic_plan.csv').open()) if r['dynamic_id']=='t00')
    subprocess.run(['git','--git-dir',str(ROOT/'input/dynamic/git-cache'/plan['repository'].replace('/','__')),
        'cat-file','-e',plan['base_commit']+'^{commit}'],check=True)
    rows=[]
    for backing in ('disk','tmpfs'):
        run=root/backing;run.mkdir()
        repo=adapter.runner.materialize(root,plan,run)
        cache=run/'cache';mount=None;worker=None
        try:
            if backing=='tmpfs':mount=adapter.mount_memory_cache(cache)
            before=adapter.memory_snapshot()
            worker,stderr,environment,affinity=adapter.runner.sandbox(root,plan,run,repo)
            (run/'replay/probe.py').write_text(PROBE)
            wheel=ROOT/'public-artifacts/certifi-2026.10.23-py3-none-any.whl'
            shutil.copy2(wheel,run/'replay'/wheel.name)
            response=adapter.runner.request(worker,dict(tag='apti6ectl',command=['/usr/bin/python3','/replay/probe.py'],shell=False,
                cwd=plan['sandbox_workdir'],timeout_s=120,log_path='/replay/probe.log',log_limit=1048576))
            (run/'response.json').write_text(json.dumps(response,indent=2))
            text=(run/'replay/probe.log').read_text()
            if response.get('exit_code')!=0:raise RuntimeError('actual uv cache control failed: '+text[-1000:])
            result=json.loads(text.strip().splitlines()[-1])
            if result['source_sha256']!=result['destination_sha256']:raise RuntimeError('uv copied bytes differ')
            result.update(backing=backing,mount_namespace=os.readlink('/proc/self/ns/mnt'),
                tmpfs_limit_bytes=adapter.TMPFS_LIMIT_BYTES if backing=='tmpfs' else 0,
                memory_headroom_before_bytes=before['memory_headroom_bytes'],memory_snapshot=json.dumps(before,sort_keys=True),
                uv_binary_sha256=hashlib.sha256((run/'replay/bin/uv').read_bytes()).hexdigest(),
                harness_sha256=hashlib.sha256((ROOT/'harness/dynamic_run.py').read_bytes()).hexdigest(),
                scope='Resource-only control; not a public trajectory, task score, or policy metric')
            rows.append(result)
        finally:
            if worker and worker.poll() is None:
                worker.stdin.write(json.dumps({'shutdown':True})+'\n');worker.stdin.flush();worker.wait(timeout=20)
            if worker:stderr.close()
            if mount:
                # This control contains only a known public wheel/probe. Its
                # bytes, logs and explicit hashes are persisted before unmount.
                subprocess.run(['tar','--acls','--xattrs','--numeric-owner','-czf',str(run/'cache-control-snapshot.tar.gz'),'--','cache'],cwd=run,check=True)
                subprocess.run(['gzip','-t',str(run/'cache-control-snapshot.tar.gz')],check=True)
                subprocess.run(['tar','--compare','--gzip','--file',str(run/'cache-control-snapshot.tar.gz')],cwd=run,check=True)
                subprocess.run(['umount',str(cache)],check=True)
    if rows[0]['hardlink_errno']!=rows[1]['hardlink_errno'] or rows[0]['uv_used_same_inode']!=rows[1]['uv_used_same_inode']:
        raise RuntimeError('cache backing changed observed default hardlink/copy behavior')
    out=ROOT.parent.parent/'replay/results/cache-preflight.csv'
    with out.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    print('Actual cache control passed:',[(r['backing'],r['hardlink_errno'],r['reflink_errno'],r['uv_used_same_inode']) for r in rows],flush=True)


def record_attempt(success,error=''):
    out=ROOT.parent.parent/'replay/results/cache-preflight-attempts.csv'
    rows=list(csv.DictReader(out.open())) if out.exists() else []
    known=(('20261029T124421Z.log','ModuleNotFoundError','wrong interpreter; replay dependency bashlex unavailable'),
           ('20261029T124550Z.log','actual cgroup memory budget unavailable','cgroup mount root queried instead of actual process membership path'))
    for name,marker,reason in known:
        log=ROOT.parent.parent/'logs'/name
        if log.exists() and marker in log.read_text(errors='replace') and not any(r['log']==name for r in rows):
            rows.append(dict(log=name,status='dependency_failure',reason=reason,scored_trial=0))
    log=Path(os.readlink('/proc/self/fd/1')).name
    rows=[r for r in rows if r['log']!=log]
    rows.append(dict(log=log,status='passed' if success else 'failed',reason=error,scored_trial=0))
    with out.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=['log','status','reason','scored_trial']);writer.writeheader();writer.writerows(rows)


if __name__=='__main__':
    try:main()
    except Exception as error:record_attempt(False,str(error));raise
    else:record_attempt(True)
