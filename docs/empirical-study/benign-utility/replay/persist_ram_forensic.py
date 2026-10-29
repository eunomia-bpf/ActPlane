"""Persist a finished RAM-cache forensic snapshot without a second disk copy.

Only the completed t00 resource-retention controller is briefly suspended.
Actual tool actions and their timings have already ended. Both ordinary gzip
archives are compared against every retained file before closed disk copies
are removed; the original controller then resumes its normal unmount path.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

ROOT=Path(os.environ['WS_RAW'])/'replay'
RUN=ROOT/'open-audit-block-broad/dynamic/runs/t00'
GROUPS=(('runtime.tar.gz',('repo','venv','tmp','home')),
        ('runtime-cache.tar.gz',('cache',)))

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        while data:=stream.read(1048576):h.update(data)
    return h.hexdigest()

def starttime(pid):
    return Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1].split()[19]

def inside(pid,started):
    metadata=json.loads((RUN/'utility-metadata.json').read_text())
    done=json.loads((RUN/'done.json').read_text())
    assert metadata['cache_controller_workspace_pid']==pid and starttime(pid)==started
    assert done['executed_calls']==done['recorded_calls'] and not done['fatal']
    assert not Path('/proc/'+str(metadata['workspace_popen_pid'])).exists()
    cache=RUN/'cache'
    assert cache.is_mount() and metadata['cache_backing']=='tmpfs'
    assert os.readlink('/proc/self/ns/mnt')==metadata['controller_mount_namespace']
    scratch=cache/'.retention-archives'
    scratch.mkdir(exist_ok=False)
    receipt=dict(controller_pid=pid,controller_starttime=started,
                 completed_tool_actions=done['executed_calls'],source_unchanged=True,archives=[])
    target=RUN/'ram-retention-receipt.json'
    target.write_text(json.dumps(receipt,indent=2))
    base=['tar','--acls','--xattrs','--numeric-owner','--atime-preserve=system',
          '--exclude=cache/.retention-archives','-I','gzip -1']
    for name,groups in GROUPS:
        temporary=scratch/name
        print('RAM-stage verified closed archive:',name,flush=True)
        subprocess.run(base+['-cf',str(temporary),'--',*groups],cwd=RUN,check=True)
        subprocess.run(['gzip','-t',str(temporary)],check=True)
        subprocess.run(['tar','--acls','--xattrs','--compare','--gzip',
                        '--exclude=cache/.retention-archives','--file',str(temporary)],cwd=RUN,check=True)
        receipt['archives'].append(dict(name=name,bytes=temporary.stat().st_size,sha256=digest(temporary),
            verification='gzip test and complete GNU tar comparison of bytes/modes/owners/times/links/ACLs/xattrs'))
        target.write_text(json.dumps(receipt,indent=2))
    reclaim=sum(int(subprocess.check_output(['du','-s','-B1',str(RUN/name)],text=True).split()[0])
                for name in GROUPS[0][1])
    space=shutil.disk_usage(RUN)
    needed=sum(item['bytes'] for item in receipt['archives'])
    if space.used-reclaim+needed>=space.total*.85:
        raise RuntimeError('verified archives still cannot fit below85; originals retained')
    # Mark the destructive phase conservatively before its first unlink. A
    # partial deletion must never authorize scratch cleanup or controller resume.
    receipt.update(source_unchanged=False,verified_ram_archives_hold_all_original_bytes=True,
                   reclaimed_disk_bytes=reclaim)
    target.write_text(json.dumps(receipt,indent=2))
    for name in GROUPS[0][1]:
        path=(RUN/name).resolve()
        if not path.is_relative_to(RUN.resolve()) or path.is_symlink():raise ValueError('closed payload escaped run')
        shutil.rmtree(path)
    for item in receipt['archives']:
        source=scratch/item['name'];partial=RUN/(item['name']+'.partial-retention')
        with source.open('rb') as src,partial.open('wb') as dst:
            while data:=src.read(1048576):
                while shutil.disk_usage(RUN).used+len(data)>=shutil.disk_usage(RUN).total*.85:
                    print('RAM archives retained; waiting below85 before persist',flush=True);time.sleep(5)
                dst.write(data)
            dst.flush();os.fsync(dst.fileno())
        assert digest(partial)==item['sha256']
        partial.rename(RUN/item['name'])
    receipt.update(all_original_bytes_persisted=True,finished_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
    target.write_text(json.dumps(receipt,indent=2))
    shutil.rmtree(scratch)
    print(json.dumps(receipt,indent=2),flush=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--inside',nargs=2);args=parser.parse_args()
    if args.inside:return inside(int(args.inside[0]),args.inside[1])
    # Wait for the retention retry's existing sleep, never suspend its tar
    # reader, a live task worker, or a renamed snapshot mid-operation.
    while True:
        if RUN.exists() and (RUN/'utility-metadata.json').exists():
            metadata=json.loads((RUN/'utility-metadata.json').read_text())
            pid=metadata['cache_controller_workspace_pid'];started=starttime(pid)
            command=Path(f'/proc/{pid}/cmdline').read_bytes()
            assert b'replay/run.py' in command and b'--open-audit' in command and b't00' in command
            children=Path(f'/proc/{pid}/task/{pid}/children')
            if not children.read_text().strip() and Path(f'/proc/{pid}/wchan').read_text().strip()=='hrtimer_nanosleep':
                os.kill(pid,signal.SIGSTOP)
                if children.read_text().strip() or not RUN.exists():
                    os.kill(pid,signal.SIGCONT);time.sleep(.1);continue
                break
        time.sleep(.1)
    print('Quiesced completed retention controller:',pid,started,flush=True)
    result=subprocess.run(['nsenter','-t',str(pid),'-m','--','python3',str(Path(__file__).resolve()),'--inside',str(pid),started])
    receipt=json.loads((RUN/'ram-retention-receipt.json').read_text()) if (RUN/'ram-retention-receipt.json').exists() else {}
    if result.returncode==0 or receipt.get('source_unchanged'):
        if result.returncode:
            subprocess.run(['nsenter','-t',str(pid),'-m','--','python3','-c',
                'import shutil;shutil.rmtree('+repr(str(RUN/'cache/.retention-archives'))+',ignore_errors=True)'],check=True)
        if starttime(pid)==started:os.kill(pid,signal.SIGCONT)
    else:
        raise RuntimeError('retention repair failed after verified RAM staging; controller remains safely paused')
    raise SystemExit(result.returncode)

if __name__=='__main__':main()
