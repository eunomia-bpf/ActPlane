#!/usr/bin/env python3
"""Reproduce positive and negative observer calibration outside scientific replays.

Run only when no other bpftrace process is active, because observer seed tags are
visible to all instances. Each invocation retains a fresh timestamped receipt.
"""
import argparse
import json
from pathlib import Path
import signal
import subprocess
import time

from analyze import HERE
from calibration_check import check
from dynamic_run import observer_start


POSITIVE="""printf visible > direct.txt
/usr/bin/python3 - <<'PY'
import os,subprocess
fd=os.open('hidden.txt',os.O_CREAT|os.O_WRONLY,0o600)
os.write(fd,b'hello')
os.close(fd)
fd=os.open('vector.txt',os.O_CREAT|os.O_WRONLY,0o600)
os.writev(fd,[b'a',b'b'])
os.pwrite(fd,b'c',1)
os.close(fd)
os.truncate('hidden.txt',1)
source=os.open('direct.txt',os.O_RDONLY)
target=os.open('copied.txt',os.O_CREAT|os.O_WRONLY,0o600)
os.copy_file_range(source,target,1)
os.close(source)
os.close(target)
subprocess.run(['/bin/true'],check=True)
subprocess.run(['/bin/false'],check=False)
PY
"""
NEGATIVE="""/usr/bin/python3 - <<'PY'
import os
fd=os.open('allocated-only',os.O_CREAT|os.O_WRONLY,0o600)
os.posix_fallocate(fd,0,4096)
os.close(fd)
os.write(1,b'hello\\n')
PY
"""
FAILED_WRITE="""/usr/bin/python3 - <<'PY'
import errno,os,resource,signal
signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE,(0,0))
fd=os.open('failed-write.txt',os.O_CREAT|os.O_WRONLY,0o600)
assert os.write(fd,b'')==0
try:
    os.write(fd,b'x')
except OSError as exc:
    assert exc.errno==errno.EFBIG
else:
    raise AssertionError('regular-file write unexpectedly succeeded')
os.close(fd)
os.write(1,b'failure-confirmed\\n')
PY
"""


def calibrate(raw):
    if subprocess.run(['pgrep','-x','bpftrace'],capture_output=True).returncode==0:
        raise SystemExit('Finish active tracing first. Calibration must not contaminate another observer.')
    run=raw/'dynamic'/('calibration-repeat-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()))
    run.mkdir(parents=True)
    (run/'project').mkdir()
    launch=raw/'dynamic/launch'
    if not launch.exists():subprocess.run(['gcc','-O2',str(HERE/'launch.c'),'-o',str(launch)],check=True)
    observer,stdout,stderr=observer_start(run)
    try:
        common=['bwrap','--unshare-all','--die-with-parent','--cap-drop','ALL','--ro-bind','/usr','/usr',
                '--ro-bind','/etc','/etc','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
                '--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp',
                '--bind',str(run/'project'),'/project','--ro-bind',str(launch),'/launch',
                '--clearenv','--setenv','PATH','/usr/bin:/bin','--chdir','/project','/launch']
        for label,tag,command in [('positive','apti6e999999',POSITIVE),('negative','apti6e999998',NEGATIVE),
                                  ('failed-write','apti6e999997',FAILED_WRITE)]:
            (run/(label+'.sh')).write_text(command)
            result=subprocess.run(common+[tag,'/bin/bash','-c',command],capture_output=True,text=True,timeout=30)
            (run/(label+'.stdout')).write_text(result.stdout)
            (run/(label+'.stderr')).write_text(result.stderr)
            (run/(label+'.json')).write_text(json.dumps(dict(exit_code=result.returncode,tag=tag)))
            if result.returncode:raise RuntimeError(label+' calibration command failed')
    finally:
        observer.send_signal(signal.SIGINT)
        observer.wait(timeout=30);stdout.close();stderr.close()
    check(raw,evidence=run/'observer.jsonl')
    print('Calibration evidence:',run)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True)
    calibrate(p.parse_args().raw)
