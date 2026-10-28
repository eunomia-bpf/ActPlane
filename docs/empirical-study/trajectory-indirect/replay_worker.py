#!/usr/bin/env python3
"""Persistent, untraced sandbox coordinator. Tagged children alone are observed."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


def drain(stream,path,limit,stats):
    size=0
    with open(path,'wb') as out:
        while True:
            data=stream.read(65536)
            if not data:break
            if size<limit:out.write(data[:limit-size])
            size+=len(data)
    stats['stdout_bytes']=size
    stats['stdout_truncated']=int(size>limit)


def job(request):
    start=time.monotonic()
    cwd=request['cwd']
    tag=request.get('tag')
    fd_read,fd_write=os.pipe()
    os.set_blocking(fd_read,False)
    env=os.environ.copy()
    env['AP_REPLAY_CWD_FD']=str(fd_write)
    command=request['command']
    if request.get('shell'):
        prefix='trap \'__ap_status=$?; builtin pwd -P >&"$AP_REPLAY_CWD_FD"; exit $__ap_status\' EXIT\n'
        argv=['/bin/bash','--noprofile','--norc','-c',prefix+command]
    else:
        argv=command
    if tag:argv=['/replay/launch',tag]+argv
    stats={}
    try:
        proc=subprocess.Popen(argv,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                              start_new_session=True,pass_fds=(fd_write,))
        os.close(fd_write)
        thread=threading.Thread(target=drain,args=(proc.stdout,request['log_path'],request.get('log_limit',2097152),stats),daemon=True)
        thread.start()
        timeout=False
        try:
            code=proc.wait(timeout=request['timeout_s'])
        except subprocess.TimeoutExpired:
            timeout=True
            os.killpg(proc.pid,signal.SIGKILL)
            code=proc.wait(timeout=10)
        thread.join(timeout=.15)
        try:
            reported=os.read(fd_read,65536).decode().strip().splitlines()
        except BlockingIOError:
            reported=[]
        return dict(exit_code=code,timed_out=int(timeout),cwd_after=reported[-1] if reported else cwd,
                    cwd_reported=int(bool(reported)),elapsed_s=round(time.monotonic()-start,4),**stats)
    except Exception as exc:
        try:os.close(fd_write)
        except OSError:pass
        Path(request['log_path']).write_text(type(exc).__name__+': '+str(exc))
        return dict(exit_code=127,timed_out=0,cwd_after=cwd,cwd_reported=0,
                    elapsed_s=round(time.monotonic()-start,4),worker_error=type(exc).__name__+': '+str(exc))
    finally:
        os.close(fd_read)


print(json.dumps({'worker_ready':True}),flush=True)
for line in sys.stdin:
    try:
        request=json.loads(line)
        if request.get('shutdown'):break
        result=job(request)
    except Exception as exc:
        result={'worker_protocol_error':str(exc)}
    print(json.dumps(result),flush=True)
