"""Trusted model-only inference transport shared with the unprivileged VM.

The channel carries messages and responses only. Tool effects remain in the
official benchmark worker. Its fixed model and credential scope are selected
by the trusted parent, never by channel content.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import threading
import time
import uuid

from repoguard.agents.ollama_backend import GenResponse


def _private_dir():
    base=Path(os.environ['WS_RAW'])/'inference-private'
    base.mkdir(mode=0o700,exist_ok=True)
    base.chmod(0o700)
    p=Path(tempfile.mkdtemp(prefix='model-',dir=base))
    p.chmod(0o700)
    return p


def make_cli_backend(model, raw_dir):
    """Use the official CLI chat implementation with an empty tool registry.

    The extra registry flags implement the upstream adapter's stated intent
    on newer CLI versions whose tool catalog exceeds its old deny list.
    """
    from repoguard.agents.claude_cli_backend import ClaudeCLIBackend
    actual=model.split(':',1)[1] if ':' in model else model
    if actual.startswith('claude-cli-'):actual=actual[len('claude-cli-'):]
    private=_private_dir()
    raw_dir=Path(raw_dir)
    raw_dir.mkdir(parents=True,exist_ok=True)
    exe=shutil.which('claude')
    if not exe:raise RuntimeError('claude CLI not found')
    shim=private/'claude-model-only'
    # This executable is outside every worker-writable case subtree.
    program='''#!PYTHON
import ctypes, json, os, pathlib, subprocess, sys, time
def child_setup():
    ctypes.CDLL(None).prctl(1,9,0,0,0)
cmd=[EXE,*sys.argv[1:],"--tools","","--strict-mcp-config","--mcp-config",'{"mcpServers":{}}',"--no-session-persistence"]
p=subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,text=True,preexec_fn=child_setup,cwd=PRIVATE)
pathlib.Path(ENVELOPE).write_text(p.stdout)
sys.stdout.write(p.stdout);sys.stderr.write(p.stderr)
raise SystemExit(p.returncode)
'''.replace('PYTHON',sys.executable).replace('EXE',repr(exe)).replace('PRIVATE',repr(str(private))).replace('ENVELOPE',repr(str(private/'last-envelope.json')))
    shim.write_text(program);shim.chmod(0o500)

    class OfficialCLI(ClaudeCLIBackend):
        def chat(self,messages,options=None,stop=None):
            response=super().chat(messages,options=options,stop=stop)
            envelope=private/'last-envelope.json'
            if envelope.exists():
                try:
                    full=json.loads(envelope.read_text())
                    identities=list((full.get('modelUsage') or {}).keys())
                    response.raw.update(cli_model_identities=identities,
                        cli_is_error=bool(full.get('is_error')),
                        cli_model_alias=actual)
                    (raw_dir/'cli-identity.json').write_text(json.dumps({
                        'requested_alias':actual,'model_identities':identities,
                        'is_error':bool(full.get('is_error'))},indent=2))
                    # Preserve complete official envelope as raw evidence.
                    target=raw_dir/f'cli-envelope-{time.time_ns()}.json'
                    target.write_text(envelope.read_text())
                except (ValueError,OSError):pass
            if response.raw.get('cli_is_error'):
                raise RuntimeError('official Claude CLI returned is_error=true; raw envelope retained')
            return response

    backend=OfficialCLI(model=actual,cache_dir=str(private/'cache'))
    backend._claude=str(shim)
    return backend


class InferenceServer:
    """Per-cell fixed-model filesystem channel, usable across a 9p share."""
    def __init__(self,model,raw_dir):
        self.model=model
        self.raw_dir=Path(raw_dir)
        self.private=_private_dir()
        self.channel=self.raw_dir/f'.inference-{uuid.uuid4().hex}'
        self.stop=threading.Event()
        self.thread=None

    def __enter__(self):
        self.raw_dir.mkdir(parents=True,exist_ok=True)
        self.channel.mkdir(mode=0o700)
        os.chown(self.channel,65534,65534)
        self.fd=os.open(self.channel,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        if self.model.startswith('claude'):
            self.backend=make_cli_backend(self.model,self.private/'calls')
        else:
            from model_backend import ModelBackend
            self.backend=ModelBackend(self.model,self.private/'calls')
        (self.raw_dir/'inference-transport.json').write_text(json.dumps({
            'fixed_model':self.model,'channel':str(self.channel),
            'trusted_raw_dir':str(self.private),'tools':'official worker only'},indent=2))
        self.thread=threading.Thread(target=self._serve,daemon=True)
        self.thread.start()
        return self.channel

    def _serve(self):
        seen=set()
        while not self.stop.is_set():
            for name in os.listdir(self.fd):
                if not re.fullmatch(r'[a-f0-9]{32}\.request\.json',name) or name in seen:continue
                seen.add(name)
                try:
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
                    with os.fdopen(fd,'rb') as f:
                        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):raise ValueError('nonregular request')
                        payload=f.read(1048577)
                    if len(payload)>1048576:raise ValueError('request exceeds channel capacity')
                    data=json.loads(payload)
                    (self.private/name).write_bytes(payload)
                    if not isinstance(data.get('messages'),list):raise ValueError('missing messages')
                    for m in data['messages']:
                        if m.get('role') not in ('system','user','assistant','tool') or not isinstance(m.get('content'),str):
                            raise ValueError('invalid message')
                    answer=self.backend.chat(data['messages'],options=data.get('options'),stop=data.get('stop'))
                    result={'response':asdict(answer)}
                except Exception as exc:
                    result={'error':type(exc).__name__,'detail':str(exc)}
                target=name.replace('.request.json','.response.json')
                (self.private/target).write_text(json.dumps(result,ensure_ascii=False))
                tmp=target+'.'+uuid.uuid4().hex+'.tmp'
                fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
                os.fchown(fd,65534,65534)
                with os.fdopen(fd,'w') as f:json.dump(result,f,ensure_ascii=False)
                os.rename(tmp,target,src_dir_fd=self.fd,dst_dir_fd=self.fd)
            self.stop.wait(.05)

    def __exit__(self,*_):
        self.stop.set()
        if self.thread:self.thread.join(timeout=665)
        if self.thread and self.thread.is_alive():
            raise RuntimeError('inference transport did not finish its active request')
        os.close(self.fd)


def client_chat(channel,messages,options=None,stop=None):
    channel=Path(channel)
    name=uuid.uuid4().hex
    request=channel/f'{name}.request.json'
    temp=channel/f'{name}.tmp'
    temp.write_text(json.dumps({'messages':messages,'options':options,'stop':stop},ensure_ascii=False))
    temp.chmod(0o600)
    temp.rename(request)
    response=channel/f'{name}.response.json'
    deadline=time.monotonic()+660
    while not response.exists():
        if time.monotonic()>deadline:raise TimeoutError('inference channel response deadline')
        time.sleep(.05)
    result=json.loads(response.read_text())
    if 'error' in result:raise RuntimeError(f"{result['error']}: {result.get('detail','')}")
    return GenResponse(**result['response'])
