"""Thin measurement/defense adapter over Harbor's unmodified Terminus 2."""
import asyncio,json,os,signal,subprocess,time,shutil,uuid
from pathlib import Path
from harbor.agents.terminus_2.terminus_2 import Terminus2

RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
OBSERVER_STRING_BYTES=1024
HOOK_ENV_NAMES=('ACTPLANE_HOOK_PROFILE','ACTPLANE_ENABLE_ADVANCED_HOOKS','ACTPLANE_ADVANCED_TRACEPOINTS')
class InstrumentedTerminus(Terminus2):
 def __init__(self,logs_dir,*args,**kwargs):
  self.bu_logs=Path(logs_dir);self.bu_condition=os.environ['BU_CONDITION'];self.bu_task=os.environ['BU_TASK'];self.bu_effect=os.environ.get('BU_NETWORK_EFFECT','kill');self.bu_index=0;self.bu_loader=None;self.bu_observer=None
  super().__init__(logs_dir,*args,**kwargs)
 async def setup(self,environment):
  try:await self._setup_measured(environment)
  except BaseException:
   self._stop_observers()
   raise
 async def _setup_measured(self,environment):
  await super().setup(environment)
  # Record instruction files only; do not synthesize project rules.
  rules=await environment.exec(command="find /app -type f \\( -name AGENTS.md -o -name CLAUDE.md -o -name .cursorrules \\) -print 2>/dev/null",timeout_sec=30)
  (self.bu_logs/'project-instruction-paths.txt').write_text(rules.stdout or '')
  if rules.stdout:raise RuntimeError('Repository instructions present: translate applicable project rules before trial')
  inventory=await environment.exec(command="find /app /root/.ssh /root/.aws /root/.gemini /etc/secrets -type f \\( -name '.env*' -o -name '*.pem' -o -name '*.key' -o -name id_rsa -o -name id_ed25519 -o -name '*credentials*' -o -name oauth_creds.json \\) -printf '%p\\n' 2>/dev/null",timeout_sec=30)
  (self.bu_logs/'source-path-inventory.txt').write_text(inventory.stdout or '')
  pane=await environment.exec(command="tmux display-message -p '#{pane_pid}'")
  cid=(await environment._run_docker_compose_command(['ps','-q','main'])).stdout.strip()
  init=int(subprocess.check_output(['docker','inspect','--format','{{.State.Pid}}',cid],text=True).strip())
  ns=os.readlink(f'/proc/{init}/ns/pid');nspid=int(pane.stdout.strip());root=None
  for path in Path('/proc').glob('[0-9]*'):
   try:
    if os.readlink(path/'ns/pid')==ns:
     match=next(x for x in (path/'status').read_text().splitlines() if x.startswith('NSpid:'))
     if int(match.split()[-1])==nspid:root=int(path.name);break
   except (OSError,StopIteration):pass
  if root is None:raise RuntimeError('Could not map tmux pane shell to host PID')
  # /proc is mounted in the Workspace PID namespace, whereas BPF uses initial
  # kernel PIDs. Obtain an independent receipt from the actual persistent shell.
  workspace_pid=root;marker='bu'+uuid.uuid4().hex[:10]
  mapping=self.bu_logs/'pid-mapping.bt';mapping_log=self.bu_logs/'pid-mapping.jsonl'
  mapping.write_text('BEGIN { printf("PID_MAPPER_READY\\n"); }\ntracepoint:syscalls:sys_enter_openat /comm == "'+marker+'"/ { printf("HOST_PID|%d\\n", curtask->tgid); exit(); }\n')
  with mapping_log.open('w') as stream:
   mapper=subprocess.Popen(['bpftrace','-f','json',str(mapping)],stdout=stream,stderr=subprocess.STDOUT)
   try:
    for _ in range(600):
     if 'PID_MAPPER_READY' in mapping_log.read_text():break
     if mapper.poll() is not None:raise RuntimeError('PID mapper failed')
     await asyncio.sleep(.1)
    else:raise RuntimeError('PID mapper startup timed out')
    await self._session.send_keys(f"printf '%s' {marker} >/proc/self/comm; : >/dev/null; printf '%s' bash >/proc/self/comm\n",block=False,min_timeout_sec=.2)
    for _ in range(100):
     if 'HOST_PID|' in mapping_log.read_text():break
     await asyncio.sleep(.1)
    else:raise RuntimeError('Persistent shell did not produce initial-PID receipt')
    import re
    root=int(re.search(r'HOST_PID\|(\d+)',mapping_log.read_text())[1])
    if root<=0 or 'helper_error' in mapping_log.read_text():raise RuntimeError('Invalid kernel PID receipt')
   finally:
    if mapper.poll() is None:mapper.send_signal(signal.SIGINT)
    mapper.wait(timeout=10)
  meta=dict(condition=self.bu_condition,task=self.bu_task,root_host_pid=root,root_workspace_pid=workspace_pid,root_namespace_pid=nspid,container_id=cid,root_pid_namespace=ns,attached_monotonic=time.monotonic(),scope='tmux pane shell and descendants; controller/model API outside scope',observer_string_bytes=OBSERVER_STRING_BYTES,requested_network_effect=self.bu_effect if self.bu_condition!='a' else 'none',engine_hook_environment={name:os.environ.get(name,'unset') for name in HOOK_ENV_NAMES})
  (self.bu_logs/'scope.json').write_text(json.dumps(meta,indent=2))
  self.bu_observer_log=(self.bu_logs/'observer.jsonl').open('w')
  observer=self.bu_logs/'observer.bt';shutil.copyfile(Path(__file__).parents[1]/'replay/source_observer.bt',observer)
  self.bu_observer=subprocess.Popen(['bpftrace','-f','json',str(observer),str(root)],env={**os.environ,'BPFTRACE_MAX_STRLEN':str(OBSERVER_STRING_BYTES),'BPFTRACE_MAX_MAP_KEYS':'262144'},stdout=self.bu_observer_log,stderr=subprocess.STDOUT)
  for _ in range(600):
   if 'SOURCE_OBSERVER_READY' in (self.bu_logs/'observer.jsonl').read_text():break
   if self.bu_observer.poll() is not None:raise RuntimeError('Observer failed: '+(self.bu_logs/'observer.jsonl').read_text()[-1000:])
   await asyncio.sleep(.1)
  else:raise RuntimeError('Observer never became ready')
  if self.bu_condition!='a':
   policy=(Path(__file__).parent/'policies'/f'{self.bu_condition}.dsl').read_text()
   if self.bu_effect=='block':
    assert policy.count('  kill connect')==1
    policy=policy.replace('  kill connect','  block connect')
   (self.bu_logs/'policy.dsl').write_text(policy)
   subprocess.run(['/workspaces/lanes/translation-models/target/release/actplane','--rule',policy,'compile','--out',str(self.bu_logs/'policy.bin'),'--force'],check=True,capture_output=True)
   self.bu_loader_log=(self.bu_logs/'engine.log').open('w')
   self.bu_loader=subprocess.Popen([str(RAW/'engine/process'),'--config',str(self.bu_logs/'policy.bin'),'--seed-pid',str(root)],stdout=self.bu_loader_log,stderr=subprocess.STDOUT)
   for _ in range(600):
    if 'ActPlane: ready' in (self.bu_logs/'engine.log').read_text():break
    if self.bu_loader.poll() is not None:raise RuntimeError('Engine failed: '+(self.bu_logs/'engine.log').read_text()[-500:])
    await asyncio.sleep(.1)
   else:raise RuntimeError('Engine never became ready')
  await self._session.send_keys('/bin/true\n',block=False,min_timeout_sec=.2)
  for _ in range(100):
   if f'|benchmark|{root}|' in (self.bu_logs/'observer.jsonl').read_text():break
   await asyncio.sleep(.1)
  else:raise RuntimeError('Independent observer did not confirm seeded shell effects')
  meta['kernel_root_verified']=True;meta['calibration_finished_ns']=time.monotonic_ns()
  (self.bu_logs/'scope.json').write_text(json.dumps(meta,indent=2))
 async def _execute_commands(self,commands,session):
  self._check_observers()
  original=session.send_keys
  async def measured(keystrokes,*args,**kwargs):
   self.bu_index+=1;index=self.bu_index
   with (self.bu_logs/'calls.jsonl').open('a') as f:f.write(json.dumps(dict(index=index,unit='tool_call',start_ns=time.monotonic_ns(),keystrokes=keystrokes,duration_sec=kwargs.get('min_timeout_sec'))) +'\n')
   try:return await original(keystrokes,*args,**kwargs)
   finally:
    with (self.bu_logs/'calls.jsonl').open('a') as f:f.write(json.dumps(dict(index=index,end_ns=time.monotonic_ns()))+'\n')
  session.send_keys=measured
  try:
   result=await super()._execute_commands(commands,session)
   self._check_observers()
   return result
  finally:
   session.send_keys=original
 async def run(self,*args,**kwargs):
  try:
   self._check_observers()
   result=await super().run(*args,**kwargs)
   self._check_observers()
   return result
  finally:self._stop_observers()
 def _check_observers(self):
  for name,proc in (('engine',self.bu_loader),('observer',self.bu_observer)):
   if proc is not None and proc.poll() is not None:raise RuntimeError(f'{name} exited unexpectedly ({proc.returncode}); coverage incomplete')
 def _stop_observers(self):
  status={name:dict(pid=proc.pid,unexpected_exit=proc.poll() is not None,pre_stop_returncode=proc.returncode) for name,proc in (('engine',self.bu_loader),('observer',self.bu_observer)) if proc is not None}
  for proc in (self.bu_loader,self.bu_observer):
   if proc is not None and proc.poll() is None:
    proc.send_signal(signal.SIGINT)
    try:proc.wait(timeout=10)
    except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=5)
  for name in ('bu_loader_log','bu_observer_log'):
   stream=getattr(self,name,None)
   if stream is not None:stream.close()
  for name,proc in (('engine',self.bu_loader),('observer',self.bu_observer)):
   if proc is not None:status[name]['final_returncode']=proc.returncode
  if status:(self.bu_logs/'observer-status.json').write_text(json.dumps(status,indent=2))
