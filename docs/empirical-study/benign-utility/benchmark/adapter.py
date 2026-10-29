"""Thin measurement/defense adapter over Harbor's unmodified Terminus 2."""
import asyncio,json,os,signal,subprocess,time
from pathlib import Path
from harbor.agents.terminus_2.terminus_2 import Terminus2

RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
class InstrumentedTerminus(Terminus2):
 def __init__(self,logs_dir,*args,**kwargs):
  self.bu_logs=Path(logs_dir);self.bu_condition=os.environ['BU_CONDITION'];self.bu_task=os.environ['BU_TASK'];self.bu_index=0;self.bu_loader=None;self.bu_observer=None
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
  meta=dict(condition=self.bu_condition,task=self.bu_task,root_host_pid=root,root_namespace_pid=nspid,container_id=cid,root_pid_namespace=ns,attached_monotonic=time.monotonic(),scope='tmux pane shell and descendants; controller/model API outside scope')
  (self.bu_logs/'scope.json').write_text(json.dumps(meta,indent=2))
  self.bu_observer_log=(self.bu_logs/'observer.jsonl').open('w')
  self.bu_observer=subprocess.Popen(['bpftrace','-f','json',str(Path(__file__).parents[1]/'replay/source_observer.bt'),str(root)],env={**os.environ,'BPFTRACE_MAX_STRLEN':'256','BPFTRACE_MAX_MAP_KEYS':'262144'},stdout=self.bu_observer_log,stderr=subprocess.STDOUT)
  for _ in range(600):
   if 'SOURCE_OBSERVER_READY' in (self.bu_logs/'observer.jsonl').read_text():break
   if self.bu_observer.poll() is not None:raise RuntimeError('Observer failed: '+(self.bu_logs/'observer.jsonl').read_text()[-1000:])
   await asyncio.sleep(.1)
  else:raise RuntimeError('Observer never became ready')
  if self.bu_condition!='a':
   policy=(Path(__file__).parent/'policies'/f'{self.bu_condition}.dsl').read_text()
   (self.bu_logs/'policy.dsl').write_text(policy)
   subprocess.run(['/workspaces/lanes/translation-models/target/release/actplane','--rule',policy,'compile','--out',str(self.bu_logs/'policy.bin'),'--force'],check=True,capture_output=True)
   self.bu_loader_log=(self.bu_logs/'engine.log').open('w')
   self.bu_loader=subprocess.Popen([str(RAW/'engine/process'),'--config',str(self.bu_logs/'policy.bin'),'--seed-pid',str(root)],stdout=self.bu_loader_log,stderr=subprocess.STDOUT)
   for _ in range(600):
    if 'ActPlane: ready' in (self.bu_logs/'engine.log').read_text():break
    if self.bu_loader.poll() is not None:raise RuntimeError('Engine failed: '+(self.bu_logs/'engine.log').read_text()[-500:])
    await asyncio.sleep(.1)
   else:raise RuntimeError('Engine never became ready')
 async def _execute_commands(self,commands,session):
  self._check_observers()
  start=time.monotonic_ns();self.bu_index+=1
  with (self.bu_logs/'calls.jsonl').open('a') as f:f.write(json.dumps(dict(index=self.bu_index,start_ns=start,commands=[dict(keystrokes=c.keystrokes,duration_sec=c.duration_sec) for c in commands]))+'\n')
  try:
   result=await super()._execute_commands(commands,session)
   self._check_observers()
   return result
  finally:
   with (self.bu_logs/'calls.jsonl').open('a') as f:f.write(json.dumps(dict(index=self.bu_index,end_ns=time.monotonic_ns()))+'\n')
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
