"""Separate declared-cohort adapter; native agent defaults remain unchanged."""
import asyncio,hashlib,json,os,re,signal,subprocess,time,uuid
from pathlib import Path
from benchmark.adapter import InstrumentedTerminus
from benchmark.expanded.collect_public import collect
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark')
ROOT=BASE.parent.parent/'benchmark/expanded'
class NetworkInstrumentationPreflightComplete(RuntimeError):pass

class ExpandedTerminus(InstrumentedTerminus):
 def __init__(self,*args,**kwargs):
  self.bu_policy_directory=ROOT/'policies'/os.environ['BU_TASK']
  self.bu_syscalls=None;self.bu_syscall_stream=None;self.bu_actual_workspace_root=None;self.bu_root_start=None
  self.bu_sources_collected=False
  super().__init__(*args,**kwargs)
 async def _setup_measured(self,environment):
  seal=json.loads((ROOT/'task-seals'/f'{self.bu_task}.json').read_text())
  frozen=json.loads((ROOT/'environment-freeze.json').read_text())
  assert seal['environment_id']==frozen['environment_id']=='workspace_kvm_guest_20261029'
  worker=frozen['workers'][os.environ['BU_EXPANDED_WORKER']]
  assert seal['worker_id']==os.environ['BU_EXPANDED_WORKER']
  assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==worker['boot_id']
  assert os.uname().release==worker['kernel_release']
  assert 'bpf' in Path('/sys/kernel/security/lsm').read_text().strip().split(',')
  for relative,expected in seal['files'].items():
   assert hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()==expected,'Frozen cohort artifact changed'
  for relative,expected in seal.get('runtime_code',{}).items():
   assert hashlib.sha256((Path(__file__).parent.parent/relative).read_bytes()).hexdigest()==expected,'Frozen runtime code changed'
  assert hashlib.sha256((BASE/'engine/process').read_bytes()).hexdigest()==seal['engine_sha256']
  await super()._setup_measured(environment)
  if self.bu_condition!='a':assert 'ActPlane: enforce mode' in (self.bu_logs/'engine.log').read_text(),'Native denial unavailable: stop before model generation'
  scope=json.loads((self.bu_logs/'scope.json').read_text())
  daemon=json.loads(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True))
  assert daemon['DockerRootDir']==worker['docker_data_root'] and daemon['Driver']==worker['docker_driver']
  scope.update(runtime_environment_id=frozen['environment_id'],runtime_worker_id=os.environ['BU_EXPANDED_WORKER'],runtime_storage_backing='kvm_guest_ext4_'+daemon['Driver'],runtime_storage_data_root=daemon['DockerRootDir'],kernel_release=worker['kernel_release'],boot_id=worker['boot_id'])
  images=list(__import__('csv').DictReader((ROOT/'results/image-inventory.csv').open()))
  expected=next(r['image_id'] for r in images if r['task']==self.bu_task)
  actual=subprocess.check_output(['docker','inspect','--format','{{.Image}}',scope['container_id']],text=True).strip()
  assert actual==expected,'Official task image differs from pre-outcome inventory'
  if self.bu_condition!='a':assert (self.bu_logs/'policy.dsl').read_bytes()==(self.bu_policy_directory/f'{self.bu_condition}.dsl').read_bytes()
  # Hold a unique comm marker in the actual persistent shell, independently
  # reconfirm the kernel TGID, and map that same marker into Workspace /proc.
  marker='buns'+uuid.uuid4().hex[:8];mapping=self.bu_logs/'workspace-map.bt';mapping_log=self.bu_logs/'workspace-map.jsonl'
  mapping.write_text('BEGIN { printf("READY\\n"); }\ntracepoint:syscalls:sys_enter_openat /comm == "'+marker+'"/ { printf("HOST_PID|%d\\n", curtask->tgid); exit(); }\n')
  matches=[]
  with mapping_log.open('w') as stream:
   mapper=subprocess.Popen(['bpftrace','-f','json',str(mapping)],stdout=stream,stderr=subprocess.STDOUT)
   try:
    for _ in range(600):
     if 'READY' in mapping_log.read_text():break
     assert mapper.poll() is None,mapping_log.read_text()
     await asyncio.sleep(.05)
    else:raise RuntimeError('Workspace mapper startup timed out')
    await self._session.send_keys(f"printf '%s' {marker} >/proc/self/comm; : >/dev/null\n",block=False,min_timeout_sec=.2)
    for _ in range(100):
     if 'HOST_PID|' in mapping_log.read_text():break
     await asyncio.sleep(.05)
    else:raise RuntimeError('Held shell marker did not yield independent kernel PID')
    observed=int(re.search(r'HOST_PID\|(\d+)',mapping_log.read_text())[1])
    assert observed==scope['root_host_pid'] and 'helper_error' not in mapping_log.read_text()
    for p in Path('/proc').glob('[0-9]*'):
     try:
      if os.readlink(p/'ns/pid')==scope['root_pid_namespace'] and (p/'comm').read_text().strip()==marker:matches.append(int(p.name))
     except OSError:pass
    assert len(matches)==1,matches
    line=next(x for x in Path(f'/proc/{matches[0]}/status').read_text().splitlines() if x.startswith('NSpid:'))
    container_root=int(line.split()[-1])
   finally:
    await self._session.send_keys("printf '%s' bash >/proc/self/comm\n",block=False,min_timeout_sec=.2)
    if mapper.poll() is None:mapper.send_signal(signal.SIGINT)
    mapper.wait(timeout=10)
  self.bu_actual_workspace_root=matches[0]
  self.bu_root_start=Path(f'/proc/{matches[0]}/stat').read_text().rsplit(')',1)[1].split()[19]
  scope.update(tmux_outer_workspace_pid=scope['root_workspace_pid'],tmux_outer_namespace_pid=scope['root_namespace_pid'],root_workspace_pid=matches[0],root_namespace_pid=container_root,actual_image_id=actual,cohort=seal['cohort'],syscall_clock_offset_ns=time.time_ns()-time.monotonic_ns())
  (self.bu_logs/'scope.json').write_text(json.dumps(scope,indent=2)+'\n')
  (self.bu_logs/'pre-agent-processes.json').write_text(json.dumps(dict(kernel_root=scope['root_host_pid'],workspace_root=matches[0],container_root=container_root,identity_method='held unique comm and independent kernel TGID receipt'),indent=2)+'\n')
  self.bu_syscall_stream=(self.bu_logs/'syscall-tracer.stderr').open('w')
  self.bu_syscalls=subprocess.Popen(['strace','-ff','-qq','-ttt','-T','-yy','-s','256','-e','trace=%process,openat,read,close,connect,sendto,sendmsg,write','-e','raw=read,write,sendto,sendmsg','-o',str(self.bu_logs/'syscalls'),'-p',str(matches[0])],stderr=self.bu_syscall_stream,stdout=subprocess.DEVNULL)
  for _ in range(100):
   assert self.bu_syscalls.poll() is None,(self.bu_logs/'syscall-tracer.stderr').read_text()
   status=Path(f'/proc/{matches[0]}/status').read_text()
   if f'TracerPid:\t{self.bu_syscalls.pid}\n' in status:break
   await asyncio.sleep(.05)
  else:raise RuntimeError('Independent syscall tracer never attached to protected shell')
  if os.environ.get('BU_NETWORK_PREFLIGHT_ONLY')=='1':
   await self._session.send_keys('/bin/true\n',block=False,min_timeout_sec=.2)
   await asyncio.sleep(.2)
   assert any('/bin/true' in p.read_text(errors='replace') for p in self.bu_logs.glob('syscalls.*') if p.name.split('.')[-1].isdigit())
   await self._session.send_keys('/bin/sleep 30 & echo $! >/tmp/bu-trace-preflight.pid\n',block=False,min_timeout_sec=.2)
   child=await environment.exec(command='cat /tmp/bu-trace-preflight.pid');child_pid=int(child.stdout.strip())
   self.bu_syscalls.send_signal(signal.SIGINT);self.bu_syscalls.wait(timeout=10)
   alive=await environment.exec(command='kill -0 '+str(child_pid));assert alive.return_code==0,'Tracer detach disrupted a background child'
   await environment.exec(command='kill '+str(child_pid))
   (self.bu_logs/'instrumentation-preflight.json').write_text(json.dumps(dict(passed=True,purpose='setup-only calibration; native Agent.run never entered',kernel_root_pid=scope['root_host_pid'],workspace_root_pid=matches[0],container_root_pid=container_root,trace_verified=True,detach_preserved_background_child=True,model_generation_calls=0),indent=2)+'\n')
   raise NetworkInstrumentationPreflightComplete('Intentional setup-only stop; no model generation or task oracle')
 def _stop_observers(self):
  if not self.bu_sources_collected:
   self.bu_sources_collected=True
   try:collect(self.bu_logs)
   except Exception as error:(self.bu_logs/'post-agent-source-collection-error.txt').write_text(repr(error)+'\n')
  process=self.bu_syscalls;root_alive=False
  if self.bu_actual_workspace_root:
   try:root_alive=Path(f'/proc/{self.bu_actual_workspace_root}/stat').read_text().rsplit(')',1)[1].split()[19]==self.bu_root_start
   except OSError:pass
  status=dict(started=process is not None,root_alive_at_cleanup=root_alive,pre_stop_returncode=process.poll() if process else None,read_payloads='raw pointer arguments; no read/write/send payload decoding')
  if process is not None and process.poll() is None:
   process.send_signal(signal.SIGINT)
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=10)
  if self.bu_syscall_stream:self.bu_syscall_stream.close()
  if process is not None:status['final_returncode']=process.returncode
  (self.bu_logs/'syscall-tracer-status.json').write_text(json.dumps(status,indent=2)+'\n')
  super()._stop_observers()
