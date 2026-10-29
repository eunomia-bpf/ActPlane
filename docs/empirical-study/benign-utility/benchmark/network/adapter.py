"""Separate declared-cohort adapter; native agent defaults remain unchanged."""
import asyncio,hashlib,json,os,shlex,signal,subprocess,time
from pathlib import Path
from benchmark.adapter import InstrumentedTerminus
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark')
ROOT=BASE.parent.parent/'benchmark/network'

class NetworkTerminus(InstrumentedTerminus):
 def __init__(self,*args,**kwargs):
  self.bu_policy_directory=Path(__file__).parent/'policies'/os.environ['BU_TASK']
  self.bu_syscalls=None;self.bu_syscall_stream=None;self.bu_actual_workspace_root=None;self.bu_root_start=None
  super().__init__(*args,**kwargs)
 async def _setup_measured(self,environment):
  await super()._setup_measured(environment)
  scope=json.loads((self.bu_logs/'scope.json').read_text())
  seal=json.loads((ROOT/'cohort-freeze.json').read_text())
  for relative,expected in seal['files'].items():
   assert hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()==expected,'Frozen cohort artifact changed'
  images=list(__import__('csv').DictReader((ROOT/'results/image-inventory.csv').open()))
  expected=next(r['image_id'] for r in images if r['task']==self.bu_task)
  actual=subprocess.check_output(['docker','inspect','--format','{{.Image}}',scope['container_id']],text=True).strip()
  assert actual==expected,'Official task image differs from pre-outcome inventory'
  if self.bu_condition!='a':assert (self.bu_logs/'policy.dsl').read_bytes()==(self.bu_policy_directory/f'{self.bu_condition}.dsl').read_bytes()
  # Find the real asciinema child shell, not merely tmux's outer pane shell.
  script="""import json,pathlib
outer=OUTER
items={}
for p in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  status=dict(line.split(':',1) for line in (p/'status').read_text().splitlines() if ':' in line)
  items[int(p.name)]=dict(ppid=int(status['PPid']),comm=status['Name'].strip(),recorder=b'asciinema' in (p/'cmdline').read_bytes())
 except (OSError,KeyError,ValueError):pass
candidates=[]
for pid,item in items.items():
 if pid==outer or item['comm'] not in ('bash','sh','dash','zsh'):continue
 chain=[];p=item['ppid']
 while p in items and p not in chain:chain.append(p);p=items[p]['ppid']
 if outer in chain and any(items[p]['recorder'] for p in chain):candidates.append(pid)
assert len(candidates)==1,candidates
print(json.dumps(dict(container_root_pid=candidates[0],processes=items)))
""".replace('OUTER',str(scope['root_namespace_pid']))
  found=await environment.exec(command='python3 -c '+shlex.quote(script),timeout_sec=30)
  assert found.return_code==0,found.stderr
  process_map=json.loads(found.stdout);container_root=process_map['container_root_pid'];matches=[]
  for p in Path('/proc').glob('[0-9]*'):
   try:
    if os.readlink(p/'ns/pid')!=scope['root_pid_namespace']:continue
    line=next(x for x in (p/'status').read_text().splitlines() if x.startswith('NSpid:'))
    if int(line.split()[-1])==container_root:matches.append(int(p.name))
   except (OSError,StopIteration):pass
  assert len(matches)==1,matches
  self.bu_actual_workspace_root=matches[0]
  self.bu_root_start=Path(f'/proc/{matches[0]}/stat').read_text().rsplit(')',1)[1].split()[19]
  scope.update(tmux_outer_workspace_pid=scope['root_workspace_pid'],tmux_outer_namespace_pid=scope['root_namespace_pid'],root_workspace_pid=matches[0],root_namespace_pid=container_root,actual_image_id=actual,cohort=seal['cohort'],syscall_clock_offset_ns=time.time_ns()-time.monotonic_ns())
  (self.bu_logs/'scope.json').write_text(json.dumps(scope,indent=2)+'\n')
  (self.bu_logs/'pre-agent-processes.json').write_text(json.dumps(process_map,indent=2)+'\n')
  self.bu_syscall_stream=(self.bu_logs/'syscall-tracer.stderr').open('w')
  self.bu_syscalls=subprocess.Popen(['strace','-ff','-qq','-ttt','-T','-yy','-s','256','-e','trace=%process,openat,read,close,connect,sendto,sendmsg,write','-e','raw=read,write,sendto,sendmsg','-o',str(self.bu_logs/'syscalls'),'-p',str(matches[0])],stderr=self.bu_syscall_stream,stdout=subprocess.DEVNULL)
  for _ in range(100):
   assert self.bu_syscalls.poll() is None,(self.bu_logs/'syscall-tracer.stderr').read_text()
   status=Path(f'/proc/{matches[0]}/status').read_text()
   if f'TracerPid:\t{self.bu_syscalls.pid}\n' in status:break
   await asyncio.sleep(.05)
  else:raise RuntimeError('Independent syscall tracer never attached to protected shell')
 def _stop_observers(self):
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
