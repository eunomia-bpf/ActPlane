"""Separate mechanism control, never included in official benchmark scores."""
import argparse,csv,errno,hashlib,json,os,re,shutil,signal,socket,subprocess,sys,time,uuid
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark');RAW=Path(os.environ.get('BU_EXPANDED_RAW',str(BASE/'expanded-vm')));RAW.mkdir(parents=True,exist_ok=True)
if len(sys.argv)>1 and sys.argv[1]=='--child':
 marker,root,effect=sys.argv[2:]
 Path('/proc/self/comm').write_text(marker)
 with open('/dev/null','rb'):pass
 os.kill(os.getpid(),signal.SIGSTOP)
 os.chroot(root)
 Path('/app/ssl/server.key').read_bytes()
 try:
  with socket.socket() as sock:sock.connect(('127.0.0.1',9))
 except OSError as error:
  print('CONNECT_ERRNO|'+str(error.errno),flush=True)
  sys.exit(0 if effect!='block' or error.errno==errno.EPERM else 2)
 sys.exit(3 if effect=='block' else 0)
def until(predicate,seconds=30):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if predicate():return
  time.sleep(.05)
 raise RuntimeError('Control readiness timed out')
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--effect',choices=['kill','block'],default='kill');args=parser.parse_args()
 folder=RAW/('enforcement-block-control' if args.effect=='block' else 'enforcement-control');folder.mkdir(exist_ok=True)
 secret=folder/'root/app/ssl/server.key';secret.parent.mkdir(parents=True,exist_ok=True);secret.write_text('Isolated mechanism control fixture, never model input.\n')
 rows=[]
 for condition in ('a','b','c'):
  marker='buct'+uuid.uuid4().hex[:8];bt=folder/f'{condition}-map.bt';log=folder/f'{condition}-map.jsonl'
  bt.write_text('BEGIN { printf("READY\\n"); }\ntracepoint:syscalls:sys_enter_openat /comm == "'+marker+'"/ { printf("HOST_PID|%d\\n", curtask->tgid); exit(); }\n')
  engine=None;child=None;failure='';code=None;root=None
  with log.open('w') as stream,(folder/f'{condition}-engine.log').open('w') as engine_stream,(folder/f'{condition}-child.log').open('w') as child_stream:
   mapper=subprocess.Popen(['bpftrace','-f','json',str(bt)],stdout=stream,stderr=subprocess.STDOUT)
   try:
    until(lambda:'READY' in log.read_text())
    child=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--child',marker,str(folder/'root'),args.effect if condition!='a' else 'none'],stdout=child_stream,stderr=subprocess.STDOUT)
    until(lambda:'HOST_PID|' in log.read_text())
    root=int(re.search(r'HOST_PID\|(\d+)',log.read_text())[1]);assert root>0 and 'helper_error' not in log.read_text()
    until(lambda:Path(f'/proc/{child.pid}/stat').read_text().rsplit(')',1)[1].split()[0]=='T')
    if condition!='a':
     policy=(Path(__file__).parent.parent/'policies'/f'{condition}.dsl').read_text()
     if args.effect=='block':
      assert policy.count('  kill connect')==1
      policy=policy.replace('  kill connect','  block connect')
     (folder/f'{condition}.dsl').write_text(policy)
     compiled=subprocess.run(['/workspaces/lanes/translation-models/target/release/actplane','--rule',policy,'compile','--out',str(folder/f'{condition}.bin'),'--force'],capture_output=True,text=True)
     (folder/f'{condition}-compile.log').write_text(compiled.stdout+compiled.stderr)
     if compiled.returncode:raise RuntimeError('Control policy compile failed')
     engine=subprocess.Popen([str(BASE/'engine/process'),'--config',str(folder/f'{condition}.bin'),'--seed-pid',str(root),'--seed-label','0'],stdout=engine_stream,stderr=subprocess.STDOUT)
     until(lambda:'ActPlane: ready' in (folder/f'{condition}-engine.log').read_text() or engine.poll() is not None)
     if 'ActPlane: ready' not in (folder/f'{condition}-engine.log').read_text():raise RuntimeError('Control engine failed: '+(folder/f'{condition}-engine.log').read_text()[-1500:])
    os.kill(child.pid,signal.SIGCONT);code=child.wait(timeout=15)
    time.sleep(.2)
   except Exception as error:failure=str(error)
   finally:
    for proc in (engine,mapper):
     if proc is not None and proc.poll() is None:proc.send_signal(signal.SIGINT);proc.wait(timeout=10)
    if child is not None and child.poll() is None:child.kill();child.wait()
  events=[]
  for line in (folder/f'{condition}-engine.log').read_text().splitlines():
   try:
    data=json.loads(line)
    if data.get('event')=='TAINT_VIOLATION':events.append(data)
   except ValueError:pass
  killed=sum(bool(e.get('killed')) for e in events)
  blocked=sum(e.get('blocked') is True for e in events)
  expected=0 if condition=='a' or args.effect=='block' else -9
  effect_ok=condition=='a' or (blocked>0 if args.effect=='block' else killed>0)
  child_text=(folder/f'{condition}-child.log').read_text(errors='replace');observed_errno=re.search(r'CONNECT_ERRNO\|(\d+)',child_text)
  row=dict(condition=condition,effect='none' if condition=='a' else args.effect,namespace_pid=child.pid if child else '',kernel_root_pid=root,returncode=code,connect_errno=observed_errno[1] if observed_errno else '',events=len(events),killed_events=killed,blocked_events=blocked,expected_returncode=expected,passed=int(not failure and code==expected and effect_ok),failure=failure,engine_sha256=hashlib.sha256((BASE/'engine/process').read_bytes()).hexdigest(),policy_sha256='' if condition=='a' or not (folder/f'{condition}.bin').exists() else hashlib.sha256((folder/f'{condition}.bin').read_bytes()).hexdigest())
  rows.append(row);print(row,flush=True)
 out=Path(os.environ.get('BU_EXPANDED_OUT',str(BASE.parent.parent/'benchmark/expanded/results')))/('enforcement-block-control.csv' if args.effect=='block' else 'enforcement-control.csv')
 with out.open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
 assert all(r['passed'] for r in rows)
if __name__=='__main__':main()
