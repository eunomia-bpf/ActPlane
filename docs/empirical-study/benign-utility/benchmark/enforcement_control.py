"""Separate mechanism control, never included in official benchmark scores."""
import csv,hashlib,json,os,re,shutil,signal,socket,subprocess,sys,time,uuid
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
if len(sys.argv)>1 and sys.argv[1]=='--child':
 marker,root=sys.argv[2:]
 Path('/proc/self/comm').write_text(marker)
 with open('/dev/null','rb'):pass
 os.kill(os.getpid(),signal.SIGSTOP)
 os.chroot(root)
 Path('/app/ssl/server.key').read_bytes()
 try:
  with socket.socket() as sock:sock.connect(('127.0.0.1',9))
 except OSError:pass
 sys.exit(0)
def until(predicate,seconds=30):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if predicate():return
  time.sleep(.05)
 raise RuntimeError('Control readiness timed out')
def main():
 folder=RAW/'enforcement-control';folder.mkdir(exist_ok=True)
 secret=folder/'root/app/ssl/server.key';secret.parent.mkdir(parents=True,exist_ok=True);secret.write_text('Isolated mechanism control fixture, never model input.\n')
 rows=[]
 for condition in ('a','b','c'):
  marker='buct'+uuid.uuid4().hex[:8];bt=folder/f'{condition}-map.bt';log=folder/f'{condition}-map.jsonl'
  bt.write_text('BEGIN { printf("READY\\n"); }\ntracepoint:syscalls:sys_enter_openat /comm == "'+marker+'"/ { printf("HOST_PID|%d\\n", curtask->tgid); exit(); }\n')
  engine=None;child=None
  with log.open('w') as stream,(folder/f'{condition}-engine.log').open('w') as engine_stream:
   mapper=subprocess.Popen(['bpftrace','-f','json',str(bt)],stdout=stream,stderr=subprocess.STDOUT)
   try:
    until(lambda:'READY' in log.read_text())
    child=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--child',marker,str(folder/'root')])
    until(lambda:'HOST_PID|' in log.read_text())
    root=int(re.search(r'HOST_PID\|(\d+)',log.read_text())[1]);assert root>0 and 'helper_error' not in log.read_text()
    until(lambda:Path(f'/proc/{child.pid}/stat').read_text().rsplit(')',1)[1].split()[0]=='T')
    if condition!='a':
     shutil.copyfile(RAW/f'policy-{condition}.bin',folder/f'{condition}.bin')
     shutil.copyfile(Path(__file__).parent/'policies'/f'{condition}.dsl',folder/f'{condition}.dsl')
     engine=subprocess.Popen([str(RAW/'engine/process'),'--config',str(folder/f'{condition}.bin'),'--seed-pid',str(root)],stdout=engine_stream,stderr=subprocess.STDOUT)
     until(lambda:'ActPlane: ready' in (folder/f'{condition}-engine.log').read_text())
    os.kill(child.pid,signal.SIGCONT);code=child.wait(timeout=15)
    time.sleep(.2)
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
  row=dict(condition=condition,namespace_pid=child.pid,kernel_root_pid=root,returncode=code,events=len(events),killed_events=killed,expected_returncode=0 if condition=='a' else -9,passed=int(code==(0 if condition=='a' else -9) and (condition=='a' or killed>0)),engine_sha256=hashlib.sha256((RAW/'engine/process').read_bytes()).hexdigest(),policy_sha256='' if condition=='a' else hashlib.sha256((folder/f'{condition}.bin').read_bytes()).hexdigest())
  rows.append(row);print(row,flush=True)
 out=RAW.parent.parent/'benchmark/results/enforcement-control.csv'
 with out.open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
 assert all(r['passed'] for r in rows)
if __name__=='__main__':main()
