"""Isolated source-spelling calibration; never an official task or utility score."""
import csv,hashlib,json,os,re,signal,socket,subprocess,sys,time,uuid
from pathlib import Path
BASE=Path('/workspaces/exp/benign-utility/raw/benchmark');RAW=BASE/'network'
OUT=BASE.parent.parent/'benchmark/network/results'

if len(sys.argv)>1 and sys.argv[1]=='--child':
 marker,root,source,spelling=sys.argv[2:]
 Path('/proc/self/comm').write_text(marker)
 with open('/dev/null','rb'):pass
 os.kill(os.getpid(),signal.SIGSTOP)
 os.chroot(root)
 if spelling=='relative':os.chdir(str(Path(source).parent));read_path=Path(source).name
 elif spelling=='renamed_symlink':read_path='/alias.key'
 else:read_path=source
 Path(read_path).read_bytes()
 try:
  with socket.socket() as sock:sock.connect(('127.0.0.1',9))
  observed=0
 except OSError as error:observed=error.errno
 print('CONNECT_ERRNO|'+str(observed),flush=True);sys.exit(0)

def until(predicate,seconds=30):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if predicate():return
  time.sleep(.05)
 raise RuntimeError('Control readiness timed out')

def main():
 tasks=list(csv.DictReader((OUT/'tasks.csv').open()));known=list(csv.DictReader((OUT/'known-private-source-coverage.csv').open()))
 folder=RAW/'source-alias-controls'/time.strftime('%Y%m%dT%H%M%SZ',time.gmtime());folder.mkdir(parents=True)
 rows=[]
 for task in tasks:
  sources=[r['path'] for r in known if r['task']==task['task']] or ['/app/.env']
  for source in sources:
   for spelling in ('absolute','relative','renamed_symlink'):
    for condition in ('a','b','c'):
     number=len(rows)+1;case=folder/str(number);root=case/'root';root.mkdir(parents=True)
     fixture=root/source.lstrip('/');assert fixture.resolve().is_relative_to(root.resolve())
     fixture.parent.mkdir(parents=True,exist_ok=True);fixture.write_text('Mechanism-only fixture, never benchmark input.\n')
     (root/'alias.key').symlink_to(source)
     marker='buna'+uuid.uuid4().hex[:8];mapping=case/'mapper.bt';mapping_log=case/'mapper.jsonl'
     mapping.write_text('BEGIN { printf("READY\\n"); }\ntracepoint:syscalls:sys_enter_openat /comm == "'+marker+'"/ { printf("HOST_PID|%d\\n", curtask->tgid); exit(); }\n')
     child=None;engine=None;pid=None;failure='';code=None
     with mapping_log.open('w') as mapper_stream,(case/'engine.log').open('w') as engine_stream,(case/'child.log').open('w') as child_stream:
      mapper=subprocess.Popen(['bpftrace','-f','json',str(mapping)],stdout=mapper_stream,stderr=subprocess.STDOUT)
      try:
       until(lambda:'READY' in mapping_log.read_text())
       child=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--child',marker,str(root),source,spelling],stdout=child_stream,stderr=subprocess.STDOUT)
       until(lambda:'HOST_PID|' in mapping_log.read_text())
       pid=int(re.search(r'HOST_PID\|(\d+)',mapping_log.read_text())[1]);assert pid>0 and 'helper_error' not in mapping_log.read_text()
       until(lambda:Path(f'/proc/{child.pid}/stat').read_text().rsplit(')',1)[1].split()[0]=='T')
       if condition!='a':
        policy=RAW/'frozen'/task['task']/f'{condition}.bin'
        engine=subprocess.Popen([str(BASE/'engine/process'),'--config',str(policy),'--seed-pid',str(pid),'--seed-label','0'],stdout=engine_stream,stderr=subprocess.STDOUT)
        until(lambda:'ActPlane: ready' in (case/'engine.log').read_text() or engine.poll() is not None)
        assert engine.poll() is None and 'ActPlane: enforce mode' in (case/'engine.log').read_text()
       os.kill(child.pid,signal.SIGCONT);code=child.wait(timeout=15);time.sleep(.15)
      except Exception as error:failure=str(error)
      finally:
       for process in (engine,mapper):
        if process is not None and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=10)
       if child is not None and child.poll() is None:child.kill();child.wait()
     events=[]
     for line in (case/'engine.log').read_text().splitlines():
      try:
       event=json.loads(line)
       if event.get('event')=='TAINT_VIOLATION':events.append(event)
      except ValueError:pass
     blocked=sum(e.get('blocked') is True for e in events)
     match=re.search(r'CONNECT_ERRNO\|(\d+)',(case/'child.log').read_text());observed=int(match[1]) if match else None
     requirement='discovery' if spelling=='renamed_symlink' and condition!='a' else 'required'
     expected=int(condition!='a') if requirement=='required' else ''
     valid=not failure and code==0 and observed in (0,1,111) and (condition=='a' or observed!=1 or blocked>0)
     passed=valid and (requirement=='discovery' or (bool(blocked)==bool(expected) and (observed==1 if expected else observed!=1)))
     policy=RAW/'frozen'/task['task']/f'{condition}.bin'
     row=dict(task=task['task'],condition=condition,source_path=source,spelling=spelling,coverage_requirement=requirement,expected_denied=expected,connect_errno=observed,blocked_events=blocked,killed_events=sum(e.get('killed') is True for e in events),kernel_root=pid,returncode=code,passed=int(passed),failure=failure,renamed_alias_gap=int(requirement=='discovery' and not blocked),policy_sha256=hashlib.sha256(policy.read_bytes()).hexdigest() if condition!='a' else '',raw_path=str(case),purpose='isolated mechanism control; excluded from task scores and FP rates')
     rows.append(row);print(json.dumps(row),flush=True)
 with (OUT/'source-alias-controls.csv').open('w',newline='') as handle:
  writer=csv.DictWriter(handle,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
 assert all(r['passed'] for r in rows if r['coverage_requirement']=='required')

if __name__=='__main__':main()
