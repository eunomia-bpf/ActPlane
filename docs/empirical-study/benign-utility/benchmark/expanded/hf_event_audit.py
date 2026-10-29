"""Join the actual HF denials to independent syscall and command-origin evidence.

This exports review candidates only. It does not promote timestamp proximity to
verified action attribution or change native rewards.
"""
import collections,csv,fcntl,hashlib,json,re
from decimal import Decimal
from pathlib import Path
ROOT=Path('/workspaces/exp/benign-utility');OUT=ROOT/'benchmark/expanded/results'
TRIAL='hf-model-inference__ZvMjJut'
guard=(OUT/'.export.lock').open('a+');fcntl.flock(guard,fcntl.LOCK_EX)
def read(name):return list(csv.DictReader((OUT/name).open()))
trial=next(r for r in read('trials.csv') if r['trial_id']==TRIAL)
directory=Path(trial['raw_result']).parent/'agent'
scope=json.loads((directory/'scope.json').read_text());root=int(scope['root_host_pid'])
offset=scope['syscall_clock_offset_ns']
events=sorted([e for e in read('interventions.csv') if e['trial_id']==TRIAL and e['is_intervention']=='1'],key=lambda e:int(e['timestamp_ns']))
assert len(events)==108
observer=[]
for number,line in enumerate((directory/'observer.jsonl').read_text().splitlines(),1):
 try:record=json.loads(line)
 except ValueError:continue
 if record.get('type')!='printf':continue
 for text in record.get('data','').splitlines():
  fields=text.split('|',4)
  if len(fields)==5 and fields[2]=='benchmark':observer.append(dict(kind=fields[0],ns=int(fields[1]),pid=int(fields[3]),value=fields[4],line=number))
parents={int(r['value']):r for r in observer if r['kind']=='FORK'}
execs=collections.defaultdict(list)
for r in observer:
 if r['kind']=='EXEC':execs[r['pid']].append(r)
def lineage(pid):
 path=[pid]
 while path[-1]!=root:
  assert path[-1] in parents,('Missing observer ancestry',path)
  path.append(parents[path[-1]]['pid']);assert len(path)<100
 return path
connects=[r for r in observer if r['kind']=='CONNECT' and r['value']=='2']
paired=[];used=set()
for event in events:
 ns=int(event['timestamp_ns']);tgid=int(event['pid'])
 candidates=[r for r in connects if r['line'] not in used and 0<=ns-r['ns']<1000000 and tgid in lineage(r['pid'])]
 assert candidates,('No independent AF_INET entry',event)
 entry=min(candidates,key=lambda r:ns-r['ns']);used.add(entry['line'])
 paired.append((event,entry))
denials=collections.defaultdict(list);trace_hashes={}
for trace in directory.glob('syscalls.*'):
 if not trace.suffix[1:].isdigit():continue
 for number,line in enumerate(trace.read_text(errors='replace').splitlines(),1):
  if 'connect(' not in line or 'EPERM' not in line:continue
  match=re.match(r'(\d+\.\d+) ',line);assert match
  target=re.search(r'inet_addr\("([^"]+)"\)',line);assert target
  denials[int(trace.suffix[1:])].append(dict(path=str(trace),line=number,text=line,wall_ns=int(Decimal(match[1])*10**9),target=target[1]))
  if trace not in trace_hashes:trace_hashes[trace]=hashlib.sha256(trace.read_bytes()).hexdigest()
assert sum(map(len,denials.values()))==len(events)
calls={}
for line in (directory/'calls.jsonl').read_text().splitlines():
 record=json.loads(line);calls.setdefault(record['index'],{}).update(record)
coverage={int(r['call_index']):r for r in read('scope-call-audit.csv') if r['trial_id']==TRIAL}
by_tid=collections.defaultdict(list)
for pair in paired:by_tid[pair[1]['pid']].append(pair)
rows=[]
for tid,pairs in by_tid.items():
 native=sorted(denials[tid],key=lambda r:r['wall_ns']);pairs.sort(key=lambda p:p[1]['ns'])
 assert len(native)==len(pairs),(tid,len(native),len(pairs))
 for (event,entry),denial in zip(pairs,native):
  assert event['target']==denial['target']
  delta=denial['wall_ns']-(entry['ns']+offset)
  assert abs(delta)<100000000,('Native wall-clock join inconsistent',tid,delta)
  ancestry=lineage(tid);branch=ancestry[-2];fork=parents[branch]
  dispatch=[(i,c) for i,c in calls.items() if c['keystrokes'] and c['start_ns']<=fork['ns']<=c.get('end_ns',c['start_ns'])]
  candidate=dispatch[0][0] if len(dispatch)==1 else 0
  status='candidate_requires_independent_review' if candidate and coverage[candidate]['security_call_coverage']=='complete' and coverage[candidate]['terminal_input_evidence']=='recorded_asciicast_input' else 'origin_requires_manual_queued_command_review'
  execution=execs.get(branch,[])
  rows.append(dict(trial_id=TRIAL,event_id=event['event_id'],engine_tgid=event['pid'],engine_timestamp_ns=event['timestamp_ns'],observer_tid=tid,observer_connect_line=entry['line'],observer_connect_ns=entry['ns'],engine_after_observer_ns=int(event['timestamp_ns'])-entry['ns'],guest_tid_ancestry_to_root='>'.join(map(str,ancestry)),root_child=branch,root_fork_line=fork['line'],root_fork_ns=fork['ns'],root_child_exec_lines=','.join(str(e['line']) for e in execution),root_child_exec_paths=','.join(e['value'] for e in execution),candidate_origin_call=candidate,candidate_origin_status=status,temporal_call=event['temporal_call_index'],trace_path=denial['path'],trace_sha256=trace_hashes[Path(denial['path'])],native_connect_line=denial['line'],native_connect_text=denial['text'],native_entry_wall_ns=denial['wall_ns'],native_minus_observer_wall_ns=delta,source_provenance=event['provenance'],adjudication='pending_independent_event_and_origin_review'))
rows.sort(key=lambda r:int(r['event_id']))
file=OUT/'hf-native-event-evidence.csv'
with file.open('w',newline='') as stream:
 writer=csv.DictWriter(stream,fieldnames=list(rows[0]),lineterminator='\n');writer.writeheader();writer.writerows(rows)
groups=collections.defaultdict(list)
for r in rows:groups[(r['engine_tgid'],r['observer_tid'],r['candidate_origin_call'],r['candidate_origin_status'])].append(int(r['event_id']))
for (tgid,tid,call,status),ids in groups.items():print(json.dumps(dict(tgid=tgid,tid=tid,candidate_call=call,status=status,event_ids=ids)))
print('Native EPERM/event one-to-one joins',len(rows),'actual TIDs',len(by_tid),'candidate original calls',sorted({r['candidate_origin_call'] for r in rows}))
