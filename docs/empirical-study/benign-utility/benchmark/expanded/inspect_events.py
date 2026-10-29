"""Read-only grouped intervention evidence for case-specific human review."""
import collections,csv,fcntl,hashlib,json,re
from pathlib import Path
ROOT=Path('/workspaces/exp/benign-utility')
OUT=ROOT/'benchmark/expanded/results'
guard=(OUT/'.export.lock').open('a+');fcntl.flock(guard,fcntl.LOCK_SH)
trials={r['trial_id']:r for r in csv.DictReader((OUT/'trials.csv').open())}
groups=collections.defaultdict(list)
for row in csv.DictReader((OUT/'interventions.csv').open()):
 if row['is_intervention']=='1':groups[(row['trial_id'],row['pid'])].append(row)
for (trial,pid),events in groups.items():
 directory=Path(trials[trial]['raw_result']).parent/'agent'
 trace=directory/('syscalls.'+pid)
 lines=trace.read_text(errors='replace').splitlines() if trace.exists() else []
 relevant={i for i,line in enumerate(lines) if 'execve(' in line or 'EPERM' in line}
 for i,line in enumerate(lines):
  if any(p in line for p in ('cert.pem','cacert.pem','ca-certificates.crt')):relevant.update(range(i,min(i+4,len(lines))))
 proof=json.loads((directory/'post-agent-source-evidence.json').read_text()) if (directory/'post-agent-source-evidence.json').exists() else {}
 public=[r for r in proof.get('files',[]) if r.get('public_header')]
 print(json.dumps(dict(trial_id=trial,pid=pid,events=len(events),event_ids=[int(r['event_id']) for r in events],temporal_calls=sorted({r['temporal_call_index'] for r in events}),provenances=sorted({r['provenance'] for r in events}),trace_path=str(trace),trace_lines=len(lines),relevant_trace_lines=[dict(line=i+1,text=lines[i]) for i in sorted(relevant)],public_source_evidence=public),sort_keys=True))
for trial in sorted({k[0] for k in groups}):
 directory=Path(trials[trial]['raw_result']).parent/'agent';calls={}
 sources=[r for r in csv.DictReader((OUT/'compiled-sources.csv').open()) if r['task']==trials[trial]['task'] and r['condition']==trials[trial]['condition'] and r['op']=='1']
 def matches(path,row):
  literal=row['literal'];mode=int(row['match_mode'])
  return {0:lambda:path==literal,1:lambda:path.startswith(literal),2:lambda:path.endswith(literal),3:lambda:True,4:lambda:literal in path}[mode]()
 candidates=collections.defaultdict(list);clones=[];denials=[]
 for trace in directory.glob('syscalls.*'):
  if not trace.suffix[1:].isdigit():continue
  for number,line in enumerate(trace.read_text(errors='replace').splitlines(),1):
   if 'clone' in line or 'fork(' in line:
    child=re.search(r' = (\d+)(?: |$)',line)
    if child:clones.append(dict(parent_guest_trace_tid=trace.suffix[1:],child_container_namespace_pid=child[1],thread=True if 'CLONE_THREAD' in line else ('unknown_resumed_requires_original_entry' if 'resumed>' in line else False),trace_path=str(trace),line=number,text=line,limitation='clone return PID is container-relative; use independent observer FORK for guest TID ancestry'))
   if 'connect(' in line and 'EPERM' in line:denials.append(dict(tid=trace.suffix[1:],trace_path=str(trace),line=number,text=line))
   match=re.search(r'openat\([^,]*, "((?:\\.|[^"\\])*)".* = (\d+)(?:<(.*?)>)?',line)
   if not match:continue
   try:path=json.loads('"'+match[1]+'"')
   except ValueError:continue
   canonical=match[3] or path
   if any(matches(path,s) or matches(canonical,s) for s in sources):candidates[(path,canonical)].append(dict(tid=trace.suffix[1:],trace_path=str(trace),line=number,text=line))
 inventory=json.loads((OUT/'per-task'/f'{trials[trial]["task"]}.json').read_text())
 public={r['path']:r for r in inventory['sources'] if r.get('public_file_sha256')}
 for (path,canonical),opens in candidates.items():
  source=public.get(path) or public.get(canonical)
  if source:
   retained=Path(source['retained_public_path']);assert hashlib.sha256(retained.read_bytes()).hexdigest()==source['public_file_sha256']
  print(json.dumps(dict(trial_id=trial,source_candidate_path=path,canonical_path=canonical,successful_opens=opens,known_public_source=source),sort_keys=True))
 print(json.dumps(dict(trial_id=trial,all_native_denials=denials,all_native_fork_clone_receipts=clones),sort_keys=True))
 for line in (directory/'calls.jsonl').read_text().splitlines():
  record=json.loads(line);calls.setdefault(record['index'],{}).update(record)
 for index,call in sorted(calls.items()):
  print(json.dumps(dict(trial_id=trial,call_index=index,keystrokes=call['keystrokes'],start_ns=call['start_ns'],end_ns=call.get('end_ns'))))
