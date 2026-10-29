"""Read-only grouped intervention evidence for case-specific human review."""
import collections,csv,json
from pathlib import Path
ROOT=Path('/workspaces/exp/benign-utility')
OUT=ROOT/'benchmark/expanded/results'
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
 for line in (directory/'calls.jsonl').read_text().splitlines():
  record=json.loads(line);calls.setdefault(record['index'],{}).update(record)
 for index,call in sorted(calls.items()):
  print(json.dumps(dict(trial_id=trial,call_index=index,keystrokes=call['keystrokes'],start_ns=call['start_ns'],end_ns=call.get('end_ns'))))
