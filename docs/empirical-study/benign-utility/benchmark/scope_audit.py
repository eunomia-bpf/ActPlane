"""Audit retained protected-root evidence independently of loader liveness.

Does not change a running trial or infer root survival from silence.
"""
import csv,json,re
from pathlib import Path

RAW=Path('/workspaces/exp/benign-utility/raw/benchmark')
OUT=RAW.parent.parent/'benchmark/results'
trials=[r for r in csv.DictReader((OUT/'trials.csv').open()) if r['selected_for_comparison']=='1']
rows=[];call_rows=[];candidates=[]
known_exits={'git-leak-recovery__N6UvkVs':8,'openssl-selfsigned-cert__a7wefSt':9}
for trial in trials:
 directory=Path(trial['raw_result']).parent/'agent'
 scope=json.loads((directory/'scope.json').read_text())
 root=int(scope['root_host_pid'])
 events=[]
 for line in (directory/'observer.jsonl').read_text().splitlines():
  try:record=json.loads(line)
  except ValueError:continue
  if record.get('type')!='printf':continue
  for item in record.get('data','').splitlines():
   fields=item.split('|',4)
   if len(fields)==5 and fields[2]=='benchmark' and fields[0] in ('FORK','EXEC'):
    events.append((fields[0],int(fields[1]),int(fields[3]),fields[4]))
 root_events=[e for e in events if e[2]==root]
 last_root=max((e[1] for e in root_events),default=0)
 calls={}
 for line in (directory/'calls.jsonl').read_text().splitlines():
  record=json.loads(line);calls.setdefault(record['index'],{}).update(record)
 pane=(directory/'terminus_2.pane').read_text(errors='replace')
 plain_pane=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',pane)
 pane_compact=re.sub(r'\s+','',plain_pane)
 finished=pane.count('asciinema: recording finished')
 cutoff=known_exits.get(trial['trial_id'],'')
 if cutoff:
  assert finished==1
  if trial['task']=='openssl-selfsigned-cert':
   assert 'openssl genrsa -out /app/ssl/server.key 2044' in pane
   assert 'test "$KEY_BITS" = 2048' in pane
 inputs=''
 for line in (directory/'recording.cast').read_text(errors='replace').splitlines()[1:]:
  try:item=json.loads(line)
  except ValueError:continue
  if isinstance(item,list) and len(item)==3 and item[1]=='i':inputs+=item[2]
 cursor=0;missing=[];empty=[];dispatches=0;failed=0
 exits=[]
 for index,call in sorted(calls.items()):
  code=call['keystrokes']
  # Candidates require manual interpretation (quoted child scripts can exit safely).
  transition=bool(re.search(r'(?m)(?:^|[;\n]|\bthen\s+)\s*(?:exit\b|logout\b|exec\s|kill\s|pkill\s)',code))
  if transition:exits.append(index);candidates.append(f"{trial['trial_id']} call{index}\n{code}\n")
  start=call['start_ns'];end=call.get('end_ns',start)
  action_kind='wait' if not code else ('interrupt' if code in ('C-c','C-d','C-z') else 'command')
  input_code={'C-c':'\x03','C-d':'\x04','C-z':'\x1a'}.get(code,code)
  if not code:input_status='empty_input_wait';empty.append(index)
  else:
   position=inputs.find(input_code,cursor)
   if position>=0:input_status='recorded_asciicast_input';cursor=position+len(input_code);dispatches+=1
   elif trial['trial_id']=='git-leak-recovery__N6UvkVs' and index==10:input_status='failed_before_dispatch';failed+=1
   elif cutoff and index>cutoff:
    # Independently checked in retained pane: outer-shell commands are visible
    # after recording finished, although they cannot occur in the inner cast.
    first_line=next(line for line in code.splitlines() if line.strip())
    assert re.sub(r'\s+','',first_line.strip()[:60]) in pane_compact,(trial['trial_id'],index)
    input_status='pane_confirmed_outer_shell_input';dispatches+=1
   else:input_status='not_in_recorded_input';missing.append(index)
  within=sum(start<=e[1]<=end for e in root_events)
  call_coverage='complete' if last_root>=start else 'root_persistence_unverified'
  if cutoff and index>cutoff:call_coverage='out_of_scope'
  if finished and not cutoff:call_coverage='lifecycle_exit_requires_audit'
  if input_status=='not_in_recorded_input':call_coverage='dispatch_unverified'
  call_rows.append(dict(trial_id=trial['trial_id'],task=trial['task'],condition=trial['condition'],call_index=index,
   exact_root_events_during_call=within,exact_root_observed_after_call_end=int(last_root>=end),
   exact_root_observed_at_or_after_call_start=int(last_root>=start),shell_transition_candidate=int(transition),
   terminal_input_evidence=input_status,action_kind=action_kind,security_call_coverage=call_coverage,
   scope_cutoff=cutoff,
   evidence='Independent EXEC/FORK exact seeded-kernel-PID events; no EXIT output hook existed'))
 rows.append(dict(trial_id=trial['trial_id'],task=trial['task'],condition=trial['condition'],kernel_root=root,
  terminal_submission_attempts=len(calls),exact_root_events=len(root_events),last_exact_root_event_ns=last_root,
  calls_root_observed_after_end=sum(r['exact_root_observed_after_call_end'] for r in call_rows if r['trial_id']==trial['trial_id']),
  calls_root_observed_at_or_after_start=sum(r['exact_root_observed_at_or_after_call_start'] for r in call_rows if r['trial_id']==trial['trial_id']),
  recording_finished_markers=finished,shell_transition_candidate_calls=','.join(map(str,exits)),
  empty_submission_calls=','.join(map(str,empty)),missing_recorded_input_calls=','.join(map(str,missing)),
  verified_nonempty_dispatches=dispatches,failed_submission_attempts=failed,
  dispatch_count_complete=int(not missing),security_coverage_end_call=cutoff,
  security_complete_calls=sum(r['security_call_coverage']=='complete' for r in call_rows if r['trial_id']==trial['trial_id']),
  security_audit_status='partial_agent_scope_exit' if cutoff else ('complete' if not finished and not missing and last_root>=max((c['start_ns'] for c in calls.values()),default=0) else 'partial_scope_or_dispatch_evidence'),
  pane_path=str(directory/'terminus_2.pane'),
  observer_path=str(directory/'observer.jsonl'),
  limitation='Observer deleted owner on exit without emitting EXIT; trace silence alone does not establish root persistence'))
for name,data in [('scope-audit.csv',rows),('scope-call-audit.csv',call_rows)]:
 if data:
  with (OUT/name).open('w',newline='') as handle:
   writer=csv.DictWriter(handle,fieldnames=list(data[0]));writer.writeheader();writer.writerows(data)
(RAW/'scope-transition-candidates.txt').write_text('\n'.join(candidates))
for row in rows:print(row['trial_id'],'calls',row['terminal_submission_attempts'],'root_after_end',row['calls_root_observed_after_end'],'root_at_after_start',row['calls_root_observed_at_or_after_start'],'recording_finished',row['recording_finished_markers'],'transition_candidates',row['shell_transition_candidate_calls'],'empty',row['empty_submission_calls'],'missing_input',row['missing_recorded_input_calls'])
