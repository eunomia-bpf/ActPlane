"""Export official Harbor rewards and separately labeled security diagnostics."""
import bisect,csv,hashlib,json,re
from datetime import datetime
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark');HERE=Path(__file__).parent;OUT=RAW.parent.parent/'benchmark/results';OUT.mkdir(parents=True,exist_ok=True)
tasks=[r['task'] for r in csv.DictReader((OUT/'tasks.csv').open())]
def write(name,rows,fields):
 with (OUT/name).open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def seconds(d):
 if not d or not d.get('started_at') or not d.get('finished_at'):return ''
 return (datetime.fromisoformat(d['finished_at'])-datetime.fromisoformat(d['started_at'])).total_seconds()
def records(p):
 if not p.exists():return []
 out=[]
 for line in p.read_text(errors='replace').splitlines():
  try:out.append(json.loads(line))
  except json.JSONDecodeError:pass
 return out
trials=[];calls_out=[];events_out=[];reads_out=[]
for job in sorted((RAW/'jobs').glob('*')):
 task=next((t for t in tasks if job.name.startswith(t+'-')),None)
 if not task:continue
 condition,attempt=job.name[len(task)+1:].split('-',1)
 for result_path in job.glob('*/result.json'):
  d=json.loads(result_path.read_text());agent=result_path.parent/'agent';exception=d.get('exception_info') or {};reward=((d.get('verifier_result') or {}).get('rewards') or {}).get('reward','')
  call_records=records(agent/'calls.jsonl');calls={}
  for r in call_records:calls.setdefault(r['index'],{}).update(r)
  trajectory=json.loads((agent/'trajectory.json').read_text()) if (agent/'trajectory.json').exists() else {}
  native=[tc for step in trajectory.get('steps',[]) for tc in step.get('tool_calls',[])]
  native_cursor=0
  for i,call in sorted(calls.items()):
   if call.get('unit')!='tool_call':continue
   for pos in range(native_cursor,len(native)):
    if native[pos].get('arguments',{}).get('keystrokes')==call.get('keystrokes'):
     call['native_tool_call_id']=native[pos].get('tool_call_id','');native_cursor=pos+1;break
  ordered=sorted(calls);starts=[calls[i]['start_ns'] for i in ordered]
  def index(ts):
   pos=bisect.bisect_right(starts,int(ts))-1
   return ordered[pos] if pos>=0 else 0
  matches=[x for x in records(agent/'engine.log') if x.get('event')=='TAINT_VIOLATION']
  events=[x for x in matches if x.get('killed') is True or x.get('blocked') is True]
  failed_enforcement=[x for x in matches if x.get('effect') in ('kill','block') and not (x.get('killed') is True or x.get('blocked') is True)]
  # Root-mode observer prints only owner=benchmark. Older exploratory observers
  # also recorded disjoint replay tags; those records never enter these counts.
  observer=records(agent/'observer.jsonl');reads=[];connects=[]
  for event in observer:
   if event.get('type')!='printf':continue
   for line in event.get('data','').splitlines():
    parts=line.split('|',4)
    if len(parts)!=5 or parts[2]!='benchmark':continue
    kind,ts,owner,pid,value=parts
    if kind=='READ':reads.append(dict(timestamp_ns=int(ts),pid=int(pid),path=value,path_truncated=int(len(value.encode())>=127),call_index=index(ts)))
    if kind=='CONNECT':connects.append(dict(timestamp_ns=int(ts),pid=int(pid),family=value,call_index=index(ts)))
  status=json.loads((agent/'observer-status.json').read_text()) if (agent/'observer-status.json').exists() else {}
  raw_observer=(agent/'observer.jsonl').read_text(errors='replace') if (agent/'observer.jsonl').exists() else ''
  raw_engine=(agent/'engine.log').read_text(errors='replace') if (agent/'engine.log').exists() else ''
  coverage='complete' if status and not any(x.get('unexpected_exit') for x in status.values()) and not re.search(r'"type"\s*:\s*"(lost_events|error|helper_error)"|lost \d+ events|ERROR:',raw_observer,re.I) else 'incomplete'
  scope=json.loads((agent/'scope.json').read_text()) if (agent/'scope.json').exists() else {}
  if not scope.get('kernel_root_verified'):coverage='incomplete'
  if condition!='a' and 'engine' not in status:coverage='incomplete'
  engine_diagnostic=bool(re.search(r'helper_error|ERROR:|failed to (?:load|attach)|ring.*(?:lost|drop)',raw_engine,re.I))
  if engine_diagnostic:coverage='incomplete'
  if failed_enforcement:coverage='incomplete'
  infrastructure=exception.get('exception_type','')
  if not infrastructure:run_status='complete'
  elif infrastructure in ('AgentTimeoutError','VerifierTimeoutError'):run_status='official_timeout'
  else:run_status='infrastructure_failure'
  trial_id=result_path.parent.name
  common=dict(task=task,condition=condition,attempt=attempt,trial_id=trial_id,main_matrix=int(attempt=='1'))
  fired_by_index={i:sum(index(e['timestamp'])==i for e in events) for i in ordered}
  killed=sum(bool(e.get('killed')) for e in events)
  trials.append(dict(**common,model=(d.get('agent_info',{}).get('model_info') or {}).get('name',''),run_status=run_status,official_reward=reward,official_success=int(reward==1) if reward!='' else '',exception_type=infrastructure,exception_message=exception.get('exception_message','')[:300],wall_s=seconds(d),environment_setup_s=seconds(d.get('environment_setup')),agent_setup_s=seconds(d.get('agent_setup')),agent_execution_s=seconds(d.get('agent_execution')),verifier_s=seconds(d.get('verifier')),tool_calls=len(calls),call_unit='tool_call' if calls and all(c.get('unit')=='tool_call' for c in calls.values()) else 'command_batch',intervention_events=len(events),killed_events=killed,intervened_calls=sum(v>0 for v in fired_by_index.values()),confirmed_false_events=0,confirmed_true_events=0,unknown_events=len(events),source_read_accesses=len(reads),source_read_processes=len({r['pid'] for r in reads}),source_paths=len({r['path'] for r in reads}),connect_attempts=len(connects),coverage=coverage,raw_result=str(result_path)))
  for i in ordered:
   call=calls[i];bin_start=((i-1)//10)*10+1
   calls_out.append(dict(**common,call_index=i,native_tool_call_id=call.get('native_tool_call_id',''),bin_start=bin_start,bin_end=bin_start+9,start_ns=call['start_ns'],end_ns=call.get('end_ns',''),intervention_events=fired_by_index[i],intervened=int(fired_by_index[i]>0),confirmed_false=0,unknown=int(fired_by_index[i]>0),source_read_accesses=sum(r['call_index']==i for r in reads),connect_attempts=sum(r['call_index']==i for r in connects),coverage=coverage))
  trials[-1].update(atif_logged_tool_calls=len(native),dispatched_tool_calls=len(calls),unexecuted_or_unmapped_atif_calls=max(0,len(native)-len(calls)),kernel_root_verified=int(bool(scope.get('kernel_root_verified'))),kernel_root_pid=scope.get('root_host_pid',''),workspace_root_pid=scope.get('root_workspace_pid',''),observer_sha256=hashlib.sha256((agent/'observer.bt').read_bytes()).hexdigest() if (agent/'observer.bt').exists() else '',policy_sha256=hashlib.sha256((agent/'policy.bin').read_bytes()).hexdigest() if (agent/'policy.bin').exists() else '',raw_rule_matches=len(matches),failed_enforcement_events=len(failed_enforcement),unattributed_intervention_events=sum(index(e['timestamp'])==0 for e in events),inet4_connect_attempts=sum(r['family']=='2' for r in connects),inet6_connect_attempts=sum(r['family']=='10' for r in connects),unix_connect_attempts=sum(r['family']=='1' for r in connects),engine_diagnostic_error=int(engine_diagnostic),observer_helper_errors=raw_observer.count('"type":"helper_error"')+raw_observer.count('"type": "helper_error"'))
  for number,e in enumerate(matches,1):
   actual=e.get('killed') is True or e.get('blocked') is True
   events_out.append(dict(**common,event_id=number,call_index=index(e['timestamp']),timestamp_ns=e['timestamp'],pid=e['pid'],session_root=e.get('session_root',''),effect=e.get('effect',''),killed=e.get('killed',''),blocked=e.get('blocked',''),is_intervention=int(actual),target=e.get('target',''),provenance=json.dumps(e.get('provenance'),sort_keys=True),adjudication='unknown' if actual else 'not_an_intervention',evidence='Independent semantic adjudication pending' if actual else 'No successful kill/block receipt'))
  reads_out.extend(dict(**common,**r) for r in reads)
write('trials.csv',trials,['task','condition','attempt','trial_id','main_matrix','model','run_status','official_reward','official_success','exception_type','exception_message','wall_s','environment_setup_s','agent_setup_s','agent_execution_s','verifier_s','tool_calls','call_unit','atif_logged_tool_calls','dispatched_tool_calls','unexecuted_or_unmapped_atif_calls','raw_rule_matches','intervention_events','killed_events','intervened_calls','confirmed_false_events','confirmed_true_events','unknown_events','failed_enforcement_events','unattributed_intervention_events','source_read_accesses','source_read_processes','source_paths','connect_attempts','inet4_connect_attempts','inet6_connect_attempts','unix_connect_attempts','coverage','engine_diagnostic_error','observer_helper_errors','kernel_root_verified','kernel_root_pid','workspace_root_pid','observer_sha256','policy_sha256','raw_result'])
write('calls.csv',calls_out,['task','condition','attempt','trial_id','main_matrix','call_index','native_tool_call_id','bin_start','bin_end','start_ns','end_ns','intervention_events','intervened','confirmed_false','unknown','source_read_accesses','connect_attempts','coverage'])
write('interventions.csv',events_out,['task','condition','attempt','trial_id','main_matrix','event_id','call_index','timestamp_ns','pid','session_root','effect','killed','blocked','is_intervention','target','provenance','adjudication','evidence'])
write('source-read-accesses.csv',reads_out,['task','condition','attempt','trial_id','main_matrix','timestamp_ns','pid','path','path_truncated','call_index'])
print('Trials',len(trials),'official outcomes',sum(r['official_reward']!='' for r in trials),'events',len(events_out))
