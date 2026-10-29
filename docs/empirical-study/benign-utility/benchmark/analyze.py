"""Export official Harbor rewards and separately labeled security diagnostics."""
import bisect,csv,hashlib,json,re,struct
from datetime import datetime
from pathlib import Path
RAW=Path('/workspaces/exp/benign-utility/raw/benchmark');HERE=Path(__file__).parent;OUT=RAW.parent.parent/'benchmark/results';OUT.mkdir(parents=True,exist_ok=True)
tasks=[r['task'] for r in csv.DictReader((OUT/'tasks.csv').open())]
audits={r['trial_id']:r for r in csv.DictReader((OUT/'error-audit.csv').open())} if (OUT/'error-audit.csv').exists() else {}
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

def verifier_evidence(directory):
 text='\n'.join(p.read_text(errors='replace') for p in directory.glob('test-std*.txt'))
 if re.search(r'ERROR collecting|errors? during collection',text):
  return 'unknown','collection_error_requires_audit','',str(directory/'test-stdout.txt'),'Audit agent-artifact failure versus verifier dependency before selecting or retrying'
 reports=[]
 for path in directory.glob('*.json'):
  try:report=json.loads(path.read_text())
  except (ValueError,OSError):continue
  result=report.get('results') or {}
  if isinstance(result,dict) and isinstance(result.get('tests'),list) and result['tests']:
   reports.append((path,result))
 if reports:
  path,result=reports[0]
  return '1','official_ctrf_tests',len(result['tests']),str(path),json.dumps(result.get('summary',{}),sort_keys=True)
 bootstrap=[line.strip() for line in text.splitlines() if re.search(r'uvx: (?:command )?not found|failed to download https://github.com/astral-sh/(?:uv|python-build-standalone)|/root/\.local/bin/env: No such file',line,re.I)]
 if bootstrap:return '0','verifier_bootstrap_failure','',str(directory/'test-stdout.txt'),' | '.join(bootstrap)[:1000]
 if re.search(r'(?m)^=+ .*\b\d+ (?:passed|failed|errors?|skipped)\b.*=+\s*$',text):
  return '1','official_pytest_summary','',str(directory/'test-stdout.txt'),'Native pytest result summary present'
 return 'unknown','verifier_execution_unestablished','',str(directory/'test-stdout.txt'),'No native CTRF tests or pytest result summary found'

def network_rule_effect(agent,condition):
 if condition=='a':return 'none'
 if not (agent/'policy.bin').exists():return 'unknown'
 data=(agent/'policy.bin').read_bytes()
 if len(data)!=74760:return 'unknown'
 count=struct.unpack_from('<I',data,4)[0]
 if count>128:return 'unknown'
 effects={data[46088+i*224+5] for i in range(count) if data[46088+i*224]==3}
 return {0:'notify',1:'block',2:'kill'}.get(next(iter(effects)),'unknown') if len(effects)==1 else 'mixed_or_unknown'
trials=[];calls_out=[];events_out=[];reads_out=[]
for job in sorted((RAW/'jobs').glob('*')):
 task=next((t for t in tasks if job.name.startswith(t+'-')),None)
 if not task:continue
 condition,attempt=job.name[len(task)+1:].split('-',1)
 job_config=json.loads((job/'config.json').read_text()) if (job/'config.json').exists() else {}
 for result_path in job.glob('*/result.json'):
  d=json.loads(result_path.read_text());agent=result_path.parent/'agent';exception=d.get('exception_info') or {};reward=((d.get('verifier_result') or {}).get('rewards') or {}).get('reward','')
  scope=json.loads((agent/'scope.json').read_text()) if (agent/'scope.json').exists() else {}
  observer_text=(agent/'observer.bt').read_text() if (agent/'observer.bt').exists() else ''
  explicit_path=re.search(r'path\(args\.file->f_path\s*,\s*(\d+)\)',observer_text)
  string_bytes=int(scope.get('observer_string_bytes',128))
  path_bytes=int(explicit_path[1]) if explicit_path else string_bytes
  effective_bytes=min(string_bytes,path_bytes)
  call_records=records(agent/'calls.jsonl');calls={}
  for r in call_records:calls.setdefault(r['index'],{}).update(r)
  trajectory=json.loads((agent/'trajectory.json').read_text()) if (agent/'trajectory.json').exists() else {}
  native=[tc for step in trajectory.get('steps',[]) for tc in step.get('tool_calls',[])]
  native_commands=[tc for tc in native if tc.get('function_name')=='bash_command']
  native_cursor=0
  for i,call in sorted(calls.items()):
   if call.get('unit')!='tool_call':continue
   for pos in range(native_cursor,len(native_commands)):
    if native_commands[pos].get('arguments',{}).get('keystrokes')==call.get('keystrokes'):
     call['native_tool_call_id']=native_commands[pos].get('tool_call_id','');native_cursor=pos+1;break
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
    if kind=='READ':reads.append(dict(timestamp_ns=int(ts),pid=int(pid),path=value,path_truncated=int(len(value.encode())>=effective_bytes-1),call_index=index(ts)))
    if kind=='CONNECT':connects.append(dict(timestamp_ns=int(ts),pid=int(pid),family=value,call_index=index(ts)))
  status=json.loads((agent/'observer-status.json').read_text()) if (agent/'observer-status.json').exists() else {}
  raw_observer=(agent/'observer.jsonl').read_text(errors='replace') if (agent/'observer.jsonl').exists() else ''
  raw_engine=(agent/'engine.log').read_text(errors='replace') if (agent/'engine.log').exists() else ''
  engine_mode=re.search(r'ActPlane: (enforce|tracepoint) mode',raw_engine)
  network_effect=network_rule_effect(agent,condition)
  coverage='complete' if status and not any(x.get('unexpected_exit') for x in status.values()) and not re.search(r'"type"\s*:\s*"(lost_events|error|helper_error)"|lost \d+ events|ERROR:',raw_observer,re.I) else 'incomplete'
  if not scope.get('kernel_root_verified'):coverage='incomplete'
  if condition!='a' and 'engine' not in status:coverage='incomplete'
  engine_diagnostic=bool(re.search(r'helper_error|ERROR:|failed to (?:load|attach)|ring.*(?:lost|drop)',raw_engine,re.I))
  if engine_diagnostic:coverage='incomplete'
  if failed_enforcement:coverage='incomplete'
  if network_effect=='block' and (not engine_mode or engine_mode[1]!='enforce'):coverage='incomplete'
  trial_id=result_path.parent.name
  audit=audits.get(trial_id)
  if audit and audit['audit']=='agent_induced_shell_exit' and coverage=='complete':coverage='partial_agent_scope_exit'
  infrastructure=exception.get('exception_type','')
  if not infrastructure:run_status='complete'
  elif infrastructure in ('AgentTimeoutError','VerifierTimeoutError'):run_status='official_timeout'
  else:run_status='infrastructure_failure'
  common=dict(task=task,condition=condition,attempt=attempt,trial_id=trial_id,main_matrix=int(attempt=='1' or re.fullmatch(r'(?:repair|block)-\d+',attempt) is not None))
  fired_by_index={i:sum(index(e['timestamp'])==i for e in events) for i in ordered}
  killed=sum(bool(e.get('killed')) for e in events)
  trials.append(dict(**common,model=(d.get('agent_info',{}).get('model_info') or {}).get('name',''),run_status=run_status,official_reward=reward,official_success=int(reward==1) if reward!='' else '',exception_type=infrastructure,exception_message=exception.get('exception_message','')[:300],wall_s=seconds(d),environment_setup_s=seconds(d.get('environment_setup')),agent_setup_s=seconds(d.get('agent_setup')),agent_execution_s=seconds(d.get('agent_execution')),verifier_s=seconds(d.get('verifier')),tool_calls=len(calls),call_unit='tool_call' if calls and all(c.get('unit')=='tool_call' for c in calls.values()) else 'command_batch',intervention_events=len(events),killed_events=killed,intervened_calls=sum(v>0 for v in fired_by_index.values()),confirmed_false_events=0,confirmed_true_events=0,unknown_events=len(events),source_read_accesses=len(reads),source_read_processes=len({r['pid'] for r in reads}),source_paths=len({r['path'] for r in reads}),connect_attempts=len(connects),coverage=coverage,raw_result=str(result_path)))
  for i in ordered:
   call=calls[i];bin_start=((i-1)//10)*10+1
   call_coverage=coverage
   if coverage=='partial_agent_scope_exit':call_coverage='complete' if i<=int(audit['security_coverage_end_call']) else 'out_of_scope'
   calls_out.append(dict(**common,call_index=i,native_tool_call_id=call.get('native_tool_call_id',''),bin_start=bin_start,bin_end=bin_start+9,start_ns=call['start_ns'],end_ns=call.get('end_ns',''),intervention_events=fired_by_index[i],intervened=int(fired_by_index[i]>0),confirmed_false=0,unknown=int(fired_by_index[i]>0),source_read_accesses=sum(r['call_index']==i for r in reads),connect_attempts=sum(r['call_index']==i for r in connects),coverage=call_coverage))
  trials[-1].update(atif_logged_tool_calls=len(native),atif_logged_command_calls=len(native_commands),atif_nonterminal_tool_calls=len(native)-len(native_commands),dispatched_tool_calls=len(calls),unexecuted_or_unmapped_command_calls=max(0,len(native_commands)-len({c['native_tool_call_id'] for c in calls.values() if c.get('native_tool_call_id')})),kernel_root_verified=int(bool(scope.get('kernel_root_verified'))),kernel_root_pid=scope.get('root_host_pid',''),workspace_root_pid=scope.get('root_workspace_pid',''),observer_sha256=hashlib.sha256((agent/'observer.bt').read_bytes()).hexdigest() if (agent/'observer.bt').exists() else '',policy_sha256=hashlib.sha256((agent/'policy.bin').read_bytes()).hexdigest() if (agent/'policy.bin').exists() else '',raw_rule_matches=len(matches),failed_enforcement_events=len(failed_enforcement),unattributed_intervention_events=sum(index(e['timestamp'])==0 for e in events),inet4_connect_attempts=sum(r['family']=='2' for r in connects),inet6_connect_attempts=sum(r['family']=='10' for r in connects),unix_connect_attempts=sum(r['family']=='1' for r in connects),engine_diagnostic_error=int(engine_diagnostic),observer_helper_errors=sum(e.get('type')=='helper_error' for e in observer))
  trials[-1].update(observer_configured_string_bytes=string_bytes,observer_explicit_path_bytes=path_bytes,observer_effective_path_bytes=effective_bytes,observer_configuration_source='recorded_at_launch' if 'observer_string_bytes' in scope else 'inferred_from_legacy_adapter',engine_hook_environment=json.dumps(scope.get('engine_hook_environment','not_recorded_at_launch'),sort_keys=True),engine_reported_mode=engine_mode[1] if engine_mode else 'not_recorded_or_not_applicable')
  matched_ids={c['native_tool_call_id'] for c in calls.values() if c.get('native_tool_call_id')}
  trials[-1].update(terminal_submission_attempts=len(calls),native_commands_without_dispatch_receipt=len(native_commands)-len(matched_ids),dispatch_receipts_without_native_command=sum(not c.get('native_tool_call_id') for c in calls.values()))
  valid,verifier_status,test_count,report_path,verification=verifier_evidence(result_path.parent/'verifier')
  root_killed=any(e.get('killed') is True and e.get('pid')==scope.get('root_host_pid') for e in events)
  effective=run_status if valid=='1' else ('infrastructure_failure' if valid=='0' else 'verifier_unverified')
  if valid=='1' and root_killed and scope.get('kernel_root_verified') and run_status=='infrastructure_failure':effective='defense_forced_failure'
  outcome_valid=valid
  outcome_score=reward if valid=='1' else ''
  outcome_source='official_verifier_reward' if valid=='1' else 'unestablished'
  if audit and audit['audit']=='agent_induced_shell_exit':
   outcome_valid='1';outcome_score=float(audit['official_job_mean']);outcome_source='official_default_mean_agent_error';effective='agent_error'
  trials[-1].update(outcome_valid=outcome_valid,outcome_score=outcome_score,outcome_success=int(outcome_score==1) if outcome_score!='' else '',outcome_source=outcome_source,security_coverage_end_call=audit.get('security_coverage_end_call','') if audit else '',visibly_dispatched_calls=audit.get('visibly_dispatched_calls','unverified') if audit else 'unverified')
  trials[-1].update(native_run_status=run_status,effective_run_status=effective,verifier_valid=valid,verifier_status=verifier_status,verifier_observed_tests=test_count,verifier_report_path=report_path,verifier_evidence=verification,trial_started_at=d.get('started_at',''),trial_finished_at=d.get('finished_at',''),selected_for_comparison=0)
  trial_config=d.get('config') or {}
  download_url=((job_config.get('verifier') or {}).get('env') or {}).get('UV_DOWNLOAD_URL',((trial_config.get('verifier') or {}).get('env') or {}).get('UV_DOWNLOAD_URL',''))
  corrected=download_url=='http://172.29.77.1:38765' and string_bytes==1024 and effective_bytes==1024
  exclusions=[]
  if not common['main_matrix']:exclusions.append('preflight_not_main_comparison')
  if not download_url:exclusions.append('legacy_or_unrecorded_verifier_transport')
  elif download_url!='http://172.29.77.1:38765':exclusions.append('different_verifier_transport')
  if string_bytes!=1024 or effective_bytes!=1024:exclusions.append('legacy_observer_configuration')
  if condition!='a' and network_effect=='kill':exclusions.append('kill_mode_supporting_only')
  elif condition!='a' and network_effect!='block':exclusions.append('network_effect_unverified_or_not_denial')
  if outcome_valid!='1':exclusions.append(verifier_status)
  if coverage not in ('complete','partial_agent_scope_exit'):exclusions.append('instrumentation_incomplete')
  if run_status=='infrastructure_failure' and effective not in ('defense_forced_failure','agent_error'):exclusions.append('native_infrastructure_failure')
  if outcome_score=='':exclusions.append('native_outcome_unavailable')
  cohort='legacy_or_preflight_supporting'
  if corrected and common['main_matrix']:cohort='native_denial_primary' if condition=='a' or network_effect=='block' else 'corrected_kill_supporting'
  trials[-1].update(comparison_cohort=cohort,comparison_exclusion_reason=';'.join(exclusions),verifier_download_url=download_url,defense_root_killed=int(root_killed),network_effect=network_effect)
  for number,e in enumerate(matches,1):
   actual=e.get('killed') is True or e.get('blocked') is True
   events_out.append(dict(**common,event_id=number,call_index=index(e['timestamp']),timestamp_ns=e['timestamp'],pid=e['pid'],session_root=e.get('session_root',''),effect=e.get('effect',''),killed=e.get('killed',''),blocked=e.get('blocked',''),is_intervention=int(actual),target=e.get('target',''),provenance=json.dumps(e.get('provenance'),sort_keys=True),adjudication='unknown' if actual else 'not_an_intervention',evidence='Independent semantic adjudication pending' if actual else 'No successful kill/block receipt'))
  reads_out.extend(dict(**common,**r) for r in reads)
selected=set()
for row in sorted(trials,key=lambda r:(r['trial_started_at'],r['trial_id'])):
 key=(row['task'],row['condition'])
 if row['comparison_cohort']=='native_denial_primary' and key not in selected and row['outcome_valid']=='1' and row['coverage'] in ('complete','partial_agent_scope_exit') and row['effective_run_status'] in ('complete','official_timeout','defense_forced_failure','agent_error') and row['outcome_score']!='':
  row['selected_for_comparison']=1;selected.add(key)
 elif row['comparison_cohort']=='native_denial_primary' and not row['comparison_exclusion_reason']:row['comparison_exclusion_reason']='later_valid_corrected_attempt'
selection={r['trial_id']:r['selected_for_comparison'] for r in trials}
for row in calls_out:row['selected_for_comparison']=selection[row['trial_id']]
write('trials.csv',trials,['task','condition','attempt','trial_id','main_matrix','selected_for_comparison','comparison_cohort','comparison_exclusion_reason','network_effect','model','run_status','native_run_status','effective_run_status','verifier_valid','verifier_status','verifier_observed_tests','verifier_report_path','verifier_evidence','verifier_download_url','trial_started_at','trial_finished_at','official_reward','official_success','exception_type','exception_message','wall_s','environment_setup_s','agent_setup_s','agent_execution_s','verifier_s','tool_calls','call_unit','atif_logged_tool_calls','atif_logged_command_calls','atif_nonterminal_tool_calls','dispatched_tool_calls','unexecuted_or_unmapped_command_calls','raw_rule_matches','intervention_events','killed_events','intervened_calls','confirmed_false_events','confirmed_true_events','unknown_events','failed_enforcement_events','unattributed_intervention_events','defense_root_killed','source_read_accesses','source_read_processes','source_paths','connect_attempts','inet4_connect_attempts','inet6_connect_attempts','unix_connect_attempts','coverage','engine_diagnostic_error','observer_helper_errors','kernel_root_verified','kernel_root_pid','workspace_root_pid','observer_sha256','observer_configured_string_bytes','observer_explicit_path_bytes','observer_effective_path_bytes','observer_configuration_source','engine_hook_environment','engine_reported_mode','policy_sha256','raw_result','outcome_valid','outcome_score','outcome_success','outcome_source','security_coverage_end_call','visibly_dispatched_calls'])
write('call-accounting.csv',[{k:r[k] for k in ('task','condition','attempt','trial_id','terminal_submission_attempts','atif_logged_command_calls','native_commands_without_dispatch_receipt','dispatch_receipts_without_native_command')} for r in trials],['task','condition','attempt','trial_id','terminal_submission_attempts','atif_logged_command_calls','native_commands_without_dispatch_receipt','dispatch_receipts_without_native_command'])
write('calls.csv',calls_out,['task','condition','attempt','trial_id','main_matrix','selected_for_comparison','call_index','native_tool_call_id','bin_start','bin_end','start_ns','end_ns','intervention_events','intervened','confirmed_false','unknown','source_read_accesses','connect_attempts','coverage'])
write('interventions.csv',events_out,['task','condition','attempt','trial_id','main_matrix','event_id','call_index','timestamp_ns','pid','session_root','effect','killed','blocked','is_intervention','target','provenance','adjudication','evidence'])
write('source-read-accesses.csv',reads_out,['task','condition','attempt','trial_id','main_matrix','timestamp_ns','pid','path','path_truncated','call_index'])
print('Trials',len(trials),'native rewards',sum(r['official_reward']!='' for r in trials),'verified main selections',len(selected),'bootstrap failures',sum(r['verifier_valid']=='0' for r in trials),'events',len(events_out))
for row in trials:
 if row['selected_for_comparison']:print('PRIMARY',row['task'],row['condition'],row['attempt'],'reward='+str(row['official_reward']),'tests='+str(row['verifier_observed_tests']),row['coverage'])
