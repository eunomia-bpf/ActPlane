"""Use shared, unchanged-default CSV logic with explicit separate cohort paths."""
import csv,hashlib,os,runpy
from pathlib import Path
import json
HERE=Path(__file__).resolve().parent
abi_helpers=runpy.run_path(str(HERE/'freeze.py'))
canonical=abi_helpers['canonical'];abi_fields=abi_helpers['fields']
os.environ.update(BU_ANALYSIS_RAW='/workspaces/exp/benign-utility/raw/benchmark/network',BU_ANALYSIS_OUT='/workspaces/exp/benign-utility/benchmark/network/results',BU_ANALYSIS_COHORT='network_exposure_followup')
for filename in ('analyze.py','scope_audit.py','analyze.py'):runpy.run_path(str(HERE.parent/filename),run_name='__main__')
OUT=Path(os.environ['BU_ANALYSIS_OUT'])
def read(name):return list(csv.DictReader((OUT/name).open())) if (OUT/name).exists() else []
def write(name,rows,original_fields):
 fields=list(dict.fromkeys(original_fields+[key for row in rows for key in row]))
 with (OUT/name).open('w',newline='') as handle:
  writer=csv.DictWriter(handle,fieldnames=fields);writer.writeheader();writer.writerows(rows)
def fields(name):
 with (OUT/name).open() as handle:return next(csv.reader(handle))
trials=read('trials.csv');calls=read('calls.csv');events=read('interventions.csv')
expected_policies={(r['task'],r['condition']):r for r in read('policies.csv')}
policy_audit=[]
for trial in trials:
 if trial['condition']=='a':trial['policy_fields_verified']='not_applicable';continue
 directory=Path(trial['raw_result']).parent/'agent';blob=directory/'policy.bin';dsl=directory/'policy.dsl'
 expected=expected_policies[(trial['task'],trial['condition'])]
 if not blob.exists() or not dsl.exists():trial['policy_fields_verified']='not_available';continue
 active=hashlib.sha256(json.dumps([canonical(x) for x in abi_fields(blob.read_bytes())],sort_keys=True).encode()).hexdigest()
 actual_dsl=hashlib.sha256(dsl.read_bytes()).hexdigest();log=(directory/'engine.log').read_text()
 equivalent=active==expected['active_abi_sha256'] and actual_dsl==expected['dsl_sha256']
 zero_seed=f"seeded pid {trial['kernel_root_pid']} label 0x0" in log
 trial['policy_fields_verified']=int(equivalent and zero_seed)
 policy_audit.append(dict(task=trial['task'],condition=trial['condition'],trial_id=trial['trial_id'],actual_active_abi_sha256=active,expected_active_abi_sha256=expected['active_abi_sha256'],dsl_equal=int(actual_dsl==expected['dsl_sha256']),active_fields_equal=int(equivalent),zero_seed_verified=int(zero_seed),actual_binary_sha256=hashlib.sha256(blob.read_bytes()).hexdigest()))
 if not equivalent or not zero_seed:
  trial['selected_for_comparison']='0';trial['instrumentation_coverage']='incomplete';trial['comparison_exclusion_reason']+=';executed_policy_or_seed_mismatch'
  for call in calls:
   if call['trial_id']==trial['trial_id']:call.update(selected_for_comparison='0',coverage='incomplete')
if policy_audit:write('executed-policy-equivalence.csv',policy_audit,list(policy_audit[0]))
call_map={(r['trial_id'],r['call_index']):r for r in calls}
origins={(r['trial_id'],r['event_id']):r for r in read('action-origin-verifications.csv') if r.get('status')=='verified'}
adjudications={(r['trial_id'],r['event_id']):r for r in read('intervention-adjudications.csv')}
for event in events:
 event['temporal_call_index']=event['call_index']
 temporal=call_map.get((event['trial_id'],event['call_index']),{})
 event['temporal_action_kind']=temporal.get('action_kind','pretool_or_unmapped')
 event['call_index']='0';event['action_attribution']='unassigned_origin';event['origin_evidence']=''
 if event['is_intervention']!='1':event['action_attribution']='not_an_intervention';continue
 key=(event['trial_id'],event['event_id'])
 if key in adjudications:
  annotation=adjudications[key];assert annotation['adjudication'] in ('false_intervention','true_violation','unknown')
  event.update(adjudication=annotation['adjudication'],evidence=annotation['evidence'])
 if key in origins:
  proof=origins[key];origin=call_map[(event['trial_id'],proof['call_index'])]
  assert proof['timestamp_ns']==event['timestamp_ns'] and proof['pid']==event['pid']
  assert origin['coverage']=='complete' and origin['action_kind'] in ('command','interrupt')
  event.update(call_index=proof['call_index'],action_attribution='independently_verified_origin',origin_evidence=proof['evidence'])
for call in calls:
 associated=[e for e in events if e['trial_id']==call['trial_id'] and e['call_index']==call['call_index'] and e['is_intervention']=='1']
 call.update(intervention_events=len(associated),intervened=int(bool(associated)),confirmed_false=int(any(e['adjudication']=='false_intervention' for e in associated)),unknown=int(any(e['adjudication']=='unknown' for e in associated)))
 call['attribution_method']='verified action origin only; timestamps retained separately'
for trial in trials:
 actual=[e for e in events if e['trial_id']==trial['trial_id'] and e['is_intervention']=='1']
 eligible=[c for c in calls if c['trial_id']==trial['trial_id'] and c['coverage']=='complete' and c['action_kind'] in ('command','interrupt')]
 trial.update(unattributed_intervention_events=sum(e['call_index']=='0' for e in actual),intervened_calls=sum(int(c['intervened']) for c in eligible),confirmed_false_events=sum(e['adjudication']=='false_intervention' for e in actual),confirmed_true_events=sum(e['adjudication']=='true_violation' for e in actual),unknown_events=sum(e['adjudication']=='unknown' for e in actual),action_attribution_method='independent origin verification; otherwise explicit unassigned')
extras={'trials.csv':['action_attribution_method','policy_fields_verified'],'calls.csv':['attribution_method'],'interventions.csv':['temporal_call_index','temporal_action_kind','action_attribution','origin_evidence']}
for name,rows in [('trials.csv',trials),('calls.csv',calls),('interventions.csv',events)]:write(name,rows,fields(name)+extras[name])
for row in read('primary-freeze.csv'):
 path=OUT.parent.parent/'results'/row['file']
 assert hashlib.sha256(path.read_bytes()).hexdigest()==row['sha256'],'Frozen original primary outputs changed'
