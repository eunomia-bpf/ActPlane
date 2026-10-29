#!/usr/bin/env python3
"""Fault-injection checks for contextual labeling, without model requests."""
import json,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
import label_rescue as label
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import DEFAULT_RAW,HERE,write_csv
checks=[]
def test(name,callback):
 callback();checks.append(dict(check=name,passed=True))
with tempfile.TemporaryDirectory(dir=DEFAULT_RAW,prefix='rescue-label-check-') as raw:
 a=SimpleNamespace(model='qwen3.8-27b-nvfp4',raw=Path(raw),stage='synthetic_check',revision='synthetic',guide_hash='synthetic',remote_tokens=20000)
 rows=[dict(statement_id=str(i),text='target',file_path='AGENTS.md',heading='heading',paragraph='context',context_sha256=str(i)) for i in range(2)]
 def response(values):return dict(model=a.model,choices=[dict(message=dict(content=json.dumps(dict(labels=values))))])
 def permuted():
  label.complete=lambda *args,**kwargs:response([[1,'content','none'],[0,'semantic_only','']])
  result=label.classify(a,rows,'guide',None)
  assert [r['statement_id'] for r in result]==['0','1'] and result[0]['context_required']==''
 test('permuted_ids_and_applicability',permuted)
 def partial():
  calls=[]
  def invoke(a,system,payload,**kwargs):
   calls.append(payload)
   return response([[0,'per_event','project'],[1,'content','INVALID']]) if len(calls)==1 else response([[0,'content','none']])
  label.complete=invoke;result=label.classify(a,rows,'guide',None)
  assert len(calls)==2 and len(calls[1]['statements'])==1 and result[0]['enforceability']=='per_event' and all(r['status']=='ok' for r in result)
 test('retains_valid_rows_and_retries_subset',partial)
 def transport():
  def invoke(*args,**kwargs):raise RuntimeError('model_request_failed')
  label.complete=invoke;result=label.classify(a,rows,'guide',None)
  assert len(result)==2 and all(r['status']=='failed' for r in result)
 test('transport_failure_preserves_every_id',transport)
 def broken():
  count=0
  def invoke(a,system,payload,**kwargs):
   nonlocal count
   count+=1
   return response([[0,'bad','bad']])
  label.complete=invoke;result=label.classify(a,rows,'guide',None)
  assert count==9 and len(result)==2 and all(r['status']=='failed' for r in result)
 test('schema_repairs_and_splits_are_bounded',broken)
write_csv(HERE/'rescue/label_validation.csv',checks)
print('Contextual label fault checks passed:',len(checks))
