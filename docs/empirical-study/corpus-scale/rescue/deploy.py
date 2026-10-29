#!/usr/bin/env python3
"""Publish only heldout-passing axes, preserving frozen type/topic and provenance."""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,read_csv,write_csv,digest
OUT=HERE/'rescue'

def main():
 selection=json.loads((OUT/'frozen_selection.json').read_text());rev=selection['revision']
 tests={r['dimension']:r for r in read_csv(OUT/'test_gates.csv')}
 enforce=tests['enforceability']['passed']=='True';context=enforce and tests['context_required']['passed']=='True'
 inputs={r['statement_id']:r for r in read_csv(HERE/'labels.csv') if r['type']=='directive'}
 provenance=[]
 for name,original in [('qwen','labels_qwen.csv'),('glm','labels_glm.csv'),('adjudicated','labels.csv')]:
  path=OUT/f'source-{name}.csv';pred={r['statement_id']:r for r in read_csv(path)}
  assert set(pred)==set(inputs) and all(r['status']=='ok' for r in pred.values()),'Incomplete rescue source labels'
  assert all(r['revision']==rev for r in pred.values())
  provenance.append(dict(source_file=str(path.relative_to(HERE)),sha256=digest(path.read_bytes()),rows=len(pred),revision=rev))
  if name!='adjudicated':continue
  rows=read_csv(HERE/original)
  for r in rows:
   if r['statement_id'] not in pred:
    # Retain each primary's original type decision, including its discrepancies.
    # The new axes apply only to the frozen adjudicated directive set.
    r.update(enforceability='',context_required='');continue
   p=pred[r['statement_id']]
   r.update(enforceability=p['enforceability'] if enforce else '',context_required=p['context_required'] if context else '',rescue_revision=rev,rescue_model=p['model'],rescue_returned_model=p['returned_model'],rescue_adjudicated=p['adjudicated'],rescue_guide_sha256=p['guide_sha256'],rescue_context_sha256=p['context_sha256'])
  write_csv(HERE/original,rows)
 write_csv(OUT/'deployment_manifest.csv',provenance)
 write_csv(OUT/'deployment_gates.csv',[dict(dimension=d,passed=p,revision=rev,test_kappa=tests[d]['test_kappa'],reason='passed_test_gate' if p else 'parent_enforcement_gate_failed' if d=='context_required' and tests[d]['passed']=='True' else 'test_gate_failed') for d,p in [('enforceability',enforce),('context_required',context)]])
if __name__=='__main__':main()
