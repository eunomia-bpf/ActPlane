#!/usr/bin/env python3
"""Dev diagnostics or one frozen test evaluation, with no test-directed tuning."""
import argparse,json,sys
from pathlib import Path
from collections import Counter
import numpy as np
from sklearn.metrics import cohen_kappa_score
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,read_csv,write_csv,digest,now
OUT=HERE/'rescue'

def evaluate(stage,revision):
 split={r['repo']:r['split'] for r in read_csv(OUT/'repository_split.csv')}
 gold=[r for r in read_csv(HERE/'paper_labels.csv') if split[r['repo']]==stage and r['type']=='directive']
 paths=[OUT/f'{stage}-{revision}-{name}.csv' for name in ['qwen','glm','adjudicated']]
 if stage=='test':
  frozen=json.loads((OUT/'frozen_selection.json').read_text());assert frozen['revision']==revision
  assert frozen['codebook_sha256']==digest((OUT/f'codebook-{revision}.txt').read_bytes())
  assert frozen['examples_sha256']==digest((OUT/f'examples-{revision}.csv').read_bytes())
  signatures={p.name:digest(p.read_bytes()) for p in paths}
  lock=OUT/'test_evaluation_lock.json'
  if lock.exists():
   assert json.loads(lock.read_text())['prediction_hashes']==signatures,'Test predictions changed after evaluation'
   print('Frozen test evaluation already exists; unchanged cached metrics reused.');return
  lock.write_text(json.dumps(dict(at=now(),revision=revision,prediction_hashes=signatures),indent=2)+'\n')
 results=[];confusion=[];errors=[]
 for name,path in zip(['qwen','glm','adjudicated'],paths):
  pred={r['statement_id']:r for r in read_csv(path)}
  for dim in ['enforceability','context_required']:
   scopes=['applicable_gold'] if dim=='enforceability' else ['applicable_gold','all_directives_including_na']
   for scope in scopes:
    base=[r for r in gold if dim=='enforceability' or scope!='applicable_gold' or r['context_required']]
    left=[r[dim] or '__NA__' for r in base]
    right=[(pred[r['statement_id']].get(dim,'') or '__NA__') if pred.get(r['statement_id'],{}).get('status')=='ok' else '__MISSING__' for r in base]
    successful=sum(pred.get(r['statement_id'],{}).get('status')=='ok' for r in base)
    kappa=float(cohen_kappa_score(left,right))
    results.append(dict(stage=stage,revision=revision,model=name,dimension=dim,scope=scope,expected=len(base),successful=successful,missing=len(base)-successful,coverage=successful/len(base),agreement=float(np.mean(np.array(left)==right)),kappa=kappa,test_status='evaluated_once' if stage=='test' else 'not_evaluated'))
    confusion.extend(dict(stage=stage,revision=revision,model=name,dimension=dim,scope=scope,gold=g,prediction=p,count=n) for (g,p),n in sorted(Counter(zip(left,right)).items()))
    if stage=='dev' and scope=='applicable_gold':
     errors.extend(dict(revision=revision,model=name,dimension=dim,statement_id=r['statement_id'],gold=g,prediction=p,text=r['text']) for r,g,p in zip(base,left,right) if g!=p)
 write_csv(OUT/f'{stage}-{revision}-scores.csv',results)
 write_csv(OUT/f'{stage}-{revision}-confusion.csv',confusion)
 if stage=='dev':write_csv(OUT/f'dev-{revision}-errors.csv',errors)
 ledger=[]
 for path in sorted(OUT.glob('dev-r*-scores.csv')):
  for row in read_csv(path):
   if row['model']=='adjudicated' and row['scope']=='applicable_gold':
    tpath=OUT/f'test-{row["revision"]}-scores.csv'
    test=next((t for t in read_csv(tpath) if t['model']=='adjudicated' and t['scope']=='applicable_gold' and t['dimension']==row['dimension']),{}) if tpath.exists() else {}
    ledger.append(dict(revision=row['revision'],dimension=row['dimension'],dev_kappa=row['kappa'],dev_coverage=row['coverage'],test_kappa=test.get('kappa',''),test_coverage=test.get('coverage',''),test_status='evaluated_once' if test else 'not_evaluated'))
 write_csv(OUT/'iteration_ledger.csv',ledger)
 for r in results:
  if r['model']=='adjudicated' and r['scope']=='applicable_gold':print(r)
 if stage=='test':
  gates=[]
  for row in results:
   if row['model']=='adjudicated' and row['scope']=='applicable_gold':
    passed=row['kappa']>=.6 and row['coverage']>=.98
    gates.append(dict(dimension=row['dimension'],passed=passed,test_kappa=row['kappa'],coverage=row['coverage'],min_test_kappa=.6,min_coverage=.98,revision=revision,scope='prospective_repository_holdout_after_prior_full_reference_exposure',reason='passed_test_gate' if passed else 'below_test_gate'))
  write_csv(OUT/'test_gates.csv',gates)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--stage',choices=['dev','test'],required=True);p.add_argument('--revision',required=True);a=p.parse_args();evaluate(a.stage,a.revision)
