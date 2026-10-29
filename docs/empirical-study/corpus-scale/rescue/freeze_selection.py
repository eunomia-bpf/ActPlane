#!/usr/bin/env python3
"""Select using dev scores only and freeze inference before test requests."""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,DEFAULT_RAW,read_csv,write_csv,digest,now
OUT=HERE/'rescue'

def main():
 candidates=[]
 for p in sorted(OUT.glob('dev-r*-scores.csv')):
  rows=[r for r in read_csv(p) if r['model']=='adjudicated' and r['scope']=='applicable_gold']
  assert len(rows)==2
  if not all(float(r['coverage'])>=.98 for r in rows):continue
  scores=[float(r['kappa']) for r in rows];candidates.append((rows[0]['revision'],min(scores),sum(scores)/len(scores)))
 assert candidates and len(candidates)<=3
 early=next((c for c in candidates if c[1]>=.65),None)
 if early is None and len(candidates)<3:raise SystemExit('Another dev revision is permitted; freeze only after early-stop or revision cap.')
 selected=early if early else max(candidates,key=lambda c:(c[1],c[2],-int(c[0][1:])))
 revision,minimum,mean=selected
 record=dict(revision=revision,selected_at=now(),min_dev_kappa=minimum,mean_dev_kappa=mean,codebook_sha256=digest((OUT/f'codebook-{revision}.txt').read_bytes()),examples_sha256=digest((OUT/f'examples-{revision}.csv').read_bytes()),engine_sha256=digest((OUT/'label_rescue.py').read_bytes()),context_builder_sha256=digest((OUT/'build_inputs.py').read_bytes()),test_inputs_sha256=digest((OUT/'test_inputs.csv').read_bytes()),repository_split_sha256=digest((OUT/'repository_split.csv').read_bytes()),source_inputs_sha256=digest((DEFAULT_RAW/'rescue-source-inputs.csv').read_bytes()),dev_scores_sha256=digest((OUT/f'dev-{revision}-scores.csv').read_bytes()),test_and_source_batch_size=48,test_and_source_max_chars=60000,remote_completion_token_ceiling=20000,remote_timeout_seconds=600,model_qwen='qwen3.8-27b-nvfp4',model_glm='zai/glm-5.3',selection_rule='first_min_dev_kappa_at_least_065_else_best_min_at_cap',holdout_caveat='prospective_only_prior_full_reference_evaluated')
 path=OUT/'frozen_selection.json'
 if path.exists():
  prior=json.loads(path.read_text());assert all(prior[k]==v for k,v in record.items() if k!='selected_at'),'Frozen selection cannot change'
 else:path.write_text(json.dumps(record,indent=2)+'\n')
 write_csv(OUT/'selection.csv',[record]);print(json.dumps(record,indent=2))
if __name__=='__main__':main()
