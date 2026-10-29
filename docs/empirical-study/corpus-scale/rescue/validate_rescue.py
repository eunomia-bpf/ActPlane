#!/usr/bin/env python3
"""Verify split isolation, frozen execution, model identities and rescue coverage."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,DEFAULT_RAW,read_csv,write_csv,digest
OUT=HERE/'rescue'

def main(a):
 checks=[]
 def record(name,expected,actual):checks.append(dict(check=name,expected=expected,actual=actual,passed=expected==actual))
 split=read_csv(OUT/'repository_split.csv');dev={r['repo'] for r in split if r['split']=='dev'};test={r['repo'] for r in split if r['split']=='test'}
 gold=read_csv(HERE/'paper_labels.csv');gold_ids={r['statement_id']:r for r in gold}
 record('repository_partition_disjoint',0,len(dev&test));record('repository_partition_complete',{r['repo'] for r in gold}==dev|test,True)
 record('dev_repository_third',len(dev|test)//3,len(dev));record('statement_partition_complete',set(gold_ids),{r['statement_id'] for r in read_csv(OUT/'statement_split.csv')})
 selected=json.loads((OUT/'frozen_selection.json').read_text());rev=selected['revision']
 for name,key in [(f'codebook-{rev}.txt','codebook_sha256'),(f'examples-{rev}.csv','examples_sha256'),('label_rescue.py','engine_sha256'),('build_inputs.py','context_builder_sha256'),('test_inputs.csv','test_inputs_sha256'),('repository_split.csv','repository_split_sha256')]:record('frozen_'+key,selected[key],digest((OUT/name).read_bytes()))
 source_path=DEFAULT_RAW/'rescue-source-inputs.csv';record('frozen_source_inputs',selected['source_inputs_sha256'],digest(source_path.read_bytes()))
 examples=read_csv(OUT/f'examples-{rev}.csv');record('few_shot_test_repository_leakage',0,sum(r['repo'] not in dev for r in examples))
 record('few_shot_labels_match_dev_reference',0,sum(any(r[k]!=gold_ids[r['statement_id']][k] for k in ['text','enforceability','context_required']) for r in examples))
 record('maximum_codebook_revisions',True,len(list(OUT.glob('codebook-r*.txt')))<=3)
 record('test_scored_only_selected_revision',set([f'test-{rev}-scores.csv']),{p.name for p in OUT.glob('test-r*-scores.csv')})
 lock=json.loads((OUT/'test_evaluation_lock.json').read_text())
 for name,h in lock['prediction_hashes'].items():record('frozen_test_prediction_'+name,h,digest((OUT/name).read_bytes()))
 from freeze_retained_axes import fingerprint
 for r in read_csv(OUT/'retained_axes.csv'):
  source=read_csv(HERE/r['source_file'])
  record('retained_axes_'+r['source_file'],r['type_topic_sha256'],fingerprint(source))
  record('retained_rows_'+r['source_file'],int(r['rows']),len(source))
 inputs={'dev':read_csv(OUT/'dev_inputs.csv'),'test':read_csv(OUT/'test_inputs.csv'),'source':read_csv(source_path)}
 for stage,rs in inputs.items():
  record(stage+'_paragraph_character_bound',0,sum(len(r['paragraph'])>2000 for r in rs));record(stage+'_heading_character_bound',0,sum(len(r['heading'])>500 for r in rs))
  record(stage+'_context_payload_hashes',0,sum(r['context_sha256']!=digest(str([r['file_path'],r['heading'],r['paragraph'],r['text']])) for r in rs))
 for stage in ['test','source']:
  input_map={r['statement_id']:r for r in inputs[stage]}
  for model in ['qwen','glm','adjudicated']:
   path=OUT/(f'source-{model}.csv' if stage=='source' else f'test-{rev}-{model}.csv')
   rows=read_csv(path);record(stage+'_'+model+'_unique_ids',len(rows),len({r['statement_id'] for r in rows}));record(stage+'_'+model+'_complete_ids',set(input_map),{r['statement_id'] for r in rows});record(stage+'_'+model+'_successful',len(input_map),sum(r['status']=='ok' for r in rows))
   expected_model='zai/glm-5.3' if model=='glm' else 'qwen3.8-27b-nvfp4'
   record(stage+'_'+model+'_named_model_identity',0,sum(r['returned_model']!=expected_model for r in rows if r['status']=='ok'))
   record(stage+'_'+model+'_context_hash_identity',0,sum(r['context_sha256']!=input_map[r['statement_id']]['context_sha256'] for r in rows))
   record(stage+'_'+model+'_applicability',0,sum(bool(r['context_required'])!=(r['enforceability']!='semantic_only') for r in rows if r['status']=='ok'))
 audit=read_csv(OUT/'context_audit.csv');cache={};bad=0
 for r in audit:
  path=DEFAULT_RAW/r['source_relpath']
  if path not in cache:cache[path]=digest(path.read_bytes())
  bad+=cache[path]!=r['source_sha256']
 record('all_context_source_hashes',0,bad)
 if (OUT/'deployment_gates.csv').exists():
  test_gates={r['dimension']:r for r in read_csv(OUT/'test_gates.csv')}
  for r in read_csv(OUT/'deployment_gates.csv'):
   if r['passed']=='True':record('deployed_'+r['dimension']+'_test_gate',True,test_gates[r['dimension']]['passed']=='True')
 # Serialize sets as counts after checking actual identity, keeping the CSV small.
 for r in checks:
  if isinstance(r['expected'],set):
   r['passed']=r['expected']==r['actual'];r['expected']=len(r['expected']);r['actual']=len(r['actual'])
 write_csv(OUT/'validation.csv',checks)
 failed=[r for r in checks if not r['passed']]
 print('Rescue validation:',len(checks)-len(failed),'/',len(checks),'passed')
 if failed:raise SystemExit(str(failed))
if __name__=='__main__':
 p=argparse.ArgumentParser();a=p.parse_args();main(a)
