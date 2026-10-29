#!/usr/bin/env python3
"""Contextual two-axis inference. Gold is never read by this executable."""
import argparse,json,sys
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,DEFAULT_RAW,read_csv,write_csv,digest,log,now
from label import complete,parse_json
DIMS=['enforceability','context_required']
FIELDS=['statement_id',*DIMS,'model','returned_model','status','adjudicated','error','guide_sha256','context_sha256','revision','completion_token_ceiling']

def valid(p):
 return p.get('enforceability') in ['semantic_only','content','per_event','cross_event'] and (p.get('context_required')=='' if p.get('enforceability')=='semantic_only' else p.get('context_required') in ['none','project','task'])

def classify(a,batch,guide,other,repair=0):
 entries=[]
 for i,r in enumerate(batch):
  e={k:r[k] for k in ['text','file_path','heading','paragraph']};e['id']=i
  if other is not None:
   choices=[{d:r[d] for d in DIMS},{d:other[r['statement_id']][d] for d in DIMS}]
   if int(digest(r['statement_id'])[:2],16)&1:choices.reverse()
   e['annotations']=choices
  entries.append(e)
 system=guide+'\n'+('Adjudicate the anonymized candidate labels by rereading the target. Neither model has priority.' if other is not None else 'Independently label each TARGET directive.')
 system+='\nReturn JSON only: {"labels": [[id, enforceability, context_required], ...]}. Return every id once. No explanations. Use the empty context string only for semantic_only. Keep reasoning brief.'
 if repair:system+='\nSchema repair: use only semantic_only/content/per_event/cross_event, and none/project/task (or empty only for semantic_only). Reapply unchanged definitions.'
 try:
  response=complete(a,system,dict(statements=entries),budget=max(2048,len(batch)*80) if a.model=='qwen3.8-27b-nvfp4' else a.remote_tokens)
  assert response.get('model')==a.model,'unexpected_returned_model'
  obj=parse_json(response['choices'][0]['message']['content'])
  parsed=obj['labels'] if isinstance(obj,dict) else obj
  result={};seen=set()
  for row in parsed:
   if isinstance(row,dict):row=[row['id'],row['enforceability'],row['context_required']]
   if len(row)!=3:raise ValueError('bad_row_length')
   i,enf,ctx=row
   if isinstance(i,str) and i.isdigit():i=int(i)
   if not isinstance(i,int) or i not in range(len(batch)) or i in seen:raise ValueError('ambiguous_id')
   seen.add(i);p=dict(enforceability=enf,context_required=ctx)
   if valid(p):result[i]=dict(statement_id=batch[i]['statement_id'],**p,model=a.model,returned_model=response['model'],status='ok',adjudicated=other is not None,error='',guide_sha256=a.guide_hash,context_sha256=batch[i]['context_sha256'],revision=a.revision,completion_token_ceiling=max(2048,len(batch)*80) if a.model=='qwen3.8-27b-nvfp4' else a.remote_tokens)
  missing=[i for i in range(len(batch)) if i not in result]
  if not missing:return [result[i] for i in range(len(batch))]
  log(a.raw/'rescue-label-events.jsonl',dict(at=now(),stage=a.stage,revision=a.revision,model=a.model,event='invalid_or_missing_ids',ids=[batch[i]['statement_id'] for i in missing],repair=repair))
  if result:
   fixed=classify(a,[batch[i] for i in missing],guide,other)
   result.update(zip(missing,fixed));return [result[i] for i in range(len(batch))]
  raise ValueError('no_valid_rows')
 except Exception as error:
  log(a.raw/'rescue-label-events.jsonl',dict(at=now(),stage=a.stage,revision=a.revision,model=a.model,event='request_or_schema_failure',error=type(error).__name__+':'+str(error)[:100],ids=[r['statement_id'] for r in batch],repair=repair))
  if str(error)!='model_request_failed' and repair<2:return classify(a,batch,guide,other,repair+1)
  if len(batch)>1 and str(error)!='model_request_failed':
   mid=len(batch)//2;return classify(a,batch[:mid],guide,other)+classify(a,batch[mid:],guide,other)
  return [dict(statement_id=r['statement_id'],model=a.model,status='failed',error=type(error).__name__+':'+str(error)[:100],guide_sha256=a.guide_hash,context_sha256=r['context_sha256'],revision=a.revision) for r in batch]

def main(a):
 guide=a.guide.read_text();examples=read_csv(a.examples)
 dev={r['statement_id'] for r in read_csv(HERE/'rescue/dev_inputs.csv')}
 assert all(r['statement_id'] in dev for r in examples),'Few-shot leakage'
 guide+='\nDEVELOPMENT EXAMPLES (target text -> enforcement, context):\n'
 for r in examples:guide+=json.dumps({k:r[k] for k in ['text',*DIMS]},ensure_ascii=False)+'\n'
 a.guide_hash=digest(guide)
 inputs=read_csv(a.input);other=None;retained=[]
 if a.other:
  primary={r['statement_id']:r for r in read_csv(a.primary)};other={r['statement_id']:r for r in read_csv(a.other)}
  todo=[]
  for r in inputs:
   l,t=primary.get(r['statement_id'],{}),other.get(r['statement_id'],{})
   if l.get('status')==t.get('status')=='ok':
    assert l['guide_sha256']==t['guide_sha256']==a.guide_hash
    if all(l[d]==t[d] for d in DIMS):retained.append(dict(l,model='agreement',adjudicated=False))
    else:todo.append(dict(r,**{d:l[d] for d in DIMS}))
   else:retained.append(dict(statement_id=r['statement_id'],status='failed',error='incomplete_pair',guide_sha256=a.guide_hash,context_sha256=r['context_sha256'],revision=a.revision))
  inputs=todo
 done={r['statement_id']:r for r in read_csv(a.output)} if a.output.exists() else {}
 assert all(r.get('guide_sha256')==a.guide_hash for r in done.values()),'Guide changed within output file'
 todo=[r for r in inputs if done.get(r['statement_id'],{}).get('status')!='ok'];done.update({r['statement_id']:r for r in retained})
 batches=[];batch=[];chars=0
 for r in todo:
  size=sum(len(r[k]) for k in ['text','heading','paragraph','file_path'])
  if batch and (len(batch)>=a.batch_size or chars+size>a.max_chars):batches.append(batch);batch=[];chars=0
  batch.append(r);chars+=size
 if batch:batches.append(batch)
 write_csv(a.output,sorted(done.values(),key=lambda r:r['statement_id']),FIELDS)
 print(a.stage,a.model,'pending',len(todo),'batches',len(batches),flush=True)
 with ThreadPoolExecutor(a.workers) as pool:
  futures=[pool.submit(classify,a,b,guide,other) for b in batches]
  for i,f in enumerate(as_completed(futures),1):
   done.update({r['statement_id']:r for r in f.result()});write_csv(a.output,sorted(done.values(),key=lambda r:r['statement_id']),FIELDS)
   print('completed',i,'/',len(batches),'ok',sum(r['status']=='ok' for r in done.values()),flush=True)
 if not batches:write_csv(a.output,sorted(done.values(),key=lambda r:r['statement_id']),FIELDS)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--guide',type=Path,required=True);p.add_argument('--examples',type=Path,required=True)
 p.add_argument('--revision',required=True);p.add_argument('--stage',required=True)
 p.add_argument('--model',required=True);p.add_argument('--workers',type=int,default=4);p.add_argument('--batch-size',type=int,default=32)
 p.add_argument('--remote-tokens',type=int,default=10000);p.add_argument('--remote-timeout',type=int,default=600);p.add_argument('--max-chars',type=int,default=30000);p.add_argument('--raw',type=Path,default=DEFAULT_RAW);p.add_argument('--retries',type=int,default=3);p.add_argument('--thinking',action='store_true')
 p.add_argument('--primary',type=Path);p.add_argument('--other',type=Path)
 a=p.parse_args();assert 1<=a.workers<=8;main(a)
