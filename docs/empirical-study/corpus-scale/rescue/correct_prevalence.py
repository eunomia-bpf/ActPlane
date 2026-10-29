#!/usr/bin/env python3
"""Test-confusion calibration with repository-bootstrap uncertainty and audit flags."""
import argparse,sys
from collections import defaultdict
from pathlib import Path
import numpy as np
from scipy.optimize import minimize
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,read_csv,write_csv
OUT=HERE/'rescue'
ENF=['semantic_only','content','per_event','cross_event']
CTX=['not_system','none','project','task']

def matrix(counts):
 totals=counts.sum(axis=0)
 if np.any(totals==0):return None,'missing_reference_class'
 a=counts/totals
 if np.linalg.matrix_rank(a)<a.shape[1]:return None,'rank_deficient_confusion'
 return a,''

def fit(a,observed):
 observed=np.asarray(observed,dtype=float)
 if observed.sum()==0:return None,'empty_target_group'
 q=observed/observed.sum()
 direct=np.linalg.solve(a,q)
 if np.min(direct)>=-1e-9 and np.max(direct)<=1+1e-9:
  p=np.maximum(direct,0);return p/p.sum(),''
 def fun(p):return -np.sum(q*np.log(np.maximum(a@p,1e-12)))
 def jac(p):return -(a.T@(q/np.maximum(a@p,1e-12)))
 result=minimize(fun,np.full(len(q),1/len(q)),jac=jac,bounds=[(0,1)]*len(q),constraints={'type':'eq','fun':lambda p:p.sum()-1,'jac':lambda p:np.ones_like(p)},method='SLSQP',options={'ftol':1e-10,'maxiter':200})
 if not result.success:return None,'optimizer_failure'
 p=np.maximum(result.x,0);return p/p.sum(),'simplex_boundary' if np.min(p)<1e-6 else ''

def context_class(r):return 'not_system' if r['enforceability']=='semantic_only' else r['context_required']

def correction_arrays(test_gold,test_pred,test_repos,new_rows,new_pred,new_repos,classes,axis):
 tc=np.zeros((len(test_repos),len(classes),len(classes)))
 nc=np.zeros((len(new_repos),len(classes)))
 ti={r:i for i,r in enumerate(test_repos)};ni={r:i for i,r in enumerate(new_repos)};ci={c:i for i,c in enumerate(classes)}
 label=(lambda r:r['enforceability']) if axis=='enforcement' else context_class
 for r in test_gold:
  p=test_pred.get(r['statement_id'],{})
  if p.get('status')!='ok':raise RuntimeError('Missing test prediction: cannot silently correct')
  tc[ti[r['repo']],ci[label(p)],ci[label(r)]]+=1
 for r in new_rows:
  p=new_pred.get(r['statement_id'],{})
  if p.get('status')!='ok':raise RuntimeError('Missing source prediction: cannot silently correct')
  nc[ni[r['repo']],ci[label(p)]]+=1
 return tc,nc

def main(a):
 selected=read_csv(OUT/'selection.csv')[0]['revision']
 test_pred={r['statement_id']:r for r in read_csv(OUT/f'test-{selected}-adjudicated.csv')}
 new_pred={r['statement_id']:r for r in read_csv(OUT/'source-adjudicated.csv')}
 split={r['repo']:r['split'] for r in read_csv(OUT/'repository_split.csv')}
 test_repos=sorted(r for r,s in split.items() if s=='test')
 gold=[r for r in read_csv(HERE/'paper_labels.csv') if split[r['repo']]=='test' and r['type']=='directive']
 inputs=read_csv(OUT/'paper_inputs.csv')
 assert all(r['statement_id'] in test_pred for r in gold)
 statements={r['statement_id']:r for r in read_csv(HERE/'statements.csv')}
 fixed={r['statement_id']:r for r in read_csv(HERE/'labels.csv')}
 new_rows=[dict(statements[s],type='directive') for s,p in fixed.items() if p['type']=='directive']
 repos={r['repo']:r for r in read_csv(HERE/'repositories.csv')};names=sorted(repos)
 categories={r['repo']:r['category'] for r in read_csv(HERE/'repository_categories.csv')}
 families=defaultdict(set)
 for r in read_csv(HERE/'corpus_manifest.csv'):
  if r['status']=='included':families[r['family']].add((r['repo'],r['content_sha256']))
 scopes={(r['repo'],r['content_sha256']):r['scope'] for r in read_csv(HERE/'file_scopes.csv') if r['status']=='ok'}
 groups=[('overall','all',new_rows,names)]
 for cat in sorted(set(categories.values())):
  rs=[r for r in new_rows if categories[r['repo']]==cat];ns=sorted(r for r in names if categories[r]==cat);groups.append(('category',cat,rs,ns))
 for fam,keys in sorted(families.items()):
  # Include description-only repositories too for a project-level correction denominator.
  rs=[r for r in new_rows if (r['repo'],r['content_sha256']) in keys];ns=sorted({r for r,h in keys});groups.append(('family',fam,rs,ns))
 for scope in sorted(set(scopes.values())):
  keys={k for k,v in scopes.items() if v==scope};rs=[r for r in new_rows if (r['repo'],r['content_sha256']) in keys];ns=sorted({r for r,h in keys});groups.append(('file_scope',scope,rs,ns))
 gates={r['dimension']:r['passed']=='True' for r in read_csv(OUT/'test_gates.csv')}
 results=[];diagnostics=[];draw_audit=[];confusion=[]
 for group_type,group,source,source_names in groups:
  for axis,classes in [('enforcement',ENF),('context',CTX)]:
   tc,nc=correction_arrays(gold,test_pred,test_repos,source,new_pred,source_names,classes,axis)
   counts=tc.sum(axis=0);mat,error=matrix(counts)
   for i,p in enumerate(classes):
    for j,g in enumerate(classes):confusion.append(dict(group_type=group_type,group=group,axis=axis,gold=g,prediction=p,count=int(counts[i,j])))
   condition=float(np.linalg.cond(mat)) if mat is not None else ''
   point,flag=fit(mat,nc.sum(axis=0)) if mat is not None else (None,error)
   if condition!='' and condition>100:flag='ill_conditioned_confusion;'+flag
   rng=np.random.default_rng(20261030)
   test_draws=rng.integers(0,len(test_repos),size=(a.bootstraps,len(test_repos)))
   strata=defaultdict(list)
   for i,name in enumerate(source_names):strata[repos[name]['stratum']].append(i)
   new_draws=np.zeros((a.bootstraps,len(classes)))
   for members in strata.values():new_draws+=nc[rng.choice(members,size=(a.bootstraps,len(members)),replace=True)].sum(axis=1)
   draws=[];failures=defaultdict(int);boundary=0
   for b,ids in enumerate(test_draws):
    bm,err=matrix(tc[ids].sum(axis=0))
    bp,bflag=fit(bm,new_draws[b]) if bm is not None else (None,err)
    draw_audit.append(dict(group_type=group_type,group=group,axis=axis,replicate=b,status='ok' if bp is not None else 'failed',reason=bflag,observed_directives=int(new_draws[b].sum())))
    if bp is None:failures[bflag]+=1;draws.append(np.full(len(classes),np.nan))
    else:draws.append(bp);boundary+=bool(bflag)
   draws=np.asarray(draws);valid=np.isfinite(draws).all(axis=1);valid_count=int(valid.sum())
   diagnostics.append(dict(group_type=group_type,group=group,axis=axis,test_repositories=len(test_repos),target_repositories=len(source_names),target_directives=int(nc.sum()),matrix_rank=np.linalg.matrix_rank(mat) if mat is not None else '',condition_number=condition,point_status=flag or 'ok',successful_bootstraps=valid_count,total_bootstraps=a.bootstraps,boundary_bootstraps=boundary,failures=str(dict(failures))))
   def add(metric,value,ds,gate):
    enough=np.isfinite(ds).sum()>=.8*a.bootstraps
    low,high=np.nanquantile(ds,[.025,.975]) if enough else ('','')
    results.append(dict(group_type=group_type,group=group,metric=metric,value=value if value is not None else '',ci_low=low,ci_high=high,method='test_confusion_constrained_multinomial_mixture',status=('corrected_estimate' if gate else 'exploratory_corrected_estimate') if value is not None else 'not_identifiable',point_flag=flag,successful_bootstraps=int(np.isfinite(ds).sum()),bootstrap_replicates=a.bootstraps,interval_status='ok' if enough else 'insufficient_identifiable_bootstrap_draws',test_repositories=len(test_repos),repositories=len(source_names),directives=len(source),revision=selected))
   if axis=='enforcement':
    for i,c in enumerate(classes):add('enforcement_'+c,None if point is None else point[i],draws[:,i],gates['enforceability'])
    add('system_state_fraction',None if point is None else 1-point[0],1-draws[:,0],gates['enforceability'])
    add('os_enforceable_fraction',None if point is None else point[2:].sum(),draws[:,2:].sum(axis=1),gates['enforceability'])
    add('os_enforceable_count',None if point is None else point[2:].sum()*nc.sum(),draws[:,2:].sum(axis=1)*new_draws.sum(axis=1),gates['enforceability'])
   else:
    for i,c in enumerate(classes):add('context_joint_'+c,None if point is None else point[i],draws[:,i],gates['context_required'] and gates['enforceability'])
    denom=1-draws[:,0];ds=np.divide(draws[:,2:].sum(axis=1),denom,out=np.full(len(draws),np.nan),where=denom>1e-9)
    add('context_required_fraction',None if point is None or point[0]>=1-1e-9 else point[2:].sum()/(1-point[0]),ds,gates['context_required'] and gates['enforceability'])
  # Project-level binary transport is only comparable for the whole-project groups.
  if group_type not in ['overall','category']:continue
  gt={name:False for name in test_repos};pr=gt.copy();nr={name:False for name in source_names}
  for r in gold:
   gt[r['repo']]|=r['enforceability']=='cross_event';pr[r['repo']]|=test_pred[r['statement_id']]['enforceability']=='cross_event'
  for r in source:nr[r['repo']]|=new_pred[r['statement_id']]['enforceability']=='cross_event'
  tc=np.zeros((len(test_repos),2,2));nc=np.zeros((len(source_names),2))
  for i,name in enumerate(test_repos):tc[i,int(pr[name]),int(gt[name])]=1
  for i,name in enumerate(source_names):nc[i,int(nr[name])]=1
  mat,error=matrix(tc.sum(axis=0));point,flag=fit(mat,nc.sum(axis=0)) if mat is not None else (None,error)
  rng=np.random.default_rng(20261030);draws=[];fails=defaultdict(int)
  strata=defaultdict(list)
  for i,name in enumerate(source_names):strata[repos[name]['stratum']].append(i)
  nd=np.zeros((a.bootstraps,2))
  for ids in strata.values():nd+=nc[rng.choice(ids,size=(a.bootstraps,len(ids)),replace=True)].sum(axis=1)
  for b in range(a.bootstraps):
   ids=rng.integers(0,len(test_repos),len(test_repos));bm,err=matrix(tc[ids].sum(axis=0));bp,bflag=fit(bm,nd[b]) if bm is not None else (None,err)
   draws.append(bp[1] if bp is not None else np.nan)
   if bp is None:fails[bflag]+=1
   draw_audit.append(dict(group_type=group_type,group=group,axis='project_cross_event',replicate=b,status='ok' if bp is not None else 'failed',reason=bflag,observed_directives=''))
  arr=np.asarray(draws);enough=np.isfinite(arr).sum()>=.8*a.bootstraps
  lo,hi=np.nanquantile(arr,[.025,.975]) if enough else ('','')
  results.append(dict(group_type=group_type,group=group,metric='cross_event_project_share',value=point[1] if point is not None else '',ci_low=lo,ci_high=hi,method='test_repository_binary_confusion_mixture',status=('corrected_estimate' if gates['enforceability'] else 'exploratory_corrected_estimate') if point is not None else 'not_identifiable',point_flag=flag or 'project_size_transport_unverified',successful_bootstraps=int(np.isfinite(arr).sum()),bootstrap_replicates=a.bootstraps,interval_status='ok' if enough else 'insufficient_identifiable_bootstrap_draws',test_repositories=len(test_repos),repositories=len(source_names),directives=len(source),revision=selected))
  for i,p in enumerate(['no_cross_event','has_cross_event']):
   for j,g in enumerate(['no_cross_event','has_cross_event']):confusion.append(dict(group_type=group_type,group=group,axis='project_cross_event',gold=g,prediction=p,count=int(tc.sum(axis=0)[i,j])))
 write_csv(OUT/'corrected_summary.csv',results);write_csv(OUT/'correction_diagnostics.csv',diagnostics);write_csv(OUT/'correction_confusion.csv',confusion);write_csv(OUT/'correction_bootstrap_audit.csv',draw_audit)
 print('Correction rows',len(results),'bootstrap audit rows',len(draw_audit))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--bootstraps',type=int,default=2000);a=p.parse_args();main(a)
