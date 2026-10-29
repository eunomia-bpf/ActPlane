#!/usr/bin/env python3
"""Freeze a repository-disjoint rescue split before codebook development."""
import csv,hashlib,json,random,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,write_csv,read_csv
OUT=HERE/'rescue'
SEED=20261029
rows=read_csv(HERE/'paper_labels.csv')
repos=sorted({r['repo'] for r in rows})
random.Random(SEED).shuffle(repos)
dev=set(repos[:len(repos)//3])
assignments=[dict(repo=r,split='dev' if r in dev else 'test',seed=SEED) for r in sorted(repos)]
if (OUT/'repository_split.csv').exists():
 assert read_csv(OUT/'repository_split.csv')==[{k:str(v) for k,v in r.items()} for r in assignments], 'Frozen split cannot change'
else:write_csv(OUT/'repository_split.csv',assignments)
write_csv(OUT/'statement_split.csv',[dict(statement_id=r['statement_id'],repo=r['repo'],split='dev' if r['repo'] in dev else 'test') for r in rows])
write_csv(OUT/'split_overview.csv',[dict(split=s,repositories=sum(r['split']==s for r in assignments),statements=sum((r['repo'] in dev)==(s=='dev') for r in rows)) for s in ['dev','test']])
write_csv(OUT/'protocol.csv',[dict(parameter=k,value=v) for k,v in [('seed',SEED),('dev_repositories',len(dev)),('test_repositories',len(repos)-len(dev)),('maximum_codebook_revisions',3),('test_kappa_gate',.6),('minimum_test_coverage',.98),('dev_early_stop_kappa',.65),('bootstrap_replicates',2000),('bootstrap_seed',20261030),('prior_test_exposure','all_original_rows_previously_evaluated; aggregate_diagnostics_previously_inspected; prospective_holdout_only')]])
